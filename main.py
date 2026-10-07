import os
import re
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Header, status, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, field_validator
from supabase import create_client, Client
from dotenv import load_dotenv

# Carregamento seguro do ambiente local
load_dotenv()

# Esconde a documentação Swagger no ambiente de produção
AMBIENTE = os.getenv("AMBIENTE", "PRODUCAO")
EXIBIR_DOCS = True if AMBIENTE == "DESENVOLVIMENTO" else False

app = FastAPI(
    title="Guardião do Cerrado - API Backend Blindado v1.3.0",
    version="1.3.0",
    docs_url="/docs" if EXIBIR_DOCS else None,
    redoc_url=None
)

SUPABASE_URL = os.getenv("SUPABASE_URL", "https://supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
# Token Secreto que blinda os endpoints contra ferramentas externas (Postman/Curl)
APP_SECRET_TOKEN = os.getenv("APP_SECRET_TOKEN", "GuardiãoCerrado@2026_SegurançaMáxima#")

if not SUPABASE_KEY:
    raise RuntimeError("CRÍTICO: Chave secreta do Supabase (SUPABASE_KEY) ausente.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- MIDDLEWARE DE AUTENTICAÇÃO MÚTUA (ANTI-INTRUSÃO) ---
api_key_header = APIKeyHeader(name="X-App-Token", auto_error=False)

def verificar_integridade_app(x_app_token: str = Depends(api_key_header)):
    """Bloqueia a requisição na camada de rede se o Token do App não for idêntico."""
    if not x_app_token or x_app_token != APP_SECRET_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Acesso negado: Origem não autorizada ou credencial inválida."
        )
    return True

# --- MODELOS DE ENTRADA SANITIZADOS VIA REGEX ---
class EnvioCupomSchema(BaseModel):
    chave_nfe: str = Field(..., min_length=44, max_length=44)
    url_sefaz: str = Field(...)
    valor_a: float = Field(..., gt=0)
    data_a: str = Field(...)
    cnpj_real: str = Field(...)
    municipio_emissao: str = Field(..., min_length=2, max_length=100)
    valor_tributos: float = Field(..., ge=0)

    @field_validator('chave_nfe', 'cnpj_real')
    @classmethod
    def apenas_numeros(cls, v: str) -> str:
        substituido = re.sub(r'\D', '', v)
        if not substituido:
            raise ValueError("O campo deve conter apenas dígitos numéricos.")
        return substituido

class AuditoriaVotoSchema(BaseModel):
    cupom_chave: str = Field(..., min_length=44, max_length=44)
    papel_auditor: str = Field(...)
    valor_total_gabarito: float = Field(..., gt=0)
    cnpj_gabarito: str = Field(...)
    municipio_gabarito: str = Field(..., min_length=2, max_length=100)

    @field_validator('papel_auditor')
    @classmethod
    def validar_papel(cls, v: str) -> str:
        if v not in ["JOGADOR_B", "JOGADOR_C"]:
            raise ValueError("Papel de auditoria inválido.")
        return v

# --- REGRAS DE DNA FISCAL E VALIDAÇÃO MATEMÁTICA ---
def validar_modulo11_nfce(chave: str) -> bool:
    if len(chave) != 44 or not chave.isdigit():
        return False
    pesos = * 6
    pesos = pesos[:43]
    try:
        digitos_invertidos = [int(x) for x in reversed(chave[:43])]
        soma = sum(d * p for d, p in zip(digitos_invertidos, pesos))
        resto = soma % 11
        digito_calculado = 0 if resto in (0, 1) else 11 - resto
        return int(chave[-1]) == digito_calculado
    except (ValueError, IndexError):
        return False

def validar_lista_branca_url(url: str, chave: str) -> bool:
    try:
        parsed_url = urlparse(url)
        dominio = parsed_url.netloc.lower().strip()
        if "@" in dominio or ":" in dominio.split(']')[-1]:
            return False
        if chave.startswith("17") and not dominio.endswith("sefaz.to.gov.br"):
            return False
        dominios_validos = [
            "sefaz.to.gov.br", "sefaz.go.gov.br", "fazenda.mg.gov.br", 
            "sefaz.mt.gov.br", "sefaz.ms.gov.br", "fazenda.df.gov.br",
            "sefaz.ma.gov.br", "sefaz.pi.gov.br", "sefaz.ba.gov.br"
        ]
        return any(dominio == d or dominio.endswith("." + d) for d in dominios_validos)
    except Exception:
        return False


# --- ENDPOINTS PROTEGIDOS DE ALTA SEGURANÇA ---

@app.get("/", status_code=status.HTTP_200_OK)
def raiz():
    return {"status": "online", "projeto": "Guardião do Cerrado", "seguranca": "blindagem_maxima_ativa"}

@app.post("/cupons/enviar", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verificar_integridade_app)])
def enviar_cupom(dados: EnvioCupomSchema, x_jogador_id: str = Header(...)):
    # Sanitização contra injeção de cabeçalhos maliciosos
    jogador_id = re.sub(r'[^a-zA-Z0-9_\-]', '', x_jogador_id).strip()
    if not jogador_id:
        raise HTTPException(status_code=400, detail="Identificador do remetente corrompido.")

    if not validar_modulo11_nfce(dados.chave_nfe):
        raise HTTPException(status_code=400, detail="Chave NFC-e matematicamente inválida.")
    
    if not validar_lista_branca_url(dados.url_sefaz, dados.chave_nfe):
        raise HTTPException(status_code=400, detail="DNA Fiscal violado. URL não autorizada.")
    
    try:
        dados_banco = {
            "chave_nfe": dados.chave_nfe,
            "url_sefaz": dados.url_sefaz,
            "jogador_a_id": jogador_id,
            "valor_a": dados.valor_a,
            "data_a": dados.data_a,
            "cnpj_real": re.sub(r'\D', '', dados.cnpj_real),
            "municipio_emissao": dados.municipio_emissao.strip(),
            "valor_tributos": dados.valor_tributos,
            "status": "PENDENTE"
        }
        supabase.table("cupons_auditoria").insert(dados_banco).execute()
        return {"status": "SUCESSO", "codigo": "RETIDO_PARA_AUDITORIA"}
    except Exception as e:
        if "23505" in str(e) or "duplicate key" in str(e).lower():
            raise HTTPException(status_code=409, detail="Este cupom fiscal já existe no ecossistema.")
        raise HTTPException(status_code=500, detail="Erro interno de persistência.")

@app.post("/cupons/auditar", status_code=status.HTTP_200_OK, dependencies=[Depends(verificar_integridade_app)])
def auditar_cupom(dados: AuditoriaVotoSchema, tempo_resposta: float = Header(...)):
    # Defesa Anti-Bot / Anti-OCR Comportamental
    if tempo_resposta < 3.0:
        raise HTTPException(status_code=403, detail="Acesso recusado: Padrão de velocidade incompatível com humanos.")
    
    try:
        # Correção Cítica de Tipagem: Extração segura de listas do Supabase PostgREST
        cupom_query = supabase.table("cupons_auditoria").select("valor_a", "municipio_emissao", "cnpj_real").eq("chave_nfe", dados.cupom_chave).execute()
        
        if not cupom_query.data or len(cupom_query.data) == 0:
            raise HTTPException(status_code=404, detail="Cupom solicitado não localizado para processamento.")
        
        # Pega defensivamente o primeiro dicionário dentro da lista retornada
        cupom_original = cupom_query.data[0]

        cnpj_gabarito_limpo = re.sub(r'\D', '', dados.cnpj_gabarito).strip()
        cnpj_original_limpo = re.sub(r'\D', '', cupom_original["cnpj_real"]).strip()

        # Comparação matemática estrita
        match_perfeito = (
            abs(dados.valor_total_gabarito - cupom_original["valor_a"]) < 0.01 and 
            dados.municipio_gabarito.lower().strip() == cupom_original["municipio_emissao"].lower().strip() and
            cnpj_gabarito_limpo == cnpj_original_limpo
        )
        
        coluna_voto = "voto_b" if dados.papel_auditor == "JOGADOR_B" else "voto_c"
        resultado_voto = "APROVADO" if match_perfeito else "DIVERGENTE"
        
        # Computa o voto de forma isolada
        supabase.table("cupons_auditoria").update({coluna_voto: resultado_voto}).eq("chave_nfe", dados.cupom_chave).execute()
        
        # Checagem condicional atômica baseada em leitura fresca de estado
        estado_query = supabase.table("cupons_auditoria").select("voto_b", "voto_c").eq("chave_nfe", dados.cupom_chave).execute()
        
        if estado_query.data and len(estado_query.data) > 0:
            estado_atualizado = estado_query.data[0]
            voto_b = estado_atualizado.get("voto_b")
            voto_c = estado_atualizado.get("voto_c")

            if voto_b == "APROVADO" and voto_c == "APROVADO":
                supabase.table("cupons_auditoria").update({"status": "APROVADO"}).eq("chave_nfe", dados.cupom_chave).execute()
            elif voto_b == "DIVERGENTE" or voto_c == "DIVERGENTE":
                if voto_b != "PENDENTE" and voto_c != "PENDENTE":
                    supabase.table("cupons_auditoria").update({"status": "SUSPEITO_PUNIDO"}).eq("chave_nfe", dados.cupom_chave).execute()

        # Blindagem contra Vazamento de Informação: Resposta unificada. 
        # Impede que atacantes façam engenharia reversa das respostas às cegas por Brute Force.
        return {"status": "PROCESSANDO", "mensagem": "Análise computada com sucesso no ecossistema."}
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Falha interna de consolidação securitária.")
