import os
import re
import math
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Header, status, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, field_validator
from supabase import create_client, Client
from dotenv import load_dotenv

# Carregamento seguro do ambiente local e variáveis de escopo
load_dotenv()

# Esconde a documentação Swagger no ambiente de produção para mitigar engenharia reversa
AMBIENTE = os.getenv("AMBIENTE", "PRODUCAO")
EXIBIR_DOCS = True if AMBIENTE == "DESENVOLVIMENTO" else False

app = FastAPI(
    title="Guardião do Cerrado - API Backend Blindado Completo",
    version="1.6.1",
    docs_url="/docs" if EXIBIR_DOCS else None,
    redoc_url=None
)

SUPABASE_URL = os.getenv("SUPABASE_URL", "https://supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

# SEGURANÇA MÁXIMA: O Token DEVE vir do ambiente criptografado da nuvem.
APP_SECRET_TOKEN = os.getenv("APP_SECRET_TOKEN")

if not SUPABASE_KEY:
    raise RuntimeError("ERRO CRÍTICO DE INFRAESTRUTURA: Chave secreta do Supabase (SUPABASE_KEY) ausente.")

if not APP_SECRET_TOKEN:
    raise RuntimeError("ERRO CRÍTICO DE SEGURANÇA: Chave de integridade do ecossistema (APP_SECRET_TOKEN) ausente.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- MIDDLEWARE DE AUTENTICAÇÃO MÚTUA DE INFRAESTRUTURA ---
api_key_header = APIKeyHeader(name="X-App-Token", auto_error=False)

def verificar_integridade_app(x_app_token: str = Depends(api_key_header)):
    """Derruba a conexão na camada de rede se o Token do aplicativo C# for inválido ou ausente."""
    if not x_app_token or x_app_token != APP_SECRET_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Acesso negado: Origem não homologada ou credencial inválida."
        )
    return True

# --- FUNÇÃO MATEMÁTICA: FÓRMULA DE HAVERSINE ---
def calcular_distancia_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calcula a distância real em quilômetros entre duas coordenadas de GPS."""
    R = 6371.0  # Raio da Terra em km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

# --- MODELOS DE ENTRADA SANITIZADOS COM TRATAMENTO DE INJEÇÃO ---

class CadastroJogadorSchema(BaseModel):
    id: str = Field(..., min_length=3, max_length=50)
    uf_atual: str = Field(..., min_length=2, max_length=2)
    device_hash: str = Field(..., min_length=32, max_length=64)
    latitude_atual: float = Field(..., ge=-90, le=90)
    longitude_atual: float = Field(..., ge=-180, le=180)

    @field_validator('id')
    @classmethod
    def sanitizar_username(cls, v: str) -> str:
        substituido = re.sub(r'[^a-zA-Z0-9_\-]', '', v).strip()
        if not substituido:
            raise ValueError("O ID de usuário fornecido possui caracteres inválidos.")
        return substituido

    @field_validator('uf_atual')
    @classmethod
    def validar_uf(cls, v: str) -> str:
        uf_maiuscula = v.upper().strip()
        ufs_validas = ["AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"]
        if uf_maiuscula not in ufs_validas:
            raise ValueError("Unidade Federativa inválida.")
        return uf_maiuscula

class EnvioCupomSchema(BaseModel):
    chave_nfe: str = Field(..., min_length=44, max_length=44)
    url_sefaz: str = Field(...)
    valor_a: float = Field(..., gt=0)
    data_a: str = Field(...)
    cnpj_real: str = Field(...)
    municipio_emissao: str = Field(..., min_length=2, max_length=100)
    valor_tributos: float = Field(..., ge=0)
    latitude_a: float = Field(..., ge=-90, le=90)
    longitude_a: float = Field(..., ge=-180, le=180)

    @field_validator('chave_nfe', 'cnpj_real')
    @classmethod
    def apenas_numeros(cls, v: str) -> str:
        substituido = re.sub(r'\D', '', v)
        if not substituido:
            raise ValueError("O campo deve conter caracteres estritamente numéricos.")
        return substituido

class AuditoriaVotoSchema(BaseModel):
    cupom_chave: str = Field(..., min_length=44, max_length=44)
    papel_auditor: str = Field(...)
    valor_total_gabarito: float = Field(..., gt=0)
    cnpj_gabarito: str = Field(...)
    municipio_gabarito: str = Field(..., min_length=2, max_length=100)
    latitude_auditor: float = Field(..., ge=-90, le=90)
    longitude_auditor: float = Field(..., ge=-180, le=180)

    @field_validator('papel_auditor')
    @classmethod
    def validar_papel(cls, v: str) -> str:
        if v not in ["JOGADOR_B", "JOGADOR_C"]:
            raise ValueError("Papel de auditoria inválido.")
        return v


# --- ENDPOINTS PROTEGIDOS DE INFRAESTRUTURA ---

@app.get("/", status_code=status.HTTP_200_OK)
def raiz():
    return {"status": "online", "projeto": "Guardião do Cerrado", "seguranca": "auditado_e_selado"}

@app.post("/jogadores/cadastrar", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verificar_integridade_app)])
def cadastrar_jogador(dados: CadastroJogadorSchema):
    try:
        # Prevenção a Ataques Sybil por Hardware Fingerprinting
        checagem_hardware = supabase.table("jogadores").select("id").eq("device_hash", dados.device_hash).execute()
        if checagem_hardware.data and len(checagem_hardware.data) > 0:
            raise HTTPException(status_code=409, detail="Este dispositivo móvel já possui uma conta ativa associada.")

        novo_jogador = {
            "id": dados.id,
            "uf_atual": dados.uf_atual,
            "device_hash": dados.device_hash,
            "latitude_atual": dados.latitude_atual,
            "longitude_atual": dados.longitude_atual,
            "pontos_confirmados": 0,
            "reputacao": 100,
            "banido": False
        }
        supabase.table("jogadores").insert(novo_jogador).execute()
        return {"status": "SUCESSO", "jogador_id": dados.id}
    except HTTPException:
        raise
    except Exception as e:
        if "duplicate key" in str(e).lower() or "23505" in str(e):
            raise HTTPException(status_code=409, detail="Este apelido/ID de usuário já está em uso.")
        raise HTTPException(status_code=500, detail="Falha interna ao registrar perfil de hardware.")

@app.post("/cupons/enviar", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verificar_integridade_app)])
def enviar_cupom(dados: EnvioCupomSchema, x_jogador_id: str = Header(...)):
    # Sanitização preventiva do cabeçalho
    jogador_id = re.sub(r'[^a-zA-Z0-9_\-]', '', x_jogador_id).strip()
    if not jogador_id:
        raise HTTPException(status_code=400, detail="Identificador do cabeçalho de rede corrompido.")

    # Algoritmo de Validação de Chave Nacional da SEFAZ - CORREÇÃO DE SINTAXE SEM ASTERISCO
    pesos = [4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    try:
        digitos_invertidos = [int(x) for x in reversed(dados.chave_nfe[:43])]
        soma = sum(d * p for d, p in zip(digitos_invertidos, pesos))
        resto = soma % 11
        digito_calculado = 0 if resto in (0, 1) else 11 - resto
        if int(dados.chave_nfe[-1]) != digito_calculado:
            raise HTTPException(status_code=400, detail="Chave NFC-e matematicamente inválida (DV incorreto).")
    except Exception:
        raise HTTPException(status_code=400, detail="Chave NFC-e estruturalmente inválida.")
    
    # Validação Antiautomação por DNA Fiscal (Mitiga Open Redirect)
    parsed_url = urlparse(dados.url_sefaz)
    dominio = parsed_url.netloc.lower().strip()
    if "@" in dominio or ":" in dominio.split(']')[-1]:
        raise HTTPException(status_code=400, detail="Estrutura de URL fiscal corrompida.")
    if dados.chave_nfe.startswith("17") and not dominio.endswith("sefaz.to.gov.br"):
        raise HTTPException(status_code=400, detail="DNA Fiscal violado: Domínio do Tocantins não autorizado.")
    
    dominios_validos = ["sefaz.to.gov.br", "sefaz.go.gov.br", "fazenda.mg.gov.br", "sefaz.mt.gov.br"]
    if not any(dominio == d or dominio.endswith("." + d) for d in dominios_validos):
        raise HTTPException(status_code=400, detail="URL fiscal de origem não cadastrada na lista branca.")
    
    try:
        dados_banco = {
            "chave_nfe": dados.chave_nfe,
            "url_sefaz": dados.url_sefaz,
            "jogador_a_id": jogador_id,
            "valor_a": dados.valor_a,
            "data_a": dados.data_a,
            "cnpj_real": dados.cnpj_real,
            "municipio_emissao": dados.municipio_emissao.strip(),
            "valor_tributos": dados.valor_tributos,
            "latitude_a": dados.latitude_a,
            "longitude_a": dados.longitude_a,
            "status": "PENDENTE"
        }
        supabase.table("cupons_auditoria").insert(dados_banco).execute()
        return {"status": "SUCESSO", "codigo": "RETIDO_PARA_AUDITORIA"}
    except Exception as e:
        if "foreign key" in str(e).lower() or "violates foreign key constraint" in str(e).lower():
            raise HTTPException(status_code=403, detail="Ação negada: O remetente não possui perfil de hardware ativo.")
        if "duplicate key" in str(e).lower() or "23505" in str(e):
            raise HTTPException(status_code=409, detail="Este cupom fiscal já foi enviado e processado pelo sistema.")
        raise HTTPException(status_code=500, detail="Falha de persistência interna de dados.")

@app.post("/cupons/auditar", status_code=status.HTTP_200_OK, dependencies=[Depends(verificar_integridade_app)])
def auditar_cupom(dados: AuditoriaVotoSchema, tempo_resposta: float = Header(...)):
    # Defesa Anti-Bot / Anti-OCR Comportamental
    if tempo_resposta < 3.0:
