import os
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field
from supabase import create_client, Client
from dotenv import load_dotenv

# Força o Python a ler as credenciais de acesso dentro do seu arquivo .env local
load_dotenv()

app = FastAPI(title="Guardião do Cerrado - API Backend")

# Configuração e carregamento seguro das chaves a partir do seu .env atual
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

# Inicialização do cliente Supabase conectado ao seu projeto real
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- MODELOS DE ENTRADA (Mapeado exatamente com as colunas do seu banco real) ---
class EnvioCupomSchema(BaseModel):
    chave_nfe: str = Field(..., min_length=44, max_length=44, description="Chave de 44 dígitos da NFC-e")
    url_sefaz: str = Field(..., description="URL extraída do QR Code")
    valor_a: float
    data_a: str
    cnpj_real: str
    municipio_emissao: str
    valor_tributos: float

class AuditoriaVotoSchema(BaseModel):
    cupom_chave: str = Field(..., min_length=44, max_length=44, description="Chave de 44 dígitos para achar o cupom")
    papel_auditor: str = Field(..., description="Deve ser 'JOGADOR_B' ou 'JOGADOR_C'")
    valor_total_gabarito: float
    cnpj_gabarito: str
    municipio_gabarito: str

# --- VALIDAÇÕES DE SEGURANÇA E MOTOR ANTIFRAUDE ---
def validar_modulo11_nfce(chave: str) -> bool:
    """Valida o dígito verificador da NFC-e usando Módulo 11 padrão SEFAZ."""
    if not chave.isdigit() or len(chave) != 44:
        return False
    
    # Pesos do módulo 11 para chaves fiscais (ciclo de 2 a 9 invertidos)
    pesos = [2, 3, 4, 5, 6, 7, 8, 9] * 6
    pesos = pesos[:43]
    
    digitos_invertidos = [int(x) for x in reversed(chave[:43])]
    soma = sum(d * p for d, p in zip(digitos_invertidos, pesos))
    resto = soma % 11
    
    digito_calculado = 0 if resto in (0, 1) else 11 - resto
    return int(chave[-1]) == digito_calculado

def validar_lista_branca_url(url: str, chave: str) -> bool:
    """Aplica a Lista Branca por DNA Fiscal para mitigar Open Redirect."""
    parsed_url = urlparse(url)
    dominio = parsed_url.netloc.lower()
    
    # Se a chave for do Tocantins ('17'), obriga o domínio a ser do SEFAZ TO
    if chave.startswith("17"):
        if not dominio.endswith("sefaz.to.gov.br"):
            return False
            
    # Domínios fiscais homologados do Cerrado
    dominios_validos = [
        "sefaz.to.gov.br", "sefaz.go.gov.br", "fazenda.mg.gov.br", 
        "sefaz.mt.gov.br", "sefaz.ms.gov.br", "fazenda.df.gov.br",
        "sefaz.ma.gov.br", "sefaz.pi.gov.br", "sefaz.ba.gov.br"
    ]
    return any(dominio.endswith(d) for d in dominios_validos)


# --- ROTAS PRINCIPAIS DO BACKEND ---

@app.get("/")
def raiz():
    return {"status": "online", "projeto": "Guardião do Cerrado"}

@app.post("/cupons/enviar")
def enviar_cupom(dados: EnvioCupomSchema, x_jogador_id: str = Header(...)):
    # 1. Validação Matemática (Módulo 11)
    if not validar_modulo11_nfce(dados.chave_nfe):
        raise HTTPException(status_code=400, detail="Chave NFC-e inválida (Falha no Dígito Verificador).")
    
    # 2. Blindagem de URL (Lista Branca)
    if not validar_lista_branca_url(dados.url_sefaz, dados.chave_nfe):
        raise HTTPException(status_code=400, detail="URL fiscal não autorizada na lista branca de segurança.")
    
    # 3. Persistência no Supabase com proteção de Idempotência nativa (chave_nfe única)
    try:
        dados_banco = {
            "chave_nfe": dados.chave_nfe,
            "url_sefaz": dados.url_sefaz,
            "jogador_a_id": x_jogador_id,
            "valor_a": dados.valor_a,
            "data_a": dados.data_a,
            "cnpj_real": dados.cnpj_real,
            "municipio_emissao": dados.municipio_emissao,
            "valor_tributos": dados.valor_tributos,
            "status": "PENDENTE"
        }
        
        resposta = supabase.table("cupons_auditoria").insert(dados_banco).execute()
        return {"status": "SUCESSO", "mensagem": "Cupom retido para auditoria às cegas.", "dados": resposta.data}
        
    except Exception as e:
        if "23505" in str(e) or "duplicate key" in str(e).lower():
            raise HTTPException(status_code=409, detail="Este cupom fiscal já foi enviado e processado pelo sistema.")
        raise HTTPException(status_code=500, detail=f"Erro interno no banco de dados: {str(e)}")

@app.post("/cupons/auditar")
def auditar_cupom(dados: AuditoriaVotoSchema, tempo_resposta: float = Header(...)):
    # 1. Defesa Comportamental Humana (Anti-OCR / Anti-Bot)
    if tempo_resposta < 3.0:
        raise HTTPException(status_code=403, detail="Atividade suspeita de automação (resposta rápida demais).")
    
    if dados.papel_auditor not in ["JOGADOR_B", "JOGADOR_C"]:
        raise HTTPException(status_code=400, detail="Papel de auditoria inválido.")

    # 2. Busca o cupom original no banco
    cupom_query = supabase.table("cupons_auditoria").select("*").eq("chave_nfe", dados.cupom_chave).execute()
    if not cupom_query.data:
        raise HTTPException(status_code=404, detail="Cupom solicitado para auditoria não foi localizado.")
    
    cupom_original = cupom_query.data[0] if isinstance(cupom_query.data, list) else cupom_query.data

    # 3. Lógica de Comparação às Cegas (Match com o Gabarito do Jogador A)
    cnpj_limpo_gabarito = dados.cnpj_gabarito.replace(".", "").replace("/", "").replace("-", "").strip()
    cnpj_limpo_original = cupom_original["cnpj_real"].replace(".", "").replace("/", "").replace("-", "").strip()

    match_perfeito = (
        abs(dados.valor_total_gabarito - cupom_original["valor_a"]) < 0.01 and 
        dados.municipio_gabarito.lower().strip() == cupom_original["municipio_emissao"].lower().strip() and
        cnpj_limpo_gabarito == cnpj_limpo_original
    )
    
    coluna_voto = "voto_b" if dados.papel_auditor == "JOGADOR_B" else "voto_c"
    resultado_voto = "APROVADO" if match_perfeito else "DIVERGENTE"
    
    # Registra o voto do auditor atual (B ou C)
    supabase.table("cupons_auditoria").update({coluna_voto: resultado_voto}).eq("chave_nfe", dados.cupom_chave).execute()
    
    # Re-seleciona para avaliar a consolidação das duas etapas do Crowdsourcing
    checagem_query = supabase.table("cupons_auditoria").select("voto_b", "voto_c").eq("chave_nfe", dados.cupom_chave).execute()
    checagem = checagem_query.data[0] if isinstance(checagem_query.data, list) else checagem_query.data
    
    # Decide o veredito final com base nas respostas dos dois auditores externos
    if checagem["voto_b"] == "APROVADO" and checagem["voto_c"] == "APROVADO":
        supabase.table("cupons_auditoria").update({"status": "APROVADO"}).eq("chave_nfe", dados.cupom_chave).execute()
        return {"status": "SUCESSO", "mensagem": "Cupom totalmente validado e homologado pelo ecossistema."}
    elif checagem["voto_b"] == "DIVERGENTE" or checagem["voto_c"] == "DIVERGENTE":
        supabase.table("cupons_auditoria").update({"status": "SUSPEITO_PUNIDO"}).eq("chave_nfe", dados.cupom_chave).execute()
        return {"status": "ALERTA", "mensagem": "Divergência detectada. Enviado para auditoria do Gestor Master."}
        
    return {"status": "PROCESSANDO", "mensagem": "Voto registrado. Aguardando a segunda etapa da auditoria às cegas."}
