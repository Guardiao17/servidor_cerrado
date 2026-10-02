# Guardião do Cerrado - Backend API

Servidor focado no processamento, validação e auditoria gamificada (Crowdsourcing) de cupons fiscais eletrônicos (NFC-e) do bioma Cerrado.

## 🚀 Tecnologias e Configurações Local
* Python 3.14 (Interpretador Homologado)
* FastAPI 
* Supabase (PostgreSQL Integrado)
* Uvicorn (Ambiente de Rede Local)

## 🛡️ Mecânicas Antifraude Ativas
* Validação matemática de dígito verificador via Módulo 11 da SEFAZ.
* Lista Branca por DNA Fiscal (Mitigação de Open Redirect).
* Isolamento de Auditoria às Cegas por dupla etapa (Jogadores B e C).
