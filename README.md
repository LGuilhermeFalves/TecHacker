# Ferramenta de Detecção de Phishing

## Relatório do Projeto

### Descrição
Sistema completo para detecção de URLs maliciosas através de análises heurísticas avançadas. A ferramenta combina verificações básicas de padrões com análises profundas de WHOIS, certificados SSL, similaridade com marcas conhecidas e conteúdo de páginas web.

### Objetivo
Identificar tentativas de phishing e URLs maliciosas antes que usuários forneçam informações sensíveis, utilizando múltiplas camadas de análise para maximizar a taxa de detecção.

### Conceito Implementado
**Conceito B** - Análise Heurística Avançada

O sistema implementa dois níveis de análise:

#### Análises Básicas (Conceito C)
- Detecção de endereços IP em URLs
- Verificação de TLDs suspeitos
- Análise de subdomínios excessivos
- Identificação de números em domínios
- Caracteres especiais suspeitos
- Imitação de marcas conhecidas
- Padrões de letras repetidas
- Uso indevido de serviços de hospedagem confiáveis

#### Análises Avançadas (Conceito B)
- **WHOIS**: Idade do domínio, registrador, país
- **Certificado SSL**: Validade, emissor, auto-assinado
- **DNS Dinâmico**: Detecção de serviços suspeitos
- **Redirecionamentos**: Análise de cadeia de redirecionamentos
- **Similaridade**: Cálculo de distância Levenshtein com marcas
- **Conteúdo HTML**: Detecção de formulários e campos sensíveis

### Arquitetura

#### Backend (Python/Flask)
- **app.py**: API REST principal com endpoints de análise
- **url_analyzer.py**: Motor de análises básicas e integração
- **advanced_analyzer.py**: Módulo de análises avançadas
- **requirements.txt**: Dependências do projeto

Tecnologias: Flask 3.0.0, python-whois, dnspython, BeautifulSoup4, Levenshtein

#### Frontend (HTML/CSS/JavaScript)
- **index.html**: Interface web interativa
- **style.css**: Estilização responsiva
- **script.js**: Lógica de comunicação com API e visualização

Tecnologias: Vanilla JavaScript, Chart.js 4.4.0, LocalStorage API

### Sistema de Pontuação

O score final varia de 0 a 100 pontos:

**Análises Básicas (0-100 pontos)**
- IP na URL: +40 pontos
- TLD suspeito: +30 pontos
- Subdomínio imita marca: +30 pontos
- Muitos números: +20 pontos
- Letras repetidas: +15 pontos
- E outras verificações...

**Análises Avançadas (até +50 pontos adicionais)**
- Domínio muito novo: +20 pontos
- DNS dinâmico: +15 pontos
- SSL auto-assinado: +15 pontos
- Formulários sensíveis: +20 pontos
- Redirecionamentos cross-domain: +10 pontos
- Alta similaridade com marca: +10 pontos

**Classificação de Risco**
- 0-29 pontos: BAIXO (verde)
- 30-49 pontos: MÉDIO (amarelo)
- 50-69 pontos: ALTO (laranja)
- 70-100 pontos: CRÍTICO (vermelho)

## Guia de Uso

### Instalação

1. Clone o repositório:
```bash
git clone <repository-url>
cd TecHacker
```

2. Instale as dependências do backend:
```bash
cd backend
pip install -r requirements.txt
```

3. Inicie a aplicação:
```bash
./start.sh
```

### Uso da Ferramenta

#### Análise Individual

1. Abra a interface web no navegador
2. Digite ou cole a URL suspeita no campo de entrada
3. Clique no botão "Analisar"
4. Aguarde o resultado (2-5 segundos para análises completas)

#### Interpretando Resultados

**Seção Principal**
- Status geral (PHISHING DETECTADO ou URL SEGURA)
- Nível de risco (BAIXO, MÉDIO, ALTO, CRÍTICO)
- Pontuação total (0-100)
- Recomendação de ação

**Características Detectadas**
- Lista de avisos e padrões identificados
- Gráfico de distribuição (tipos de características)

**Análises Avançadas** (expandíveis)
- WHOIS: Informações do domínio
- SSL: Dados do certificado
- Similaridade: Comparação com marcas
- Conteúdo: Análise da página HTML
- Redirecionamentos: Cadeia de redirecionamentos

**Detalhes Técnicos**
- Todas as verificações realizadas
- Valores booleanos e numéricos de cada teste

#### Recursos Adicionais

**Histórico de Análises**
- Clique em "Ver Histórico" para visualizar análises anteriores
- Clique em qualquer item para recarregar seus detalhes
- Limite de 50 análises armazenadas localmente
- "Limpar Histórico" remove todas as entradas

**Exportação de Dados**
- "Exportar Resultado": Salva a análise atual em JSON
- "Exportar Histórico": Salva todas as análises em JSON
- Arquivos incluem timestamp e são nomeados automaticamente

### Exemplos de Teste

**URL Legítima**
```
https://www.google.com
```
Resultado esperado: Score baixo, sem alertas graves

**Phishing Complexo**
```
https://metamask-lloginn.webflow.io/
```
Resultado esperado: Score alto (70-90), múltiplos alertas:
- Imitação de marca (MetaMask)
- Letras repetidas (lloginn)
- Hospedagem suspeita



### API REST

#### Endpoint: POST /api/analyze

Analisa uma URL individual.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "is_phishing": false,
  "score": 15,
  "risk_level": "BAIXO",
  "recommendation": "URL parece segura...",
  "checks": {
    "has_ip": false,
    "suspicious_tld": false,
    ...
  },
  "advanced": {
    "whois": {...},
    "ssl": {...},
    "similarity": {...},
    "content": {...},
    "redirects": {...}
  }
}
```

#### Endpoint: POST /api/batch-analyze

Analisa múltiplas URLs.

**Request:**
```json
{
  "urls": ["https://example1.com", "https://example2.com"]
}
```

**Response:**
```json
{
  "results": [...],
  "summary": {
    "total": 2,
    "phishing_detected": 1,
    "safe": 1
  }
}
```

#### Endpoint: GET /api/health

Verifica status do servidor.

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

### Estrutura de Arquivos

```
TecHacker/
├── backend/
│   ├── app.py                    # API Flask principal
│   ├── url_analyzer.py           # Motor de análises básicas
│   ├── advanced_analyzer.py      # Análises avançadas
│   └── requirements.txt          # Dependências Python
├── frontend/
│   ├── index.html                # Interface web
│   ├── style.css                 # Estilos CSS
│   ├── script.js                 # Lógica JavaScript
│   └── script_c.js               # Backup Conceito C
├── README.md                     # Este arquivo
├── QUICKSTART.md                 # Guia rápido
├── CONCEITO_B_COMPLETO.md        # Documentação técnica
├── GUIA_CONCEITO_B.md            # Guia de funcionalidades
└── EXEMPLOS_URLS.md              # URLs de teste
```

### Dependências

**Backend (Python 3.8+)**
- flask==3.0.0
- flask-cors==4.0.0
- requests==2.31.0
- tldextract==5.1.1
- python-whois==0.8.0
- dnspython==2.4.2
- beautifulsoup4==4.12.2
- python-Levenshtein==0.23.0

**Frontend**
- Chart.js 4.4.0 (via CDN)
- Navegador moderno com suporte a ES6


### Licença

Este projeto foi desenvolvido para fins educacionais.

