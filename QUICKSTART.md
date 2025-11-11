# 🚀 Guia Rápido de Instalação

## Início Rápido (3 passos)

### 1️⃣ Instalar Dependências

```bash
cd backend
pip3 install -r requirements.txt
```

### 2️⃣ Iniciar o Projeto

**Opção A - Script Automático (Recomendado):**
```bash
./start.sh
```

**Opção B - Manual:**
```bash
# Terminal 1: Backend
cd backend
python3 app.py

# Terminal 2: Frontend (opcional - servidor web)
cd frontend
python3 -m http.server 8000
# Ou abra diretamente: xdg-open index.html
```

### 3️⃣ Acessar a Aplicação

- **Frontend**: Abra `frontend/index.html` no navegador
  - Ou acesse `http://localhost:8000` se estiver usando servidor web
- **Backend API**: `http://localhost:5000`

## 🧪 Testando

### URLs Suspeitas para Teste:
```
http://paypa1-security.tk/login
https://facebook-verify.xyz/account
http://192.168.1.1/secure-login
https://www.apple-id-verification-secure-login.com
```

### URLs Legítimas para Comparação:
```
https://www.google.com
https://github.com
https://www.paypal.com
```

## 🛑 Parar o Servidor

```bash
# Se usou start.sh
kill <PID_mostrado>

# Ou force:
fuser -k 5000/tcp
```

## ❓ Problemas Comuns

### Porta 5000 já em uso
```bash
fuser -k 5000/tcp
```

### Módulos Python não encontrados
```bash
pip3 install -r backend/requirements.txt
```

### CORS Error no Frontend
Certifique-se de que o backend está rodando em `http://localhost:5000`

## 📚 Documentação Completa

Consulte [README.md](README.md) para informações detalhadas sobre:
- Arquitetura do projeto
- Funcionalidades implementadas
- API endpoints
- Sistema de pontuação
- E muito mais!
