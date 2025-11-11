#!/bin/bash

echo "🛡️  TecHacker - Detector de Phishing"
echo "===================================="
echo ""

# Verificar se está no diretório correto
if [ ! -d "backend" ] || [ ! -d "frontend" ]; then
    echo "❌ Erro: Execute este script a partir do diretório raiz do projeto TecHacker"
    exit 1
fi

# Verificar se Python está instalado
if ! command -v python3 &> /dev/null; then
    echo "❌ Erro: Python 3 não está instalado"
    exit 1
fi

# Verificar se as dependências estão instaladas
echo "📦 Verificando dependências..."
cd backend

if ! python3 -c "import flask" 2>/dev/null; then
    echo "⚙️  Instalando dependências Python..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "❌ Erro ao instalar dependências"
        exit 1
    fi
fi

# Parar processos anteriores na porta 5000
echo "🔄 Verificando porta 5000..."
fuser -k 5000/tcp 2>/dev/null
sleep 1

# Iniciar o backend
echo "🚀 Iniciando servidor backend..."
python3 app.py > /tmp/techacker_backend.log 2>&1 &
BACKEND_PID=$!

# Aguardar o backend iniciar
echo "⏳ Aguardando backend iniciar..."
sleep 3

# Verificar se o backend está rodando
if ! ps -p $BACKEND_PID > /dev/null; then
    echo "❌ Erro ao iniciar o backend. Verifique os logs em /tmp/techacker_backend.log"
    exit 1
fi

# Verificar se a API está respondendo
if curl -s http://localhost:5000/api/health > /dev/null 2>&1; then
    echo "✅ Backend iniciado com sucesso!"
else
    echo "⚠️  Backend iniciado, mas não está respondendo imediatamente. Aguardando..."
    sleep 2
fi

echo ""
echo "===================================="
echo "✅ TecHacker está rodando!"
echo "===================================="
echo ""
echo "📍 Backend: http://localhost:5000"
echo "📍 Frontend: file://$(pwd)/../frontend/index.html"
echo ""
echo "📝 Logs do backend: /tmp/techacker_backend.log"
echo "🔢 PID do backend: $BACKEND_PID"
echo ""
echo "Para parar o servidor, execute:"
echo "  kill $BACKEND_PID"
echo "ou"
echo "  fuser -k 5000/tcp"
echo ""

# Abrir frontend no navegador padrão
cd ../frontend
if command -v xdg-open &> /dev/null; then
    echo "🌐 Abrindo frontend no navegador..."
    xdg-open index.html
elif command -v open &> /dev/null; then
    open index.html
fi

echo ""
echo "Pressione Ctrl+C para ver os logs ou feche este terminal quando terminar."
echo ""

# Mostrar logs em tempo real
tail -f /tmp/techacker_backend.log
