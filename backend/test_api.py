"""
Script de teste para a API do TecHacker
Execute: python3 test_api.py
"""

import requests
import json

API_URL = "http://localhost:5000/api"

# URLs de teste
test_urls = {
    "Phishing Óbvio": [
        "http://paypa1-security.tk/login",
        "https://facebook-verify.xyz/account-update",
        "http://192.168.1.1/secure-login",
        "https://www.apple-id-verification-secure-login-update.com",
        "http://google-security@malicious.com/verify"
    ],
    "Suspeito": [
        "http://amaz0n-deals.online/products",
        "https://netfl1x-free-trial.xyz",
        "http://instagram-followers-free.tk"
    ],
    "Legítimo": [
        "https://www.google.com",
        "https://github.com",
        "https://www.paypal.com",
        "https://www.amazon.com",
        "https://www.facebook.com"
    ]
}

def test_health():
    """Testa o endpoint de health check"""
    print("\n🏥 Testando Health Check...")
    try:
        response = requests.get(f"{API_URL}/health")
        if response.status_code == 200:
            print("✅ API está funcionando!")
            print(f"   Resposta: {response.json()}")
            return True
        else:
            print(f"❌ API retornou status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erro ao conectar: {e}")
        return False

def analyze_url(url):
    """Analisa uma URL específica"""
    try:
        response = requests.post(
            f"{API_URL}/analyze",
            json={"url": url},
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def print_result(result):
    """Imprime o resultado de forma formatada"""
    if "error" in result:
        print(f"   ❌ Erro: {result['error']}")
        return
    
    # Emoji baseado no risco
    risk_emoji = {
        "BAIXO": "✅",
        "MÉDIO": "⚠️",
        "ALTO": "🚨",
        "CRÍTICO": "🛑"
    }
    
    emoji = risk_emoji.get(result.get('risk_level', ''), '❓')
    
    print(f"   {emoji} Score: {result['phishing_score']}/100 | Risco: {result['risk_level']}")
    print(f"   Domínio: {result['domain']}")
    print(f"   Phishing: {'SIM' if result['is_phishing'] else 'NÃO'}")
    
    # Mostrar principais warnings
    if result.get('warnings'):
        print(f"   Avisos: {len(result['warnings'])}")
        for warning in result['warnings'][:3]:  # Mostrar apenas os 3 primeiros
            print(f"      • {warning}")

def run_tests():
    """Executa todos os testes"""
    print("=" * 70)
    print("🛡️  TecHacker - Testes da API de Detecção de Phishing")
    print("=" * 70)
    
    # Testar health check
    if not test_health():
        print("\n❌ API não está disponível. Certifique-se de que o backend está rodando.")
        return
    
    # Testar URLs
    for category, urls in test_urls.items():
        print(f"\n📋 Testando URLs: {category}")
        print("-" * 70)
        
        for url in urls:
            print(f"\n🔍 {url}")
            result = analyze_url(url)
            print_result(result)
    
    print("\n" + "=" * 70)
    print("✅ Testes concluídos!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
