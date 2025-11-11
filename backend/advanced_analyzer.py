"""
Módulo de análises avançadas para detecção de phishing (Conceito B)
Implementa análises heurísticas avançadas incluindo WHOIS, SSL, DNS, etc.
"""

import whois
import socket
import ssl
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import logging
from urllib.parse import urlparse
import dns.resolver
from bs4 import BeautifulSoup
import Levenshtein

logger = logging.getLogger(__name__)


class AdvancedAnalyzer:
    """
    Classe para análises avançadas de URLs (Conceito B)
    """
    
    def __init__(self):
        # Serviços de DNS dinâmico conhecidos
        self.dynamic_dns_providers = [
            'no-ip.com', 'no-ip.org', 'no-ip.biz',
            'dyndns.org', 'dyndns.com',
            'ddns.net', 'duckdns.org',
            'afraid.org', 'changeip.com',
            'dnsdynamic.org', 'dynu.com'
        ]
        
        # Marcas conhecidas para análise de similaridade
        self.known_brands = [
            'google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal',
            'netflix', 'instagram', 'twitter', 'linkedin', 'github',
            'metamask', 'coinbase', 'binance', 'blockchain',
            'itau', 'bradesco', 'santander', 'nubank', 'inter',
            'mercadolivre', 'mercadopago'
        ]
    
    def analyze_whois(self, domain: str) -> Dict[str, Any]:
        """
        Analisa informações WHOIS do domínio
        Retorna idade do domínio, data de criação, expiração, etc.
        """
        try:
            w = whois.whois(domain)
            
            # Extrair data de criação
            creation_date = None
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
            
            # Calcular idade do domínio
            domain_age_days = None
            is_new_domain = False
            
            if creation_date:
                domain_age_days = (datetime.now() - creation_date).days
                is_new_domain = domain_age_days < 365  # Menos de 1 ano
            
            # Extrair data de expiração
            expiration_date = None
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    expiration_date = w.expiration_date[0]
                else:
                    expiration_date = w.expiration_date
            
            return {
                'available': True,
                'domain_age_days': domain_age_days,
                'is_new_domain': is_new_domain,
                'creation_date': creation_date.isoformat() if creation_date else None,
                'expiration_date': expiration_date.isoformat() if expiration_date else None,
                'registrar': w.registrar,
                'country': w.country if hasattr(w, 'country') else None,
                'error': None
            }
            
        except Exception as e:
            logger.warning(f"Erro ao consultar WHOIS para {domain}: {str(e)}")
            return {
                'available': False,
                'error': str(e),
                'domain_age_days': None,
                'is_new_domain': None
            }
    
    def check_dynamic_dns(self, domain: str) -> bool:
        """
        Verifica se o domínio usa serviço de DNS dinâmico
        """
        domain_lower = domain.lower()
        return any(provider in domain_lower for provider in self.dynamic_dns_providers)
    
    def analyze_ssl_certificate(self, hostname: str) -> Dict[str, Any]:
        """
        Analisa o certificado SSL do domínio
        Verifica emissor, validade, e coincidência com o domínio
        """
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extrair informações do certificado
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    
                    # Verificar validade
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    
                    days_until_expiry = (not_after - datetime.now()).days
                    is_expired = days_until_expiry < 0
                    expires_soon = 0 < days_until_expiry < 30
                    
                    # Verificar se o domínio coincide com o certificado
                    cert_common_name = subject.get('commonName', '')
                    domain_matches = hostname in cert_common_name or cert_common_name in hostname
                    
                    # Verificar emissor (Let's Encrypt é grátis e comum em phishing)
                    issuer_org = issuer.get('organizationName', '')
                    is_self_signed = issuer_org == subject.get('organizationName', '')
                    uses_free_ssl = 'Let\'s Encrypt' in issuer_org
                    
                    return {
                        'available': True,
                        'issuer': issuer_org,
                        'is_self_signed': is_self_signed,
                        'uses_free_ssl': uses_free_ssl,
                        'is_expired': is_expired,
                        'expires_soon': expires_soon,
                        'days_until_expiry': days_until_expiry,
                        'domain_matches': domain_matches,
                        'common_name': cert_common_name,
                        'valid_from': not_before.isoformat(),
                        'valid_until': not_after.isoformat(),
                        'error': None
                    }
                    
        except socket.timeout:
            logger.warning(f"Timeout ao conectar ao SSL de {hostname}")
            return {'available': False, 'error': 'Timeout na conexão SSL'}
        except ssl.SSLError as e:
            logger.warning(f"Erro SSL para {hostname}: {str(e)}")
            return {'available': False, 'error': f'Erro SSL: {str(e)}'}
        except Exception as e:
            logger.warning(f"Erro ao analisar SSL de {hostname}: {str(e)}")
            return {'available': False, 'error': str(e)}
    
    def check_redirects(self, url: str) -> Dict[str, Any]:
        """
        Verifica redirecionamentos suspeitos
        """
        try:
            response = requests.head(url, allow_redirects=True, timeout=10)
            
            redirect_count = len(response.history)
            has_redirects = redirect_count > 0
            has_multiple_redirects = redirect_count > 2
            
            # Verificar se redireciona para domínio diferente
            original_domain = urlparse(url).netloc
            final_domain = urlparse(response.url).netloc
            crosses_domains = original_domain != final_domain
            
            return {
                'has_redirects': has_redirects,
                'redirect_count': redirect_count,
                'has_multiple_redirects': has_multiple_redirects,
                'crosses_domains': crosses_domains,
                'final_url': response.url,
                'status_code': response.status_code
            }
            
        except Exception as e:
            logger.warning(f"Erro ao verificar redirecionamentos de {url}: {str(e)}")
            return {
                'has_redirects': False,
                'redirect_count': 0,
                'error': str(e)
            }
    
    def calculate_brand_similarity(self, domain: str) -> Dict[str, Any]:
        """
        Calcula similaridade com marcas conhecidas usando distância de Levenshtein
        """
        domain_clean = domain.lower().replace('-', '').replace('_', '')
        
        similarities = {}
        max_similarity = 0
        most_similar_brand = None
        
        for brand in self.known_brands:
            # Calcular distância de Levenshtein
            distance = Levenshtein.distance(domain_clean, brand)
            
            # Calcular similaridade (0-100%)
            max_len = max(len(domain_clean), len(brand))
            similarity = (1 - distance / max_len) * 100 if max_len > 0 else 0
            
            similarities[brand] = round(similarity, 2)
            
            if similarity > max_similarity:
                max_similarity = similarity
                most_similar_brand = brand
        
        # Considera suspeito se similaridade > 70% mas não exatamente igual
        is_similar = max_similarity > 70 and domain_clean != most_similar_brand
        
        return {
            'most_similar_brand': most_similar_brand,
            'similarity_score': round(max_similarity, 2),
            'is_similar_to_brand': is_similar,
            'all_similarities': similarities
        }
    
    def analyze_page_content(self, url: str) -> Dict[str, Any]:
        """
        Analisa o conteúdo HTML da página
        Detecta formulários de login e solicitações de dados sensíveis
        """
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code != 200:
                return {'available': False, 'error': f'Status code: {response.status_code}'}
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Detectar formulários
            forms = soup.find_all('form')
            has_forms = len(forms) > 0
            
            # Detectar campos sensíveis
            password_fields = soup.find_all('input', {'type': 'password'})
            email_fields = soup.find_all('input', {'type': 'email'})
            
            # Procurar por padrões de campos sensíveis por name/id
            sensitive_patterns = ['password', 'passwd', 'pwd', 'email', 'user', 'login', 
                                'credit', 'card', 'cvv', 'ssn', 'cpf']
            
            all_inputs = soup.find_all('input')
            sensitive_fields = []
            
            for inp in all_inputs:
                name = inp.get('name', '').lower()
                id_attr = inp.get('id', '').lower()
                
                if any(pattern in name or pattern in id_attr for pattern in sensitive_patterns):
                    sensitive_fields.append({
                        'type': inp.get('type'),
                        'name': inp.get('name'),
                        'id': inp.get('id')
                    })
            
            has_login_form = len(password_fields) > 0
            has_sensitive_fields = len(sensitive_fields) > 0
            
            # Detectar solicitação de informações financeiras
            text_content = soup.get_text().lower()
            asks_for_financial_info = any(word in text_content for word in 
                                          ['credit card', 'cartão de crédito', 'cvv', 
                                           'card number', 'número do cartão'])
            
            return {
                'available': True,
                'has_forms': has_forms,
                'form_count': len(forms),
                'has_login_form': has_login_form,
                'has_sensitive_fields': has_sensitive_fields,
                'sensitive_field_count': len(sensitive_fields),
                'asks_for_financial_info': asks_for_financial_info,
                'title': soup.title.string if soup.title else None,
                'error': None
            }
            
        except requests.Timeout:
            return {'available': False, 'error': 'Timeout ao carregar página'}
        except Exception as e:
            logger.warning(f"Erro ao analisar conteúdo de {url}: {str(e)}")
            return {'available': False, 'error': str(e)}
