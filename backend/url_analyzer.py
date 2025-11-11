import re
import requests
from urllib.parse import urlparse, parse_qs
import tldextract
import string
from typing import Dict, List, Any
import logging
from advanced_analyzer import AdvancedAnalyzer

logger = logging.getLogger(__name__)

class URLAnalyzer:
    """
    Classe para análise de URLs e detecção de características de phishing
    Implementação dos conceitos C e B
    """
    
    def __init__(self, enable_advanced=True):
        # Inicializar analisador avançado (Conceito B)
        self.enable_advanced = enable_advanced
        if enable_advanced:
            self.advanced = AdvancedAnalyzer()
        else:
            self.advanced = None
        # Lista de domínios conhecidos de marcas populares
        self.legitimate_brands = [
            'google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal',
            'netflix', 'instagram', 'twitter', 'linkedin', 'github', 'reddit',
            'youtube', 'whatsapp', 'dropbox', 'adobe', 'salesforce', 'oracle',
            'spotify', 'ebay', 'aliexpress', 'walmart', 'metamask', 'coinbase',
            'binance', 'blockchain', 'trust', 'ledger', 'trezor', 'exodus',
            'itau', 'bradesco', 'santander', 'caixa', 'nubank', 'inter',
            'mercadolivre', 'mercadopago', 'picpay', 'pagseguro'
        ]
        
        # Serviços de hospedagem legítimos (mas podem hospedar phishing)
        self.trusted_hosting = [
            'webflow', 'wix', 'squarespace', 'wordpress', 'blogspot', 
            'github.io', 'gitlab.io', 'netlify', 'vercel', 'herokuapp',
            'cloudflare', 'amazonaws', 'azurewebsites', 'googleusercontent'
        ]
        
        # Palavras suspeitas comumente usadas em phishing
        self.suspicious_words = [
            'verify', 'account', 'update', 'confirm', 'login', 'signin',
            'banking', 'secure', 'webscr', 'lucky', 'winner', 'free',
            'bonus', 'urgent', 'suspended', 'unusual', 'click'
        ]
        
        # TLDs suspeitos
        self.suspicious_tlds = [
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'date'
        ]
    
    def analyze(self, url: str) -> Dict[str, Any]:
        """
        Analisa uma URL e retorna um dicionário com os resultados
        """
        try:
            # Validar URL básica
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            # Realizar todas as verificações
            # Verificar subdomínio E domínio para características suspeitas
            full_domain_check = f"{extracted.subdomain}.{extracted.domain}" if extracted.subdomain else extracted.domain
            
            checks = {
                'has_ip_address': self._check_ip_address(parsed.netloc),
                'has_at_symbol': '@' in url,
                'url_length': len(url),
                'is_url_too_long': len(url) > 75,
                'has_suspicious_tld': extracted.suffix.lower() in self.suspicious_tlds,
                'has_excessive_subdomains': self._check_excessive_subdomains(extracted),
                'has_numbers_in_domain': self._check_numbers_in_domain(full_domain_check),
                'has_special_chars': self._check_special_characters(full_domain_check),
                'uses_https': parsed.scheme == 'https',
                'has_suspicious_words': self._check_suspicious_words(url),
                'mimics_brand': self._check_brand_mimicry(full_domain_check),
                'subdomain_mimics_brand': self._check_brand_mimicry(extracted.subdomain) if extracted.subdomain else False,
                'has_many_dots': url.count('.') > 4,
                'has_double_slash': '//' in parsed.path,
                'domain_length': len(extracted.domain),
                'subdomain_count': len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
                'has_repeated_letters': self._check_repeated_letters(full_domain_check),
                'uses_trusted_hosting': self._check_trusted_hosting(extracted.domain, extracted.suffix)
            }
            
            # Calcular score de phishing (0-100)
            score = self._calculate_phishing_score(checks)
            
            # Determinar se é phishing
            is_phishing = score >= 50
            risk_level = self._get_risk_level(score)
            
            result = {
                'url': url,
                'domain': f"{extracted.domain}.{extracted.suffix}",
                'subdomain': extracted.subdomain if extracted.subdomain else None,
                'is_phishing': is_phishing,
                'phishing_score': score,
                'risk_level': risk_level,
                'checks': checks,
                'warnings': self._generate_warnings(checks),
                'recommendation': self._generate_recommendation(score)
            }
            
            # Análises avançadas (Conceito B)
            if self.enable_advanced and self.advanced:
                advanced_results = self._perform_advanced_analysis(url, extracted, checks)
                result['advanced'] = advanced_results
                
                # Recalcular score com análises avançadas
                advanced_score_adjustment = self._calculate_advanced_score(advanced_results)
                result['phishing_score'] = min(score + advanced_score_adjustment, 100)
                result['is_phishing'] = result['phishing_score'] >= 50
                result['risk_level'] = self._get_risk_level(result['phishing_score'])
                
                # Adicionar avisos avançados
                advanced_warnings = self._generate_advanced_warnings(advanced_results)
                result['warnings'].extend(advanced_warnings)
            
            logger.info(f"URL analisada: {url} - Score: {result['phishing_score']} - Phishing: {result['is_phishing']}")
            
            return result
            
        except Exception as e:
            logger.error(f"Erro ao analisar URL {url}: {str(e)}")
            raise
    
    def _check_ip_address(self, netloc: str) -> bool:
        """Verifica se a URL usa endereço IP ao invés de domínio"""
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        return bool(ip_pattern.search(netloc))
    
    def _check_excessive_subdomains(self, extracted) -> bool:
        """Verifica se há uso excessivo de subdomínios (mais de 2)"""
        if not extracted.subdomain:
            return False
        subdomain_parts = extracted.subdomain.split('.')
        return len(subdomain_parts) > 2
    
    def _check_numbers_in_domain(self, domain: str) -> bool:
        """Verifica presença de números no domínio"""
        return bool(re.search(r'\d', domain))
    
    def _check_special_characters(self, domain: str) -> bool:
        """Verifica presença de caracteres especiais suspeitos no domínio"""
        special_chars = ['-', '_']
        return any(char in domain for char in special_chars) and domain.count('-') > 1
    
    def _check_suspicious_words(self, url: str) -> bool:
        """Verifica presença de palavras suspeitas na URL"""
        url_lower = url.lower()
        return any(word in url_lower for word in self.suspicious_words)
    
    def _check_brand_mimicry(self, domain: str) -> bool:
        """Verifica se o domínio tenta imitar uma marca conhecida"""
        domain_lower = domain.lower()
        for brand in self.legitimate_brands:
            # Verifica se contém o nome da marca mas não é exatamente a marca
            if brand in domain_lower and domain_lower != brand:
                # Verifica substituições comuns: 0 por o, 1 por l, etc
                if self._has_character_substitution(domain_lower, brand):
                    return True
                # Verifica se apenas contém o nome da marca com outros caracteres
                if len(domain_lower) > len(brand) + 2:
                    return True
        return False
    
    def _has_character_substitution(self, domain: str, brand: str) -> bool:
        """Verifica substituições comuns de caracteres"""
        substitutions = {
            '0': 'o',
            '1': 'l',
            '3': 'e',
            '4': 'a',
            '5': 's',
            '7': 't'
        }
        for num, letter in substitutions.items():
            if num in domain and letter in brand:
                return True
        return False
    
    def _check_repeated_letters(self, domain: str) -> bool:
        """
        Verifica se há letras repetidas suspeitas (ex: lloginn, faceb00k)
        Phishers frequentemente duplicam letras para criar domínios similares
        """
        if not domain:
            return False
        
        # Padrões suspeitos de repetição
        # Procura por 3+ letras iguais seguidas ou padrões específicos
        suspicious_patterns = [
            r'(.)\1{2,}',  # 3 ou mais letras iguais (aaa, lll)
            r'll',         # ll no meio do domínio (lloginn)
            r'oo',         # oo suspeito (faceb00k com zeros)
        ]
        
        domain_lower = domain.lower()
        
        # Palavras legítimas que têm letras duplas (para não dar falso positivo)
        legitimate_doubles = ['google', 'paypal', 'twitter', 'yahoo', 'bloomberg']
        if any(legit in domain_lower for legit in legitimate_doubles):
            return False
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain_lower):
                # Verificar se é parte de uma marca legítima
                # Se encontrou 'll' mas não está em 'paypal', é suspeito
                if pattern == r'll':
                    # Exceções: paypal, email, etc.
                    if 'paypal' in domain_lower or 'email' in domain_lower:
                        continue
                return True
        
        return False
    
    def _check_trusted_hosting(self, domain: str, tld: str) -> bool:
        """
        Verifica se está usando serviço de hospedagem confiável
        Mas se estiver, aumenta suspeita se subdomínio imita marca
        """
        full_domain = f"{domain}.{tld}".lower()
        
        for hosting in self.trusted_hosting:
            if hosting in full_domain:
                return True
        
        return False
    
    def _calculate_phishing_score(self, checks: Dict[str, Any]) -> int:
        """
        Calcula um score de 0-100 indicando probabilidade de phishing
        Quanto maior o score, mais provável que seja phishing
        """
        score = 0
        
        # Pesos para cada verificação
        if checks['has_ip_address']:
            score += 20
        if checks['has_at_symbol']:
            score += 15
        if checks['is_url_too_long']:
            score += 10
        if checks['has_suspicious_tld']:
            score += 15
        if checks['has_excessive_subdomains']:
            score += 15
        if checks['has_numbers_in_domain']:
            score += 8
        if checks['has_special_chars']:
            score += 10
        if not checks['uses_https']:
            score += 12
        if checks['has_suspicious_words']:
            score += 12
        if checks['mimics_brand']:
            score += 25
        if checks['has_many_dots']:
            score += 8
        if checks['has_double_slash']:
            score += 5
        
        # Novas verificações
        if checks.get('subdomain_mimics_brand'):
            score += 30  # Subdomínio imitando marca é MUITO suspeito
        if checks.get('has_repeated_letters'):
            score += 15  # Letras repetidas (lloginn)
        if checks.get('uses_trusted_hosting') and (checks['mimics_brand'] or checks.get('subdomain_mimics_brand')):
            # Se usa hospedagem confiável MAS imita marca = phishing usando serviço legítimo
            score += 25
        
        return min(score, 100)
    
    def _get_risk_level(self, score: int) -> str:
        """Retorna o nível de risco baseado no score"""
        if score < 30:
            return 'BAIXO'
        elif score < 50:
            return 'MÉDIO'
        elif score < 70:
            return 'ALTO'
        else:
            return 'CRÍTICO'
    
    def _generate_warnings(self, checks: Dict[str, Any]) -> List[str]:
        """Gera uma lista de avisos baseados nas verificações"""
        warnings = []
        
        if checks['has_ip_address']:
            warnings.append("⚠️ URL usa endereço IP ao invés de nome de domínio")
        if checks['has_at_symbol']:
            warnings.append("⚠️ URL contém símbolo '@', técnica comum em phishing")
        if checks['is_url_too_long']:
            warnings.append("⚠️ URL muito longa (comum em tentativas de ofuscação)")
        if checks['has_suspicious_tld']:
            warnings.append("⚠️ Domínio usa extensão suspeita")
        if checks['has_excessive_subdomains']:
            warnings.append("⚠️ Uso excessivo de subdomínios")
        if checks['has_numbers_in_domain']:
            warnings.append("⚠️ Domínio contém números (possível substituição de letras)")
        if checks['has_special_chars']:
            warnings.append("⚠️ Domínio contém caracteres especiais em excesso")
        if not checks['uses_https']:
            warnings.append("⚠️ Conexão não segura (HTTP ao invés de HTTPS)")
        if checks['has_suspicious_words']:
            warnings.append("⚠️ URL contém palavras suspeitas comuns em phishing")
        if checks['mimics_brand']:
            warnings.append("⚠️ ALERTA: Domínio parece imitar uma marca conhecida")
        if checks['has_many_dots']:
            warnings.append("⚠️ Muitos pontos na URL")
        if checks['has_double_slash']:
            warnings.append("⚠️ Barras duplas suspeitas no caminho")
        
        # Novos avisos
        if checks.get('subdomain_mimics_brand'):
            warnings.append("🚨 ALERTA CRÍTICO: Subdomínio imita marca conhecida (ex: metamask-lloginn.webflow.io)")
        if checks.get('has_repeated_letters'):
            warnings.append("⚠️ Letras repetidas suspeitas detectadas (ex: lloginn ao invés de login)")
        if checks.get('uses_trusted_hosting') and (checks['mimics_brand'] or checks.get('subdomain_mimics_brand')):
            warnings.append("🚨 PERIGO: Phishing hospedado em serviço legítimo (webflow, wix, etc)")
        
        return warnings if warnings else ["✅ Nenhum sinal óbvio de phishing detectado"]
    
    def _generate_recommendation(self, score: int) -> str:
        """Gera uma recomendação baseada no score"""
        if score < 30:
            return "✅ URL parece segura. Mantenha práticas de segurança ao navegar."
        elif score < 50:
            return "⚠️ URL apresenta algumas características suspeitas. Prossiga com cautela."
        elif score < 70:
            return "🚨 URL altamente suspeita. Não é recomendado acessar ou fornecer informações."
        else:
            return "🛑 PERIGO! URL com fortes indícios de phishing. NÃO acesse e NÃO forneça dados."
    
    def _perform_advanced_analysis(self, url: str, extracted, checks: Dict[str, Any]) -> Dict[str, Any]:
        """
        Realiza análises avançadas (Conceito B)
        """
        domain_full = f"{extracted.domain}.{extracted.suffix}"
        hostname = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
        
        advanced_results = {}
        
        # 1. Análise WHOIS
        logger.info(f"Executando análise WHOIS para {domain_full}")
        advanced_results['whois'] = self.advanced.analyze_whois(domain_full)
        
        # 2. Verificar DNS dinâmico
        advanced_results['uses_dynamic_dns'] = self.advanced.check_dynamic_dns(domain_full)
        
        # 3. Análise SSL (apenas se usar HTTPS)
        if checks['uses_https']:
            logger.info(f"Executando análise SSL para {hostname}")
            advanced_results['ssl'] = self.advanced.analyze_ssl_certificate(hostname)
        else:
            advanced_results['ssl'] = {'available': False, 'error': 'Site não usa HTTPS'}
        
        # 4. Verificar redirecionamentos
        logger.info(f"Verificando redirecionamentos para {url}")
        advanced_results['redirects'] = self.advanced.check_redirects(url)
        
        # 5. Similaridade com marcas (Levenshtein)
        logger.info(f"Calculando similaridade com marcas conhecidas")
        advanced_results['brand_similarity'] = self.advanced.calculate_brand_similarity(extracted.domain)
        
        # 6. Análise de conteúdo da página
        logger.info(f"Analisando conteúdo da página {url}")
        advanced_results['content'] = self.advanced.analyze_page_content(url)
        
        return advanced_results
    
    def _calculate_advanced_score(self, advanced: Dict[str, Any]) -> int:
        """
        Calcula ajuste no score baseado em análises avançadas
        Retorna pontos adicionais (0-50)
        """
        additional_score = 0
        
        # WHOIS - Domínio novo é suspeito
        whois_data = advanced.get('whois', {})
        if whois_data.get('available') and whois_data.get('is_new_domain'):
            additional_score += 15
            logger.info(f"Domínio novo detectado (< 1 ano): +15 pontos")
        
        # DNS Dinâmico - Muito suspeito
        if advanced.get('uses_dynamic_dns'):
            additional_score += 20
            logger.info(f"DNS dinâmico detectado: +20 pontos")
        
        # SSL
        ssl_data = advanced.get('ssl', {})
        if ssl_data.get('available'):
            if ssl_data.get('is_self_signed'):
                additional_score += 15
                logger.info(f"Certificado auto-assinado: +15 pontos")
            if ssl_data.get('is_expired'):
                additional_score += 20
                logger.info(f"Certificado expirado: +20 pontos")
            if not ssl_data.get('domain_matches'):
                additional_score += 15
                logger.info(f"Domínio não coincide com certificado: +15 pontos")
            if ssl_data.get('expires_soon'):
                additional_score += 5
                logger.info(f"Certificado expira em breve: +5 pontos")
        
        # Redirecionamentos
        redirects = advanced.get('redirects', {})
        if redirects.get('has_multiple_redirects'):
            additional_score += 10
            logger.info(f"Múltiplos redirecionamentos: +10 pontos")
        if redirects.get('crosses_domains'):
            additional_score += 12
            logger.info(f"Redirecionamento entre domínios: +12 pontos")
        
        # Similaridade com marcas (Levenshtein)
        similarity = advanced.get('brand_similarity', {})
        if similarity.get('is_similar_to_brand'):
            additional_score += 20
            logger.info(f"Alta similaridade com marca ({similarity.get('most_similar_brand')}): +20 pontos")
        
        # Conteúdo da página
        content = advanced.get('content', {})
        if content.get('available'):
            if content.get('has_login_form'):
                additional_score += 15
                logger.info(f"Formulário de login detectado: +15 pontos")
            if content.get('asks_for_financial_info'):
                additional_score += 20
                logger.info(f"Solicita informações financeiras: +20 pontos")
        
        logger.info(f"Score adicional de análises avançadas: +{additional_score} pontos")
        return additional_score
    
    def _generate_advanced_warnings(self, advanced: Dict[str, Any]) -> List[str]:
        """
        Gera avisos baseados em análises avançadas
        """
        warnings = []
        
        # WHOIS
        whois_data = advanced.get('whois', {})
        if whois_data.get('available'):
            if whois_data.get('is_new_domain'):
                age_days = whois_data.get('domain_age_days', 0)
                warnings.append(f"🚨 Domínio muito novo ({age_days} dias) - comum em phishing")
        
        # DNS Dinâmico
        if advanced.get('uses_dynamic_dns'):
            warnings.append("🚨 CRÍTICO: Usa serviço de DNS dinâmico (no-ip, dyndns, etc)")
        
        # SSL
        ssl_data = advanced.get('ssl', {})
        if ssl_data.get('available'):
            if ssl_data.get('is_self_signed'):
                warnings.append("⚠️ Certificado SSL auto-assinado (não confiável)")
            if ssl_data.get('is_expired'):
                warnings.append("🚨 CRÍTICO: Certificado SSL expirado")
            if not ssl_data.get('domain_matches'):
                warnings.append("⚠️ Domínio não corresponde ao certificado SSL")
            if ssl_data.get('uses_free_ssl'):
                warnings.append("ℹ️ Usa certificado SSL gratuito (Let's Encrypt) - comum em phishing")
        elif not advanced.get('checks', {}).get('uses_https'):
            # Já tem aviso no básico
            pass
        
        # Redirecionamentos
        redirects = advanced.get('redirects', {})
        if redirects.get('has_multiple_redirects'):
            count = redirects.get('redirect_count', 0)
            warnings.append(f"⚠️ Múltiplos redirecionamentos detectados ({count})")
        if redirects.get('crosses_domains'):
            warnings.append("⚠️ Redireciona para domínio diferente")
        
        # Similaridade
        similarity = advanced.get('brand_similarity', {})
        if similarity.get('is_similar_to_brand'):
            brand = similarity.get('most_similar_brand')
            score = similarity.get('similarity_score')
            warnings.append(f"🚨 ALERTA: {score}% similar a '{brand}' (possível typosquatting)")
        
        # Conteúdo
        content = advanced.get('content', {})
        if content.get('available'):
            if content.get('has_login_form'):
                warnings.append("⚠️ Página contém formulário de login")
            if content.get('has_sensitive_fields'):
                count = content.get('sensitive_field_count', 0)
                warnings.append(f"⚠️ Solicita informações sensíveis ({count} campos)")
            if content.get('asks_for_financial_info'):
                warnings.append("🚨 CRÍTICO: Solicita informações financeiras (cartão, CVV, etc)")
        
        return warnings
