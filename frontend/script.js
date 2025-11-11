// Configuração da API
const API_URL = 'http://localhost:5000/api';

// Elementos DOM
const analyzeForm = document.getElementById('analyzeForm');
const urlInput = document.getElementById('urlInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const btnText = document.getElementById('btnText');
const btnLoader = document.getElementById('btnLoader');
const resultsSection = document.getElementById('resultsSection');
const resultCard = document.getElementById('resultCard');

// Event Listeners
analyzeForm.addEventListener('submit', handleAnalyze);

/**
 * Manipula o envio do formulário de análise
 */
async function handleAnalyze(e) {
    e.preventDefault();
    
    const url = urlInput.value.trim();
    
    if (!url) {
        showError('Por favor, digite uma URL para análise');
        return;
    }
    
    // Mostrar loading
    setLoading(true);
    hideResults();
    
    try {
        const result = await analyzeURL(url);
        displayResults(result);
        showResults();
    } catch (error) {
        showError(error.message);
    } finally {
        setLoading(false);
    }
}

/**
 * Faz a requisição para a API de análise
 */
async function analyzeURL(url) {
    try {
        const response = await fetch(`${API_URL}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Erro ao analisar URL');
        }
        
        return data;
    } catch (error) {
        if (error.message.includes('Failed to fetch')) {
            throw new Error('Não foi possível conectar ao servidor. Verifique se o backend está rodando.');
        }
        throw error;
    }
}

/**
 * Exibe os resultados da análise na página
 */
function displayResults(result) {
    // Status principal
    const mainStatus = document.getElementById('mainStatus');
    const statusClass = result.is_phishing ? 'danger' : 'safe';
    const statusText = result.is_phishing 
        ? '🚨 ALERTA: Possível site de Phishing!' 
        : '✅ URL parece segura';
    
    mainStatus.className = `main-status ${statusClass}`;
    mainStatus.textContent = statusText;
    
    // Informações da URL
    document.getElementById('analyzedUrl').textContent = result.url;
    document.getElementById('domain').textContent = result.domain;
    
    // Nível de risco
    const riskLevel = document.getElementById('riskLevel');
    riskLevel.textContent = result.risk_level;
    riskLevel.className = `info-value risk-badge ${result.risk_level.toLowerCase()}`;
    
    // Score de phishing
    document.getElementById('phishingScore').textContent = `${result.phishing_score}/100`;
    
    // Barra de score
    updateScoreBar(result.phishing_score);
    
    // Recomendação
    const recommendation = document.getElementById('recommendation');
    recommendation.textContent = result.recommendation;
    recommendation.className = getRecommendationClass(result.phishing_score);
    
    // Avisos
    displayWarnings(result.warnings);
    
    // Detalhes técnicos
    displayTechnicalDetails(result.checks);
}

/**
 * Atualiza a barra de progresso do score
 */
function updateScoreBar(score) {
    const scoreBar = document.getElementById('scoreBar');
    scoreBar.style.width = `${score}%`;
    
    // Cor baseada no score
    let color;
    if (score < 30) {
        color = '#10b981'; // Verde
    } else if (score < 50) {
        color = '#f59e0b'; // Amarelo
    } else if (score < 70) {
        color = '#fb923c'; // Laranja
    } else {
        color = '#ef4444'; // Vermelho
    }
    
    scoreBar.style.backgroundColor = color;
    scoreBar.textContent = `${score}%`;
}

/**
 * Retorna a classe CSS para a recomendação baseada no score
 */
function getRecommendationClass(score) {
    if (score < 30) {
        return 'recommendation safe';
    } else if (score < 70) {
        return 'recommendation warning';
    } else {
        return 'recommendation danger';
    }
}

/**
 * Exibe a lista de avisos
 */
function displayWarnings(warnings) {
    const warningsList = document.getElementById('warningsList');
    warningsList.innerHTML = '';
    
    warnings.forEach(warning => {
        const li = document.createElement('li');
        li.textContent = warning;
        
        // Se for um aviso positivo (✅), adicionar classe especial
        if (warning.startsWith('✅')) {
            li.classList.add('safe');
        }
        
        warningsList.appendChild(li);
    });
}

/**
 * Exibe os detalhes técnicos da análise
 */
function displayTechnicalDetails(checks) {
    const technicalDetails = document.getElementById('technicalDetails');
    technicalDetails.innerHTML = '';
    
    const checkLabels = {
        'has_ip_address': 'Usa endereço IP',
        'has_at_symbol': 'Contém símbolo @',
        'url_length': 'Comprimento da URL',
        'is_url_too_long': 'URL muito longa',
        'has_suspicious_tld': 'TLD suspeito',
        'has_excessive_subdomains': 'Subdomínios excessivos',
        'has_numbers_in_domain': 'Números no domínio',
        'has_special_chars': 'Caracteres especiais',
        'uses_https': 'Usa HTTPS',
        'has_suspicious_words': 'Palavras suspeitas',
        'mimics_brand': 'Imita marca conhecida',
        'subdomain_mimics_brand': 'Subdomínio imita marca',
        'has_many_dots': 'Muitos pontos',
        'has_double_slash': 'Barras duplas no caminho',
        'domain_length': 'Comprimento do domínio',
        'subdomain_count': 'Quantidade de subdomínios',
        'has_repeated_letters': 'Letras repetidas suspeitas',
        'uses_trusted_hosting': 'Usa hospedagem confiável'
    };
    
    for (const [key, value] of Object.entries(checks)) {
        const row = document.createElement('div');
        row.className = 'detail-row';
        
        const label = document.createElement('span');
        label.className = 'detail-label';
        label.textContent = checkLabels[key] || key;
        
        const valueSpan = document.createElement('span');
        valueSpan.className = 'detail-value';
        
        // Formatar valor
        if (typeof value === 'boolean') {
            valueSpan.textContent = value ? '✗ Sim' : '✓ Não';
            valueSpan.classList.add(value.toString());
            
            // Para HTTPS e hospedagem confiável, inverter a lógica (são bons quando true)
            if (key === 'uses_https' || key === 'uses_trusted_hosting') {
                valueSpan.textContent = value ? '✓ Sim' : '✗ Não';
                valueSpan.className = `detail-value ${!value}`;
            }
        } else {
            valueSpan.textContent = value;
        }
        
        row.appendChild(label);
        row.appendChild(valueSpan);
        technicalDetails.appendChild(row);
    }
}

/**
 * Exibe mensagem de erro
 */
function showError(message) {
    alert(`❌ Erro: ${message}`);
}

/**
 * Define o estado de loading do botão
 */
function setLoading(loading) {
    analyzeBtn.disabled = loading;
    btnText.style.display = loading ? 'none' : 'inline';
    btnLoader.style.display = loading ? 'inline-block' : 'none';
}

/**
 * Mostra a seção de resultados
 */
function showResults() {
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Esconde a seção de resultados
 */
function hideResults() {
    resultsSection.style.display = 'none';
}

// Verificar se a API está disponível ao carregar a página
window.addEventListener('DOMContentLoaded', async () => {
    try {
        const response = await fetch(`${API_URL}/health`);
        if (!response.ok) {
            console.warn('API pode não estar disponível');
        } else {
            console.log('✅ API conectada com sucesso');
        }
    } catch (error) {
        console.warn('⚠️ Não foi possível conectar à API. Certifique-se de que o backend está rodando.');
    }
});
