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

// Novos elementos (Conceito B)
const historyBtn = document.getElementById('historyBtn');
const exportBtn = document.getElementById('exportBtn');
const historySection = document.getElementById('historySection');
const closeHistoryBtn = document.getElementById('closeHistoryBtn');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');
const exportHistoryBtn = document.getElementById('exportHistoryBtn');
const historyContent = document.getElementById('historyContent');
const explanationModal = document.getElementById('explanationModal');
const modalClose = document.querySelector('.modal-close');

// Variável global para armazenar último resultado
let lastAnalysisResult = null;
let characteristicsChart = null;

// Event Listeners
analyzeForm.addEventListener('submit', handleAnalyze);
historyBtn.addEventListener('click', showHistory);
exportBtn.addEventListener('click', exportResult);
closeHistoryBtn.addEventListener('click', hideHistory);
clearHistoryBtn.addEventListener('click', clearHistory);
exportHistoryBtn.addEventListener('click', exportHistory);
modalClose.addEventListener('click', closeModal);

// Fechar modal clicando fora
window.addEventListener('click', (e) => {
    if (e.target === explanationModal) {
        closeModal();
    }
});

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
    hideHistory();
    
    try {
        const result = await analyzeURL(url);
        lastAnalysisResult = result;
        
        displayResults(result);
        showResults();
        
        // Salvar no histórico
        saveToHistory(result);
        
        // Mostrar botão de exportar
        exportBtn.style.display = 'inline-block';
        
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
    
    // Gráfico de características
    displayCharacteristicsChart(result.checks);
    
    // Análises avançadas (Conceito B)
    if (result.advanced) {
        displayAdvancedAnalysis(result.advanced);
    }
    
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
 * Cria gráfico de distribuição de características
 */
function displayCharacteristicsChart(checks) {
    const canvas = document.getElementById('characteristicsChart');
    const ctx = canvas.getContext('2d');
    
    // Destruir gráfico anterior se existir
    if (characteristicsChart) {
        characteristicsChart.destroy();
    }
    
    // Contar características detectadas
    const detected = Object.values(checks).filter(v => v === true).length;
    const notDetected = Object.values(checks).filter(v => v === false).length;
    
    characteristicsChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Características Suspeitas', 'Características Seguras'],
            datasets: [{
                data: [detected, notDetected],
                backgroundColor: [
                    '#ef4444',
                    '#10b981'
                ],
                borderWidth: 2,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = detected + notDetected;
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Exibe análises avançadas (Conceito B)
 */
function displayAdvancedAnalysis(advanced) {
    const advancedSection = document.getElementById('advancedSection');
    advancedSection.style.display = 'block';
    
    // WHOIS
    displayWHOIS(advanced.whois || {});
    
    // SSL
    displaySSL(advanced.ssl || {});
    
    // Similaridade
    displaySimilarity(advanced.brand_similarity || {});
    
    // Conteúdo
    displayContent(advanced.content || {});
    
    // Redirecionamentos
    displayRedirects(advanced.redirects || {});
}

/**
 * Exibe informações WHOIS
 */
function displayWHOIS(whois) {
    const container = document.getElementById('whoisDetails');
    container.innerHTML = '';
    
    if (!whois.available) {
        container.innerHTML = `<p class="advanced-value negative">❌ ${whois.error || 'Informações não disponíveis'}</p>`;
        return;
    }
    
    const items = [
        { label: 'Idade do Domínio', value: whois.domain_age_days ? `${whois.domain_age_days} dias` : 'Desconhecido', class: whois.is_new_domain ? 'negative' : 'positive' },
        { label: 'Data de Criação', value: whois.creation_date ? new Date(whois.creation_date).toLocaleDateString('pt-BR') : 'Desconhecido' },
        { label: 'Data de Expiração', value: whois.expiration_date ? new Date(whois.expiration_date).toLocaleDateString('pt-BR') : 'Desconhecido' },
        { label: 'Registrador', value: whois.registrar || 'Desconhecido' },
        { label: 'País', value: whois.country || 'Desconhecido' },
        { label: 'Status', value: whois.is_new_domain ? '⚠️ Domínio Novo (< 1 ano)' : '✅ Domínio Estabelecido', class: whois.is_new_domain ? 'warning' : 'positive' }
    ];
    
    items.forEach(item => {
        const div = createAdvancedItem(item.label, item.value, item.class);
        container.appendChild(div);
    });
}

/**
 * Exibe informações SSL
 */
function displaySSL(ssl) {
    const container = document.getElementById('sslDetails');
    container.innerHTML = '';
    
    if (!ssl.available) {
        container.innerHTML = `<p class="advanced-value negative">❌ ${ssl.error || 'Certificado não disponível'}</p>`;
        return;
    }
    
    const items = [
        { label: 'Emissor', value: ssl.issuer || 'Desconhecido' },
        { label: 'Nome Comum', value: ssl.common_name || 'Desconhecido' },
        { label: 'Válido Até', value: ssl.valid_until ? new Date(ssl.valid_until).toLocaleDateString('pt-BR') : 'Desconhecido' },
        { label: 'Dias até Expirar', value: ssl.days_until_expiry || 'Desconhecido', class: ssl.expires_soon ? 'warning' : 'positive' },
        { label: 'Auto-Assinado', value: ssl.is_self_signed ? '❌ Sim' : '✅ Não', class: ssl.is_self_signed ? 'negative' : 'positive' },
        { label: 'Expirado', value: ssl.is_expired ? '❌ Sim' : '✅ Não', class: ssl.is_expired ? 'negative' : 'positive' },
        { label: 'Domínio Coincide', value: ssl.domain_matches ? '✅ Sim' : '❌ Não', class: ssl.domain_matches ? 'positive' : 'negative' },
        { label: 'Tipo', value: ssl.uses_free_ssl ? 'ℹ️ Let\'s Encrypt (Gratuito)' : 'Certificado Pago', class: ssl.uses_free_ssl ? '' : 'positive' }
    ];
    
    items.forEach(item => {
        const div = createAdvancedItem(item.label, item.value, item.class);
        container.appendChild(div);
    });
}

/**
 * Exibe similaridade com marcas
 */
function displaySimilarity(similarity) {
    const container = document.getElementById('similarityDetails');
    container.innerHTML = '';
    
    if (!similarity.most_similar_brand) {
        container.innerHTML = '<p class="advanced-value">Nenhuma similaridade significativa detectada</p>';
        return;
    }
    
    const items = [
        { label: 'Marca Mais Similar', value: similarity.most_similar_brand },
        { label: 'Grau de Similaridade', value: `${similarity.similarity_score}%`, class: similarity.is_similar_to_brand ? 'negative' : 'positive' },
        { label: 'Possível Typosquatting', value: similarity.is_similar_to_brand ? '⚠️ Sim' : '✅ Não', class: similarity.is_similar_to_brand ? 'warning' : 'positive' }
    ];
    
    items.forEach(item => {
        const div = createAdvancedItem(item.label, item.value, item.class);
        container.appendChild(div);
    });
    
    // Mostrar top 5 similaridades
    if (similarity.all_similarities) {
        const sorted = Object.entries(similarity.all_similarities)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
        
        const topDiv = document.createElement('div');
        topDiv.style.marginTop = '15px';
        topDiv.innerHTML = '<strong>Top 5 Marcas Similares:</strong>';
        
        sorted.forEach(([brand, score]) => {
            const item = document.createElement('div');
            item.className = 'advanced-item';
            item.innerHTML = `
                <span class="advanced-label">${brand}</span>
                <span class="advanced-value">${score}%</span>
            `;
            topDiv.appendChild(item);
        });
        
        container.appendChild(topDiv);
    }
}

/**
 * Exibe análise de conteúdo
 */
function displayContent(content) {
    const container = document.getElementById('contentDetails');
    container.innerHTML = '';
    
    if (!content.available) {
        container.innerHTML = `<p class="advanced-value negative">❌ ${content.error || 'Conteúdo não disponível'}</p>`;
        return;
    }
    
    const items = [
        { label: 'Título da Página', value: content.title || 'Sem título' },
        { label: 'Possui Formulários', value: content.has_forms ? `✅ Sim (${content.form_count})` : '❌ Não', class: content.has_forms ? 'warning' : 'positive' },
        { label: 'Formulário de Login', value: content.has_login_form ? '⚠️ Sim' : '✅ Não', class: content.has_login_form ? 'warning' : 'positive' },
        { label: 'Campos Sensíveis', value: content.has_sensitive_fields ? `⚠️ Sim (${content.sensitive_field_count})` : '✅ Não', class: content.has_sensitive_fields ? 'warning' : 'positive' },
        { label: 'Solicita Info Financeira', value: content.asks_for_financial_info ? '🚨 Sim' : '✅ Não', class: content.asks_for_financial_info ? 'negative' : 'positive' }
    ];
    
    items.forEach(item => {
        const div = createAdvancedItem(item.label, item.value, item.class);
        container.appendChild(div);
    });
}

/**
 * Exibe informações de redirecionamentos
 */
function displayRedirects(redirects) {
    const container = document.getElementById('redirectDetails');
    container.innerHTML = '';
    
    if (redirects.error) {
        container.innerHTML = `<p class="advanced-value negative">❌ ${redirects.error}</p>`;
        return;
    }
    
    const items = [
        { label: 'Possui Redirecionamentos', value: redirects.has_redirects ? '⚠️ Sim' : '✅ Não', class: redirects.has_redirects ? 'warning' : 'positive' },
        { label: 'Número de Redirecionamentos', value: redirects.redirect_count || 0, class: redirects.has_multiple_redirects ? 'negative' : 'positive' },
        { label: 'Cruza Domínios', value: redirects.crosses_domains ? '⚠️ Sim' : '✅ Não', class: redirects.crosses_domains ? 'warning' : 'positive' },
        { label: 'URL Final', value: redirects.final_url || 'N/A' },
        { label: 'Status HTTP', value: redirects.status_code || 'N/A' }
    ];
    
    items.forEach(item => {
        const div = createAdvancedItem(item.label, item.value, item.class);
        container.appendChild(div);
    });
}

/**
 * Cria um item de análise avançada
 */
function createAdvancedItem(label, value, className = '') {
    const div = document.createElement('div');
    div.className = 'advanced-item';
    
    const labelSpan = document.createElement('span');
    labelSpan.className = 'advanced-label';
    labelSpan.textContent = label;
    
    const valueSpan = document.createElement('span');
    valueSpan.className = `advanced-value ${className}`;
    valueSpan.textContent = value;
    
    div.appendChild(labelSpan);
    div.appendChild(valueSpan);
    
    return div;
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

// ===== HISTÓRICO =====

/**
 * Salva resultado no histórico (LocalStorage)
 */
function saveToHistory(result) {
    try {
        let history = JSON.parse(localStorage.getItem('phishingHistory') || '[]');
        
        const historyItem = {
            url: result.url,
            domain: result.domain,
            score: result.phishing_score,
            isPhishing: result.is_phishing,
            riskLevel: result.risk_level,
            timestamp: new Date().toISOString(),
            result: result
        };
        
        // Adicionar no início
        history.unshift(historyItem);
        
        // Limitar a 50 itens
        if (history.length > 50) {
            history = history.slice(0, 50);
        }
        
        localStorage.setItem('phishingHistory', JSON.stringify(history));
    } catch (error) {
        console.error('Erro ao salvar no histórico:', error);
    }
}

/**
 * Mostra o histórico
 */
function showHistory() {
    const history = JSON.parse(localStorage.getItem('phishingHistory') || '[]');
    
    if (history.length === 0) {
        historyContent.innerHTML = '<p class="empty-message">Nenhuma análise no histórico ainda.</p>';
    } else {
        historyContent.innerHTML = '';
        
        history.forEach((item, index) => {
            const div = document.createElement('div');
            div.className = `history-item ${item.isPhishing ? 'phishing' : ''}`;
            div.onclick = () => loadFromHistory(index);
            
            const scoreClass = item.score < 30 ? 'positive' : item.score < 70 ? 'warning' : 'negative';
            
            div.innerHTML = `
                <div class="history-item-header">
                    <span class="history-url">${item.url}</span>
                    <span class="history-score ${scoreClass}">${item.score}/100</span>
                </div>
                <div class="history-date">
                    ${new Date(item.timestamp).toLocaleString('pt-BR')} - ${item.riskLevel}
                </div>
            `;
            
            historyContent.appendChild(div);
        });
    }
    
    historySection.style.display = 'block';
    resultsSection.style.display = 'none';
}

/**
 * Esconde o histórico
 */
function hideHistory() {
    historySection.style.display = 'none';
}

/**
 * Carrega um item do histórico
 */
function loadFromHistory(index) {
    const history = JSON.parse(localStorage.getItem('phishingHistory') || '[]');
    const item = history[index];
    
    if (item && item.result) {
        lastAnalysisResult = item.result;
        urlInput.value = item.url;
        displayResults(item.result);
        showResults();
        hideHistory();
        exportBtn.style.display = 'inline-block';
    }
}

/**
 * Limpa o histórico
 */
function clearHistory() {
    if (confirm('Tem certeza que deseja limpar todo o histórico?')) {
        localStorage.removeItem('phishingHistory');
        showHistory(); // Atualizar visualização
    }
}

/**
 * Exporta o histórico completo
 */
function exportHistory() {
    const history = JSON.parse(localStorage.getItem('phishingHistory') || '[]');
    
    if (history.length === 0) {
        alert('Histórico vazio!');
        return;
    }
    
    const dataStr = JSON.stringify(history, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = `techacker-historico-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
}

// ===== EXPORTAÇÃO =====

/**
 * Exporta o resultado atual
 */
function exportResult() {
    if (!lastAnalysisResult) {
        alert('Nenhum resultado para exportar!');
        return;
    }
    
    const dataStr = JSON.stringify(lastAnalysisResult, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    
    const filename = `techacker-analise-${lastAnalysisResult.domain}-${new Date().toISOString().split('T')[0]}.json`;
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = filename;
    link.click();
}

// ===== MODAL =====

/**
 * Abre modal com explicação
 */
function openModal(title, content) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = content;
    explanationModal.style.display = 'flex';
}

/**
 * Fecha modal
 */
function closeModal() {
    explanationModal.style.display = 'none';
}

// ===== UTILITÁRIOS =====

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
