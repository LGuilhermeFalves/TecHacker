from flask import Flask, request, jsonify
from flask_cors import CORS
from url_analyzer import URLAnalyzer
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Inicializar o analisador
analyzer = URLAnalyzer()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Endpoint para verificar se a API está funcionando"""
    return jsonify({'status': 'ok', 'message': 'API is running'}), 200

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """
    Endpoint principal para análise de URLs
    Espera um JSON com o campo 'url'
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'URL não fornecida',
                'message': 'Por favor, forneça uma URL no campo "url"'
            }), 400
        
        url = data['url']
        logger.info(f"Analisando URL: {url}")
        
        # Realizar análise
        result = analyzer.analyze(url)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Erro ao analisar URL: {str(e)}")
        return jsonify({
            'error': 'Erro ao processar a requisição',
            'message': str(e)
        }), 500

@app.route('/api/batch-analyze', methods=['POST'])
def batch_analyze():
    """
    Endpoint para análise de múltiplas URLs de uma vez
    Espera um JSON com o campo 'urls' (array)
    """
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({
                'error': 'URLs não fornecidas',
                'message': 'Por favor, forneça um array de URLs no campo "urls"'
            }), 400
        
        urls = data['urls']
        
        if not isinstance(urls, list):
            return jsonify({
                'error': 'Formato inválido',
                'message': 'O campo "urls" deve ser um array'
            }), 400
        
        results = []
        for url in urls:
            try:
                result = analyzer.analyze(url)
                results.append(result)
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e),
                    'is_phishing': None
                })
        
        return jsonify({'results': results}), 200
        
    except Exception as e:
        logger.error(f"Erro ao analisar URLs em lote: {str(e)}")
        return jsonify({
            'error': 'Erro ao processar a requisição',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    logger.info("Iniciando servidor Flask na porta 5000...")
    app.run(debug=True, host='0.0.0.0', port=5000)
