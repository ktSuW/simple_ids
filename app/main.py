from flask import Flask, request, jsonify
from flask_swagger_ui import get_swaggerui_blueprint
from sql_injection_detector import SQLInjectionDetector

app = Flask(__name__, static_url_path='/static')
detector = SQLInjectionDetector()

# Swagger configuration
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "SQL Injection Detector API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

@app.route('/detect', methods=['POST'])
def detect_injection():
    data = request.get_json()
    if not data or 'query' not in data:
        return jsonify({"error": "No query provided"}), 400
    
    query = data['query']
    detected_types = detector.detect(query)
    result = {
        'query': query,
        'detected_types': detected_types,
        'is_safe': len(detected_types) == 0
    }
    
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
