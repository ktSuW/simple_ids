from sql_injection_detector import SQLInjectionDetector

detector = SQLInjectionDetector()

def detect_injection(query):
    detected_types = detector.detect(query)
    result = {
        'query': query,
        'detected_types': detected_types,
        'is_safe': len(detected_types) == 0
    }
    
    print("Query:", result['query'])
    print("Detected Types:", result['detected_types'])
    print("Is Safe:", result['is_safe'])
    print()  # Add a blank line for readability for each query 

if __name__ == '__main__':
    # Test queries
    queries = [
        "SELECT * FROM users WHERE username = 'admin' OR 1=1",  # Tautology (both Inband and First Order)
        "SELECT * FROM users UNION SELECT * FROM admins",  # Union-based
        "SELECT * FROM users; DROP TABLE users;",  # Piggybacking
        "SELECT * FROM users WHERE id = 1 OR 1=1--",  # Comment injection with tautology
        "SELECT * FROM users WHERE username = '' OR '1'='1'",  # Another tautology variant
        "SELECT * FROM users WHERE id = 1; EXEC xp_cmdshell('net user')",  # Stored procedure
        "SELECT * FROM users WHERE username = 'admin%27 --'",  # Alternate encoding
        "SELECT * FROM users WHERE id = 1 AND 1=1",  # Boolean-based blind
        "SELECT * FROM users WHERE id = 1; WAITFOR DELAY '00:00:05'",  # Time-based blind
    ]

    # Test each query
    for query in queries:
        detect_injection(query)