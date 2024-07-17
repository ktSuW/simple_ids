import requests

def check_server_health():
    try:
        response = requests.get('http://localhost:5000/health')
        return response.status_code == 200
    except requests.ConnectionError:
        return False



queries = [
    "SELECT * FROM users WHERE username = 'admin' OR 1=1",
    "SELECT * FROM users UNION SELECT * FROM admins",
    "SELECT * FROM users; DROP TABLE users;",
    "SELECT * FROM users WHERE id = 1 OR 1=1--",
    "SELECT * FROM users WHERE username = '' OR '1'='1'",
    "SELECT * FROM users WHERE id = 1; EXEC xp_cmdshell('net user')",
    "SELECT * FROM users WHERE username = 'admin%27 --'",
    "SELECT * FROM users WHERE id = 1 AND 1=1",
    "SELECT * FROM users WHERE id = 1; WAITFOR DELAY '00:00:05'"
]

if check_server_health():
    print("Server is running. Starting tests...")
    for query in queries:
        response = requests.post('http://localhost:5000/detect', json={'query': query})
    print(f"Query: {query}")
    try:
        print(f"Response: {response.json()}\n")
    except requests.exceptions.JSONDecodeError:
        print(f"Failed to decode JSON: {response.text}\n")
else:
    print("Server is not running. Please start the server and try again.")