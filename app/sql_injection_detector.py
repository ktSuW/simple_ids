import re

class SQLInjectionDetector:
    def __init__(self):
        # Define SQL injection patterns categorized by detailed type of attack
        self.patterns = {
            'Data Extraction Channel': {
                'Inband': {
                    'Error-Based SQLi': [
                        r"SELECT\s+\*\s+FROM", r"XP_CMDSHELL", r"UTL_INADDR\.GET_HOST_ADDRESS",
                        r"convert\(int,\s*\(SELECT\s+\(CASE\s+WHEN\s+\(1=1\)\s+THEN\s+CHAR\(49\)\s+ELSE\s+CHAR\(48\)\s+END\)\)\)"
                    ],
                    'Union-Based SQLi': [
                        r"\bunion\b\s+SELECT", r"\bselect\b"
                    ],
                    'Tautology': [
                        r'1=1', r"'\s*or\s*'1'='1"
                    ]
                },
                'Out of Band': {
                    'DNS-Based SQLi': [
                        r";\s*EXEC\s+xp_cmdshell\('nslookup\s+[a-zA-Z0-9.-]+'\)",
                        r"EXTRACTVALUE\(xmltype\('\s*%remote;]>'\),\s*'/l'\)"
                    ],
                    'HTTP-Based SQLi': [
                        r"LOAD_FILE\('http://[a-zA-Z0-9.-]+/[a-zA-Z0-9_.-]+'\)",
                        r"LOAD\s+DATA\s+INFILE\s+'http://[a-zA-Z0-9.-]+/[a-zA-Z0-9_.-]+'"
                    ]
                }
            },
            'Server Response': {
                'Blind-Based SQLi': {
                    'Boolean-Based Blind Injection': [
                        r"AND\s+1=1", r"AND\s+1=0"
                    ],
                    'Time-Based Blind Injection': [
                        r"SLEEP\(\d+\)", r"WAITFOR\s+DELAY\s+'00:00:\d+'"
                    ]
                }
            },
            'First Order Injection': [
                r'1=1',  # Tautology
                r'\bunion\b\s+SELECT',  # Union Attack
                r';',  # Piggybacking
                r'EXEC',  # Stored Procedure SQLi
                r'%27'  # Alternate Encoding SQLi (single quote encoded)
            ],
            'Second Order Injection': [
                r"username\s*=\s*'admin'\s*--",  # Example where user-controlled input from a previous interaction is used unsafely in a query
                r"User Input Stored and Later Executed"
            ],
            'Other Types': {
                'Illegal/Logically Incorrect Queries': [
                    r'\binsert\b', r'\bdelete\b', r'\bupdate\b', r'\bdrop\b',
                    r'\bfrom\b', r'\bwhere\b', r'\bload_file\b', r'\boutfile\b'
                ],
                'Data Type Manipulation': [
                    r'\bchar\b', r'\bvarchar\b', r'\bnchar\b', r'\bnvarchar\b', r'\balt\b'
                ],
                'Version Disclosure': [r'@@version'],
                'Other Common Patterns': [
                    r"\x27|\x22", r"\x3D", r"\x2F\x2A", r"\x3B", r"\x27\x2B\x2F\x2A",
                    r'\bsysobjects\b', r'\bsyscolumns\b'
                ]
            }
        }

    def detect(self, query):
        detected_types = []

        for category, subcategories in self.patterns.items():
            if isinstance(subcategories, dict):
                for subcategory, attack_types in subcategories.items():
                    if isinstance(attack_types, dict):
                        for attack_type, patterns in attack_types.items():
                            if self._check_patterns(patterns,query):
                                detected_types.append(f"{category} => {subcategory} =>{attack_type}")
                    else:
                        if self._check_patterns(subcategories, query):
                            detected_types.append(category)
                    
        return detected_types
    
    def _check_patterns(self, patterns, query):
        # Generator expression
        return any (re.search(pattern, query, re.IGNORECASE) for pattern in patterns)