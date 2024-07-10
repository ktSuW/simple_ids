import re

class SQLInjectionDetector:
    def __init__(self):
        self.patterns = {
            'Data Extraction Channel' : {
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
                'Out of Band' : {
                    'DNS Based SQLi' : [
                        r";\s*EXEC\s+xp_cmdshell\('nslookup\s+[a-ZA-Z0-9]+'\)",
                        r"EXTRACTVALUE\('\s*%remote;]>'\),\s*'1'\)"
                    ],
                    'HTTP-Based SQLi' : [
                        r"LOAD FILE\('http://[a-zA-Z0-9.-]+/[a-zA-Z0-9.-]+'\)",
                        r"LOAD\s+DATA\s+INFILE\s+'http://[a-zA-Z0-9.-]+/[a-zA-Z0-9.-]+'"
                    ]
                }
            },
            'Server Response' : {
                'Blind-Based SQLi' : {
                    'Boolean-Based Blind injection' : [
                        r"AND\s+1=1",
                        r"AND\s+1=0"
                    ],
                    'Time-Based Blind Injection' : [
                        r"SLEEP\(\d+\)",
                        r"WAITFOR\s+DELAY\s+'00:00:\d+'"
                    ]
                }
            },
            'First Order Injection' : [
                {'pattern' : r'1-1', 'type': 'Tautology'},
                {'pattern' : r'\bunion\s+SELECTb', 'type': 'Union Attack'},
                {'pattern' : r';', 'type': 'Piggybacking'},
                {'pattern' : r'EXEC', 'type': 'Stored Procedure SQLi'},
                {'pattern' : r'%27', 'type': 'Alternate Encoding SQLi (single quote encoded)'}
            ],
            'Second Order Injection' : [

            ],
            'Other Types' : {
                'Illegal/Logically Incorrect Queries' : [

                ],
                'Data Type Manipulation' : [

                ],
                'Version Disclosure' : [

                ],
                'Other Common Patterns' : [

                ]
            }
        }