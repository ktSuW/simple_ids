import re

class SQLInjectionDetector:
    def __init__(self):
        self.patterns = {
            'In-Band' : {
                'Tautology' : [r'1=1', r"'s*ors*'1'='1"],
                'Union Attack' : [r'\bunion\b', r'\bselect\b']
            },
            'Blind (Inferential)' : {
                'Boolean-Based' : [

                ],
                'Time-Based' : [

                ]
            },
            'Out of Band': {
                'DNS-Based' : [

                ],
                'HTTP-Based': [

                ]
            },
            'Other Types' : {
                'Piggybacking' : [],
                'Malicious Payload' : [],
                'Comment Injection' : [],
                'Metadata Tempering' : [],
                'Illegal/Logically Incorrect Queries' : [],
                'Data Exposure' : [],
                'Common Injection' : [],
                'Data Type Manipulation' : [],
                'Time Delay' : [],
                'Version Disclousre' : [],
                'Other Common Patterns' : [],

            }
        }