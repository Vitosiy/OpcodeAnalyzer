class Vulnerability:
    def __init__(self, D, P):
        self.dangerous_functions = D
        self.protective_functions = P
        
RXSS = Vulnerability(['ECHO', 'printf', ], ['htmlspecialchars', 'intval', ])
SQLI = Vulnerability(['mysql_query', 'query', ], ['mysql_escape_string', 'mysql_real_escape_string', 'intval', ])
