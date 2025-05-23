import ast
import re
import os
from typing import List, Dict, Tuple

class SecurityReviewer:
    def __init__(self):
        self.vulnerabilities = []
        self.checks = [
            ("SQL Injection", self.check_sql_injection),
            ("Hardcoded Credentials", self.check_hardcoded_credentials),
            ("XSS Vulnerability", self.check_xss),
            ("Unsafe Deserialization", self.check_deserialization),
            ("Command Injection", self.check_command_injection),
            ("Insecure TLS/SSL", self.check_insecure_ssl),
            ("Directory Traversal", self.check_directory_traversal),
            ("Log Injection", self.check_log_injection),
        ]

    def review_file(self, file_path: str) -> List[Dict]:
        """Review a Python file for security vulnerabilities"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                tree = ast.parse(content)
                
                for check_name, check_func in self.checks:
                    issues = check_func(tree, content)
                    for issue in issues:
                        self.vulnerabilities.append({
                            "file": os.path.basename(file_path),
                            "type": check_name,
                            "line": issue[0],
                            "code": issue[1],
                            "severity": issue[2] if len(issue) > 2 else "Medium"
                        })
                
                return self.vulnerabilities
        except Exception as e:
            print(f"Error reviewing file {file_path}: {str(e)}")
            return []

    def check_sql_injection(self, tree: ast.AST, content: str) -> List[Tuple]:
        """Check for SQL injection vulnerabilities"""
        issues = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Str)):
                    if node.func.attr in ('format', 'replace'):
                        sql_keywords = ['select', 'insert', 'update', 'delete', 'where']
                        s = node.func.value.s.lower()
                        if any(kw in s for kw in sql_keywords):
                            line_no = node.lineno
                            line = content.split('\n')[line_no - 1].strip()
                            issues.append((line_no, line, "High"))
        
        return issues

    def check_hardcoded_credentials(self, tree: ast.AST, content: str) -> List[Tuple]:
        """Check for hardcoded passwords or API keys"""
        issues = []
        cred_patterns = [
            r'password\s*=\s*[\'"].+?[\'"]',
            r'api_key\s*=\s*[\'"].+?[\'"]',
            r'secret\s*=\s*[\'"].+?[\'"]',
            r'token\s*=\s*[\'"].+?[\'"]'
        ]
        
        for i, line in enumerate(content.split('\n')):
            for pattern in cred_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append((i + 1, line.strip(), "Critical"))
        
        return issues

    def check_xss(self, tree: ast.AST, content: str) -> List[Tuple]:
        """Check for potential XSS vulnerabilities"""
        issues = []
        xss_patterns = [
            r'\.html\(',
            r'\.append\(',
            r'\.innerHTML\s*=',
            r'document\.write\('
        ]
        
        for i, line in enumerate(content.split('\n')):
            for pattern in xss_patterns:
                if re.search(pattern, line):
                    if not any(safe in line for safe in ['escape', 'encode', 'sanitize']):
                        issues.append((i + 1, line.strip(), "High"))
        
        return issues

    def check_deserialization(self, tree: ast.AST, content: str) -> List[Tuple]:
        """Check for unsafe deserialization"""
        issues = []
        unsafe_modules = ['pickle', 'yaml', 'marshal']
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in unsafe_modules:
                        line_no = node.lineno
                        line = content.split('\n')[line_no - 1].strip()
                        issues.append((line_no, line, "High"))
        
        return issues

    def check_command_injection(self, tree: ast.AST, content: str) -> List[Tuple]:
        """Check for command injection vulnerabilities"""
        issues = []
        unsafe_functions = ['os.system', 'subprocess.call', 'subprocess.Popen']
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)):
                    func_name = f"{node.func.value.id}.{node.func.attr}"
                    if func_name in unsafe_functions:
                        line_no = node.lineno
                        line = content.split('\n')[line_no - 1].strip()
                        
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and not arg.id.isupper():
                                issues.append((line_no, line, "Critical"))
                                break
        
        return issues

    def check_insecure_ssl(self, tree: ast.AST, content: str) -> List[Tuple]:
        """Check for insecure SSL/TLS configurations"""
        issues = []
        insecure_patterns = [
            r'verify\s*=\s*False',
            r'SSLv3',
            r'PROTOCOL_SSLv23'
        ]
        
        for i, line in enumerate(content.split('\n')):
            for pattern in insecure_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append((i + 1, line.strip(), "High"))
        
        return issues

    def check_directory_traversal(self, tree: ast.AST, content: str) -> List[Tuple]:
        """Check for directory traversal vulnerabilities"""
        issues = []
        traversal_patterns = [
            r'open\s*\([\'"]\.\./',
            r'open\s*\([\'"]\.\.\\',
            r'os\.path\.join\s*\(.*\.\.'
        ]
        
        for i, line in enumerate(content.split('\n')):
            for pattern in traversal_patterns:
                if re.search(pattern, line):
                    issues.append((i + 1, line.strip(), "High"))
        
        return issues

    def check_log_injection(self, tree: ast.AST, content: str) -> List[Tuple]:
        """Check for log injection vulnerabilities"""
        issues = []
        log_functions = ['logging.info', 'logging.warning', 'logging.error']
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)):
                    if node.func.value.id == 'logging' and node.func.attr in ['info', 'warning', 'error']:
                        line_no = node.lineno
                        line = content.split('\n')[line_no - 1].strip()
                        issues.append((line_no, line, "Medium"))
        
        return issues

def print_report(vulnerabilities: List[Dict]):
    """Print a formatted report of found vulnerabilities"""
    if not vulnerabilities:
        print("\nNo security vulnerabilities found!")
        return
    
    print("\nSECURITY CODE REVIEW REPORT")
    print("=" * 80)
    print(f"{'File':<20} {'Line':<5} {'Severity':<10} {'Type':<25} {'Code Snippet':<30}")
    print("-" * 80)
    
    for vuln in vulnerabilities:
        code_snippet = vuln['code'][:50] + '...' if len(vuln['code']) > 50 else vuln['code']
        print(f"{vuln['file']:<20} {vuln['line']:<5} {vuln['severity']:<10} "
              f"{vuln['type']:<25} {code_snippet:<30}")

if __name__ == "__main__":
    print("=== Python Secure Code Reviewer ===")
    print("Checks for: SQLi, XSS, Hardcoded Secrets, etc.\n")
    
    while True:
        file_path = input("Enter path to Python file to review (or 'quit' to exit): ").strip()
        
        if file_path.lower() in ('quit', 'exit'):
            break
            
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found. Please try again.")
            continue
            
        if not file_path.endswith('.py'):
            print("Warning: This tool works best with .py files. Continue? (y/n)")
            if input().lower() != 'y':
                continue
                
        reviewer = SecurityReviewer()
        vulnerabilities = reviewer.review_file(file_path)
        print_report(vulnerabilities)
        
        print("\nReview completed. You can analyze another file or type 'quit' to exit.")
