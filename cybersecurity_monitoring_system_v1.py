
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rozszerzony System Monitorowania Cyberbezpieczeństwa
Autor: Marek Z, AI Assistant
Data: 2025-09-16

Program pobiera informacje o cyberbezpieczeństwie z RSS feeds i API,
klasyfikuje je na incydenty, zagrożenia i luki, a następnie generuje
profesjonalne raporty w formatach HTML, JSON i CSV.

Wymagania:
- requests
- beautifulsoup4
- feedparser (opcjonalne, program działa bez tego)

Instalacja:
pip install requests beautifulsoup4 feedparser

Użycie:
python cybersecurity_monitor.py
"""

import requests
from bs4 import BeautifulSoup
import json
from datetime import datetime, timedelta
import time
import re
from urllib.parse import urljoin, urlparse
import csv
import xml.etree.ElementTree as ET
import random
import logging
import os

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Klucze API (opcjonalne)
API_KEYS = {
    'virustotal': '8799778183788c0622a0782a4a3547c8ac731249f82db2b781ca941463a5747c',  # API
    'shodan': 'f5VVSrXsZefbrELI3eAxCTd5E4wd2Quk',      # API
    'alienvault': 'b3301fa1068227e3fb333c159dd16ab38c2263858a9e693a1972cb8bc95eebd7',  # API
}

class AdvancedCyberSecurityMonitor:
    def __init__(self):
        # RSS Feeds - kompletna lista źródeł
        self.rss_sources = {
            'web_insecurity_blog_rss': 'https://security.lauritz-holtmann.de/index.xml',
            'access_vector_rss': 'https://accessvector.net/rss.xml',
            'aleph_research_posts_rss': 'http://little-canada.org/feeds/output/aleph-posts.rss',
            'aleph_research_vulns_rss': 'http://little-canada.org/feeds/output/aleph-vulns.rss',
            'alexander_popov_rss': 'https://a13xp0p0v.github.io/feed.xml',
            'android_offensive_security_rss': 'https://androidoffsec.withgoogle.com/index.xml',
            'apple_security_research_rss': 'https://little-canada.org/feeds/output/applesecurityresearch.rss',
            'assetnote_rss': 'https://blog.assetnote.io/feed.xml',
            'atredis_partners_rss': 'https://www.atredis.com/blog?format=rss',
            'shielder_rss': 'https://www.shielder.it/blog/index.xml',
            'brendon_tiszka_rss': 'https://little-canada.org/feeds/output/tiszka.rss',
            'checkpoint_research_rss': 'https://research.checkpoint.com/feed/',
            'cisco_talos_rss': 'http://feeds.feedburner.com/feedburner/Talos',
            'connor_mcgarr_rss': 'https://connormcgarr.github.io/feed.xml',
            'darknavy_rss': 'https://www.darknavy.org/index.xml',
            'dfsec_research_rss': 'https://blog.dfsec.com/feed.xml',
            'doar_e_rss': 'https://doar-e.github.io/feeds/rss.xml?_=',
            'doyensec_rss': 'https://blog.doyensec.com/atom.xml',
            'elttam_rss': 'https://little-canada.org/feeds/output/elttam.rss',
            'embrace_the_red_rss': 'https://embracethered.com/blog/index.xml',
            'exploits_forsale_rss': 'https://little-canada.org/feeds/output/exploitsforsale.rss',
            'grimm_blog_rss': 'https://blog.grimm-co.com/feeds/posts/default',
            'gamozo_labs_rss': 'https://gamozolabs.github.io/feed.xml',
            'github_security_lab_rss': 'https://github.blog/tag/github-security-lab/feed/',
            'google_security_research_advisories_rss': 'https://little-canada.org/feeds/output/google-research-advisories.rss',
            'guido_vranken_rss': 'https://guidovranken.com/feed/',
            'hacktus_rss': 'https://hacktus.tech/rss.xml',
            'impalabs_rss': 'https://blog.impalabs.com/feed.xml',
            'intrigus_rss': 'https://intrigus.org/feed.xml',
            'isosceles_rss': 'https://blog.isosceles.com/rss/',
            'johan_carlsson_rss': 'https://joaxcar.com/blog/feed/',
            'joseph_ravichandran_rss': 'https://little-canada.org/feeds/output/jprx.rss?_123',
            'keen_security_lab_rss': 'https://little-canada.org/feeds/output/tencent-keenlabs.rss',
            'low_level_adventures_rss': 'https://0x434b.dev/rss/',
            'mdsec_rss': 'https://www.mdsec.co.uk/feed/',
            'matteo_malvica_rss': 'https://www.matteomalvica.com/blog/index.xml',
            'meta_redteam_advisories_rss': 'https://little-canada.org/feeds/output/meta-redteam-advisories.rss',
            'meta_redteamx_rss': 'https://rtx.meta.security/feed.xml',
            'microsoft_bvr_rss': 'https://microsoftedge.github.io/edgevr/feed.xml',
            'mozilla_attack_defense_rss': 'https://blog.mozilla.org/attack-and-defense/feed/',
            'ods_security_research_rss': 'https://oddsolutions.github.io/feed.xml',
            'oversecured_rss': 'https://blog.oversecured.com/feed.xml',
            'itm4n_rss': 'https://itm4n.github.io/feed.xml',
            'pt_swarm_rss': 'https://swarm.ptsecurity.com/feed/',
            'portswigger_rss': 'https://portswigger.net/research/rss',
            'positive_technologies_rss': 'http://feeds.feedburner.com/positiveTechnologiesResearchLab',
            'slonser_notes_rss': 'https://blog.slonser.info/posts/index.xml',
            'project_zero_rss': 'http://googleprojectzero.blogspot.com/feeds/posts/default',
            'project_zero_rca_rss': 'https://little-canada.org/feeds/output/projectzero-rca.rss?_123',
            'kaist_hacking_lab_rss': 'https://kaist-hacking.github.io/publication/index.xml',
            'ret2_systems_rss': 'https://blog.ret2.io/feed.xml',
            'realmode_labs_rss': 'https://medium.com/feed/realmodelabs',
            'codean_labs_rss': 'https://codeanlabs.com/blog/category/research/feed/',
            'rhino_security_labs_rss': 'https://rhinosecuritylabs.com/feed/',
            'sam_curry_rss': 'https://samcurry.net/api/feed.rss',
            'sean_heelan_rss': 'https://sean.heelan.io/feed/?_',
            'secfault_security_rss': 'https://secfault-security.com/feed.rss',
            'renwa_rss': 'https://medium.com/@renwa/feed',
            'stratum_security_rss': 'https://blog.stratumsecurity.com/rss/',
            'synacktiv_rss': 'https://little-canada.org/feeds/output/synacktiv-publications.rss?_=123',
            'talos_reports_rss': 'http://little-canada.org/feeds/output/talos-reports.rss',
            'taszk_rss': 'https://labs.taszk.io/blog/index.xml',
            'teddy_katz_rss': 'https://blog.teddykatz.com/feed.xml',
            'trenchant_rss': 'http://little-canada.org/feeds/output/trenchant.rss',
            'windows_internals_rss': 'https://windows-internals.com/feed/',
            'youssef_sammouda_rss': 'https://ysamm.com/?feed=rss2',
            'zdi_rss': 'https://www.zerodayinitiative.com/blog?format=rss',
            'ysanatomic_rss': 'https://ysanatomic.github.io/feed.xml',
            'xdavidhu_rss': 'https://bugs.xdavidhu.me/feed.xml',
            'jub0bs_rss': 'https://jub0bs.com/posts/index.xml',
            'kylebot_rss': 'https://blog.kylebot.net/atom.xml',
            'pi3_blog_rss': 'http://blog.pi3.com.pl/?feed=rss2',
            'securitum_rss': 'https://research.securitum.com/feed/',
            'secret_club_rss': 'https://secret.club/feed.xml',
            'spaceraccoon_rss': 'https://spaceraccoon.dev/feed/',
            'watchtowr_labs_rss': 'https://labs.watchtowr.com/rss/'
        }

        # API Sources
        self.api_sources = {
            'nvd_cve': {
                'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
                'params': {
                    'resultsPerPage': 20,
                    'startIndex': 0,
                    'pubStartDate': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000'),
                    'pubEndDate': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000')
                }
            },
            'virustotal_api': {
                'url': 'https://www.virustotal.com/vtapi/v2/file/report',
                'requires_key': True,
                'note': 'Wymaga klucza API z VirusTotal'
            },
            'shodan_api': {
                'url': 'https://api.shodan.io/shodan/host/search',
                'requires_key': True,
                'note': 'Wymaga klucza API z Shodan'
            }
        }

        # Rotacja User-Agents dla obejścia blokad
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]

        self.headers = {
            'User-Agent': random.choice(self.user_agents)
        }

        self.incidents = []
        self.threats = []
        self.vulnerabilities = []
        self.api_keys = API_KEYS

    def set_api_key(self, service, key):
        """Ustawia klucz API dla danego serwisu"""
        self.api_keys[service] = key
        print(f"✅ Ustawiono klucz API dla {service}")

    def parse_simple_rss(self, url, source_name):
        """Prosta implementacja parsera RSS bez feedparser"""
        try:
            print(f"📡 Pobieranie RSS z {source_name}...")
            response = requests.get(url, headers=self.headers, timeout=15)

            if response.status_code != 200:
                print(f"❌ Błąd HTTP {response.status_code} dla {source_name}")
                return []

            # Parsowanie XML
            try:
                root = ET.fromstring(response.content)
            except ET.ParseError as e:
                print(f"❌ Błąd parsowania XML dla {source_name}: {e}")
                return []

            entries = []

            # Znajdź wszystkie elementy <item>
            items = root.findall('.//item')

            for item in items[:10]:  # Maksymalnie 10 elementów
                try:
                    title_elem = item.find('title')
                    link_elem = item.find('link')
                    description_elem = item.find('description')
                    pub_date_elem = item.find('pubDate')

                    title = title_elem.text if title_elem is not None else 'Brak tytułu'
                    link = link_elem.text if link_elem is not None else ''
                    description = description_elem.text if description_elem is not None else ''
                    pub_date = pub_date_elem.text if pub_date_elem is not None else 'Brak daty'

                    # Oczyszczenie opisu z HTML
                    if description:
                        description = BeautifulSoup(description, 'html.parser').get_text()
                        description = description[:300] + '...' if len(description) > 300 else description

                    news_item = {
                        'source': source_name,
                        'title': title,
                        'link': link,
                        'date': pub_date,
                        'summary': description,
                        'category': self.classify_news(title + ' ' + description)
                    }

                    entries.append(news_item)

                except Exception as e:
                    print(f"⚠️ Błąd podczas przetwarzania elementu RSS: {e}")
                    continue

            print(f"✅ Pobrano {len(entries)} wpisów z {source_name}")
            return entries

        except Exception as e:
            print(f"❌ Błąd podczas pobierania RSS z {source_name}: {e}")
            return []

    def parse_with_feedparser(self, url, source_name):
        """Parsowanie RSS z użyciem feedparser (jeśli dostępny)"""
        try:
            import feedparser
            print(f"📡 Pobieranie RSS z {source_name} (feedparser)...")

            feed = feedparser.parse(url)

            if feed.bozo:
                print(f"⚠️ Ostrzeżenie: Problemy z parsowaniem RSS dla {source_name}")

            entries = []
            for entry in feed.entries[:10]:  # Ostatnie 10 wpisów
                try:
                    # Parsowanie daty
                    published = entry.get('published', entry.get('updated', 'Brak daty'))
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        published = datetime(*entry.published_parsed[:6]).strftime('%Y-%m-%d %H:%M')

                    # Pobranie opisu
                    summary = entry.get('summary', entry.get('description', ''))
                    if summary:
                        # Usunięcie tagów HTML
                        summary = BeautifulSoup(summary, 'html.parser').get_text()
                        summary = summary[:300] + '...' if len(summary) > 300 else summary

                    news_item = {
                        'source': source_name,
                        'title': entry.get('title', 'Brak tytułu'),
                        'link': entry.get('link', ''),
                        'date': published,
                        'summary': summary,
                        'category': self.classify_news(entry.get('title', '') + ' ' + summary)
                    }

                    entries.append(news_item)

                except Exception as e:
                    print(f"⚠️ Błąd podczas przetwarzania wpisu RSS: {e}")
                    continue

            print(f"✅ Pobrano {len(entries)} wpisów z {source_name}")
            return entries

        except ImportError:
            print(f"⚠️ feedparser niedostępny, używam prostego parsera XML")
            return self.parse_simple_rss(url, source_name)
        except Exception as e:
            print(f"❌ Błąd podczas pobierania RSS z {source_name}: {e}")
            return []

    def fetch_nvd_cve_data(self):
        """Pobiera dane CVE z National Vulnerability Database"""
        try:
            print("🔌 Pobieranie danych CVE z NVD...")
            response = requests.get(
                self.api_sources['nvd_cve']['url'],
                params=self.api_sources['nvd_cve']['params'],
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []

                for cve in data.get('vulnerabilities', []):
                    cve_data = cve.get('cve', {})

                    # Podstawowe informacje
                    cve_id = cve_data.get('id', 'N/A')
                    published = cve_data.get('published', 'N/A')

                    # Opis
                    descriptions = cve_data.get('descriptions', [])
                    description = ''
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break

                    # Metryki CVSS
                    metrics = cve_data.get('metrics', {})
                    cvss_score = 'N/A'
                    severity = 'N/A'

                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 'N/A')
                        severity = cvss_data.get('baseSeverity', 'N/A')
                    elif 'cvssMetricV30' in metrics:
                        cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 'N/A')
                        severity = cvss_data.get('baseSeverity', 'N/A')

                    vulnerability = {
                        'source': 'NVD (NIST)',
                        'title': f"{cve_id} - {severity} ({cvss_score})",
                        'link': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        'date': published[:10] if published != 'N/A' else 'N/A',
                        'summary': description[:300] + '...' if len(description) > 300 else description,
                        'category': 'vulnerability',
                        'cvss_score': cvss_score,
                        'severity': severity,
                        'cve_id': cve_id
                    }

                    vulnerabilities.append(vulnerability)

                print(f"✅ Pobrano {len(vulnerabilities)} luk z NVD")
                return vulnerabilities

        except Exception as e:
            print(f"❌ Błąd podczas pobierania danych CVE: {e}")
            return []

    def classify_news(self, text):
        """Klasyfikuje newsy na podstawie słów kluczowych"""
        if not text:
            return 'general'

        text_lower = text.lower()

        vulnerability_keywords = [
            'cve', 'luka', 'vulnerability', 'exploit', 'patch', 'update', 'zero-day', 'bug',
            'security flaw', 'backdoor', 'buffer overflow', 'injection', 'xss', 'csrf',
            'rce', 'remote code execution', 'privilege escalation', 'authentication bypass'
        ]

        threat_keywords = [
            'malware', 'ransomware', 'phishing', 'trojan', 'virus', 'botnet', 'apt',
            'campaign', 'spyware', 'adware', 'rootkit', 'keylogger', 'worm', 'stealer',
            'cryptojacking', 'ddos', 'social engineering'
        ]

        incident_keywords = [
            'atak', 'attack', 'breach', 'hack', 'incident', 'naruszenie', 'wyciek', 'leak',
            'data breach', 'cyber attack', 'compromise', 'intrusion', 'unauthorized access',
            'security incident', 'cyber incident'
        ]

        if any(keyword in text_lower for keyword in vulnerability_keywords):
            return 'vulnerability'
        elif any(keyword in text_lower for keyword in threat_keywords):
            return 'threat'
        elif any(keyword in text_lower for keyword in incident_keywords):
            return 'incident'
        else:
            return 'general'

    def add_to_category(self, news_item, category):
        """Dodaje news do odpowiedniej kategorii"""
        if category == 'vulnerability':
            self.vulnerabilities.append(news_item)
        elif category == 'threat':
            self.threats.append(news_item)
        elif category == 'incident':
            self.incidents.append(news_item)

    def collect_rss_news(self):
        """Zbiera newsy ze wszystkich źródeł RSS"""
        all_entries = []

        # Testuj wszystkie źródła RSS
        for source_key, rss_url in self.rss_sources.items():
            entries = self.parse_with_feedparser(rss_url, source_key.replace('_rss', '').replace('_', ' ').title())
            all_entries.extend(entries)
            time.sleep(2)  # Opóźnienie między requestami

        # Klasyfikacja i dodanie do kategorii
        for entry in all_entries:
            self.add_to_category(entry, entry['category'])

        return all_entries

    def fetch_api_data(self):
        """Pobiera dane ze wszystkich dostępnych API"""
        all_api_data = []
        
        # 1. VirusTotal API
        if self.api_keys.get('virustotal'):
            vt_data = self.fetch_virustotal_data()
            all_api_data.extend(vt_data)
        
        # 2. Shodan API
        if self.api_keys.get('shodan'):
            shodan_data = self.fetch_shodan_data()
            all_api_data.extend(shodan_data)
        
        # 3. AlienVault (OTX) API
        if self.api_keys.get('alienvault'):
            otx_data = self.fetch_alienvault_data()
            all_api_data.extend(otx_data)
        
        # 4. NVD API (bez klucza)
        nvd_data = self.fetch_nvd_cve_data()
        all_api_data.extend(nvd_data)
        
        return all_api_data

    def fetch_virustotal_data(self):
        """Pobiera dane z VirusTotal API"""
        try:
            logger.info("🔌 Pobieranie danych z VirusTotal...")
            
            headers = {
                'x-apikey': self.api_keys['virustotal'],
                'User-Agent': random.choice(self.user_agents)
            }
            
            # Pobierz najnowsze malware samples
            url = 'https://www.virustotal.com/api/v3/intelligence/search'
            params = {
                'query': 'type:file positives:5+ fs:2024-09-01+',
                'limit': 20
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                threats = []
                
                for item in data.get('data', []):
                    attributes = item.get('attributes', {})
                    stats = attributes.get('last_analysis_stats', {})
                    
                    threat = {
                        'source': 'VirusTotal',
                        'title': f"Malware wykryty przez {stats.get('malicious', 0)} silników",
                        'link': f"https://www.virustotal.com/gui/file/{item.get('id', '')}",
                        'date': datetime.now().strftime('%Y-%m-%d'),
                        'summary': f"SHA256: {item.get('id', '')[:16]}... | Wykrycia: {stats.get('malicious', 0)}/{sum(stats.values())}",
                        'category': 'threat',
                        'detection_ratio': f"{stats.get('malicious', 0)}/{sum(stats.values())}"
                    }
                    threats.append(threat)
                
                logger.info(f"✅ Pobrano {len(threats)} zagrożeń z VirusTotal")
                return threats
            else:
                logger.error(f"❌ VirusTotal API - HTTP {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"❌ Błąd VirusTotal API: {e}")
            return []

    def fetch_shodan_data(self):
        """Pobiera dane z Shodan API"""
        try:
            logger.info("🔌 Pobieranie danych z Shodan...")
            
            # Wyszukaj podatne systemy
            url = 'https://api.shodan.io/shodan/host/search'
            params = {
                'key': self.api_keys['shodan'],
                'query': 'vuln:CVE-2024 country:PL',
                'limit': 20
            }
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                
                for match in data.get('matches', []):
                    vulns = match.get('vulns', [])
                    
                    for vuln_id in vulns:
                        vulnerability = {
                            'source': 'Shodan',
                            'title': f"Podatny system: {match.get('ip_str', 'N/A')} - {vuln_id}",
                            'link': f"https://www.shodan.io/host/{match.get('ip_str', '')}",
                            'date': datetime.now().strftime('%Y-%m-%d'),
                            'summary': f"IP: {match.get('ip_str', 'N/A')} | Port: {match.get('port', 'N/A')} | Organizacja: {match.get('org', 'N/A')} | Kraj: {match.get('location', {}).get('country_name', 'N/A')}",
                            'category': 'vulnerability',
                            'cve_id': vuln_id,
                            'ip_address': match.get('ip_str', 'N/A'),
                            'port': match.get('port', 'N/A')
                        }
                        vulnerabilities.append(vulnerability)
                
                logger.info(f"✅ Pobrano {len(vulnerabilities)} luk z Shodan")
                return vulnerabilities
            else:
                logger.error(f"❌ Shodan API - HTTP {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"❌ Błąd Shodan API: {e}")
            return []

    def fetch_alienvault_data(self):
        """Pobiera dane z AlienVault OTX API"""
        try:
            logger.info("🔌 Pobieranie danych z AlienVault OTX...")
            
            headers = {
                'X-OTX-API-KEY': self.api_keys['alienvault'],
                'User-Agent': random.choice(self.user_agents)
            }
            
            # Pobierz najnowsze pulsy (threat intelligence)
            url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
            params = {
                'limit': 20,
                'modified_since': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                threats = []
                
                for pulse in data.get('results', []):
                    threat = {
                        'source': 'AlienVault OTX',
                        'title': pulse.get('name', 'Brak nazwy'),
                        'link': f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                        'date': pulse.get('created', datetime.now().strftime('%Y-%m-%d'))[:10],
                        'summary': pulse.get('description', 'Brak opisu')[:400] + ('...' if len(pulse.get('description', '')) > 400 else ''),
                        'category': 'threat',
                        'tags': ', '.join(pulse.get('tags', [])),
                        'indicators_count': len(pulse.get('indicators', []))
                    }
                    threats.append(threat)
                
                logger.info(f"✅ Pobrano {len(threats)} zagrożeń z AlienVault OTX")
                return threats
            else:
                logger.error(f"❌ AlienVault OTX API - HTTP {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"❌ Błąd AlienVault OTX API: {e}")
            return []

    def collect_api_data(self):
        """Zbiera dane ze wszystkich API"""
        logger.info("🔌 Pobieranie danych z API...")
        
        # Sprawdź dostępne klucze API
        available_apis = []
        if self.api_keys.get('virustotal'):
            available_apis.append('VirusTotal')
        if self.api_keys.get('shodan'):
            available_apis.append('Shodan')
        if self.api_keys.get('alienvault'):
            available_apis.append('AlienVault OTX')
        available_apis.append('NVD (bez klucza)')
        
        logger.info(f"📋 Dostępne API: {', '.join(available_apis)}")
        
        # Pobierz dane ze wszystkich API
        all_api_data = self.fetch_api_data()
        
        # Klasyfikuj i dodaj do odpowiednich kategorii
        for item in all_api_data:
            self.add_to_category(item, item['category'])
        
        logger.info(f"✅ Pobrano łącznie {len(all_api_data)} elementów z API")
        time.sleep(2)

    def collect_all_data(self):
        """Zbiera wszystkie dane ze wszystkich źródeł"""
        print("🔄 Rozpoczynanie zbierania danych...")

        # RSS Feeds
        print("\n📡 Pobieranie danych RSS...")
        self.collect_rss_news()

        # API Data
        print("\n🔌 Pobieranie danych z API...")
        self.collect_api_data()

        print(f"\n✅ Zebrano łącznie:")
        print(f"   - Incydenty: {len(self.incidents)}")
        print(f"   - Zagrożenia: {len(self.threats)}")
        print(f"   - Luki: {len(self.vulnerabilities)}")

    def generate_enhanced_report(self):
        """Generuje rozszerzony raport z danymi RSS i API"""
        today = datetime.now().strftime("%Y-%m-%d")
        # Tworzenie katalogu z datą
        report_dir = f"reports/{today}"
        os.makedirs(report_dir, exist_ok=True)

        report_filename = f"{report_dir}/index.html"
        json_filename = f"{report_dir}/enhanced_cybersecurity_data_{today}.json"
        csv_filename = f"{report_dir}/enhanced_cybersecurity_summary_{today}.csv"

        # Sortowanie według daty (najnowsze pierwsze)
        def sort_by_date(items):
            return sorted(items, key=lambda x: x.get('date', ''), reverse=True)

        self.incidents = sort_by_date(self.incidents)
        self.threats = sort_by_date(self.threats)
        self.vulnerabilities = sort_by_date(self.vulnerabilities)

        html_content = f"""
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rozszerzony Raport Cyberbezpieczeństwa - {today}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
        .container {{ max-width: 1400px; margin: 0 auto; background-color: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }}
        .content {{ padding: 30px; }}
        .summary {{ background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%); padding: 25px; border-radius: 10px; margin-bottom: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-box {{ text-align: center; padding: 20px; background: white; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; color: #1976d2; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #1976d2; border-bottom: 3px solid #1976d2; padding-bottom: 10px; display: flex; align-items: center; gap: 10px; }}
        .news-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }}
        .news-item {{ background: white; border-radius: 10px; padding: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); border-left: 5px solid #4caf50; transition: transform 0.3s ease; }}
        .news-item:hover {{ transform: translateY(-5px); }}
        .news-item.incident {{ border-left-color: #f44336; }}
        .news-item.threat {{ border-left-color: #ff9800; }}
        .news-item.vulnerability {{ border-left-color: #9c27b0; }}
        .news-title {{ font-weight: bold; color: #333; margin-bottom: 10px; font-size: 1.1em; }}
        .news-meta {{ color: #666; font-size: 0.9em; margin-bottom: 10px; display: flex; justify-content: space-between; }}
        .news-summary {{ color: #555; line-height: 1.5; margin-bottom: 15px; }}
        .news-link {{ color: #1976d2; text-decoration: none; font-weight: bold; }}
        .news-link:hover {{ text-decoration: underline; }}
        .source-tag {{ background: #e0e0e0; padding: 3px 8px; border-radius: 15px; font-size: 0.8em; }}
        .severity-high {{ background: #ffebee; color: #c62828; }}
        .severity-medium {{ background: #fff3e0; color: #ef6c00; }}
        .severity-low {{ background: #e8f5e8; color: #2e7d32; }}
        .cve-info {{ background: #f3e5f5; padding: 10px; border-radius: 5px; margin: 10px 0; }}
        .footer {{ background: #f5f5f5; padding: 20px; text-align: center; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Rozszerzony Raport Cyberbezpieczeństwa</h1>
            <p>Dane z RSS feeds i API | {today}</p>
        </div>

        <div class="content">
            <div class="summary">
                <h3>📊 Podsumowanie Dzienne</h3>
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-number">{len(self.incidents)}</div>
                        <div>Incydenty Bezpieczeństwa</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(self.threats)}</div>
                        <div>Nowe Zagrożenia</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(self.vulnerabilities)}</div>
                        <div>Wykryte Luki</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(self.incidents) + len(self.threats) + len(self.vulnerabilities)}</div>
                        <div>Łącznie Alertów</div>
                    </div>
                </div>
            </div>
"""

        # Sekcja incydentów
        if self.incidents:
            html_content += """
            <div class="section">
                <h2>🚨 Incydenty Bezpieczeństwa</h2>
                <div class="news-grid">
"""
            for item in self.incidents[:20]:  # Maksymalnie 20 najnowszych
                html_content += f"""
                    <div class="news-item incident">
                        <div class="news-title">{item['title']}</div>
                        <div class="news-meta">
                            <span class="source-tag">{item['source']}</span>
                            <span>{item['date']}</span>
                        </div>
                        <div class="news-summary">{item['summary']}</div>
                        <a href="{item['link']}" class="news-link" target="_blank">Czytaj więcej →</a>
                    </div>
"""
            html_content += """
                </div>
            </div>
"""

        # Sekcja zagrożeń
        if self.threats:
            html_content += """
            <div class="section">
                <h2>⚠️ Nowe Zagrożenia</h2>
                <div class="news-grid">
"""
            for item in self.threats[:20]:
                html_content += f"""
                    <div class="news-item threat">
                        <div class="news-title">{item['title']}</div>
                        <div class="news-meta">
                            <span class="source-tag">{item['source']}</span>
                            <span>{item['date']}</span>
                        </div>
                        <div class="news-summary">{item['summary']}</div>
                        <a href="{item['link']}" class="news-link" target="_blank">Czytaj więcej →</a>
                    </div>
"""
            html_content += """
                </div>
            </div>
"""

        # Sekcja luk
        if self.vulnerabilities:
            html_content += """
            <div class="section">
                <h2>🔓 Wykryte Luki w Zabezpieczeniach</h2>
                <div class="news-grid">
"""
            for item in self.vulnerabilities[:20]:
                severity_class = ''
                if 'cvss_score' in item and item['cvss_score'] != 'N/A':
                    try:
                        score = float(item['cvss_score'])
                        if score >= 7.0:
                            severity_class = 'severity-high'
                        elif score >= 4.0:
                            severity_class = 'severity-medium'
                        else:
                            severity_class = 'severity-low'
                    except:
                        pass

                cve_info = ''
                if 'cve_id' in item:
                    cve_info = f'<div class="cve-info">CVE ID: {item["cve_id"]} | CVSS: {item.get("cvss_score", "N/A")} | Severity: {item.get("severity", "N/A")}</div>'

                html_content += f"""
                    <div class="news-item vulnerability {severity_class}">
                        <div class="news-title">{item['title']}</div>
                        <div class="news-meta">
                            <span class="source-tag">{item['source']}</span>
                            <span>{item['date']}</span>
                        </div>
                        {cve_info}
                        <div class="news-summary">{item['summary']}</div>
                        <a href="{item['link']}" class="news-link" target="_blank">Czytaj więcej →</a>
                    </div>
"""
            html_content += """
                </div>
            </div>
"""

        html_content += f"""
        </div>

        <div class="footer">
            <p><strong>Źródła danych:</strong></p>
            <p>RSS: CERT.PL, Niebezpiecznik, Bleeping Computer, Security Affairs, Krebs Security, Threatpost, Dark Reading, InfoSecurity Magazine, Security Week, Cybersecurity News, HackRead, The Hacker News, CISA, SANS</p>
            <p>API: National Vulnerability Database (NVD), VirusTotal, Shodan, AlienVault OTX</p>
            <p>Raport przygotowany i wygenerowany przez Marek Ziemniewicz: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>
"""

        # Zapisz raport HTML
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

        # Zapisz dane JSON
        data = {
            'date': today,
            'incidents': self.incidents,
            'threats': self.threats,
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total_incidents': len(self.incidents),
                'total_threats': len(self.threats),
                'total_vulnerabilities': len(self.vulnerabilities),
                'sources_used': list(self.rss_sources.keys()) + ['nvd_api']
            }
        }

        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        # Zapisz CSV
        with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Kategoria', 'Źródło', 'Tytuł', 'Data', 'Link', 'Podsumowanie', 'CVE_ID', 'CVSS_Score', 'Severity'])

            for item in self.incidents:
                writer.writerow(['Incydent', item['source'], item['title'], item['date'], item['link'], item['summary'], '', '', ''])
            for item in self.threats:
                writer.writerow(['Zagrożenie', item['source'], item['title'], item['date'], item['link'], item['summary'], '', '', ''])
            for item in self.vulnerabilities:
                writer.writerow(['Luka', item['source'], item['title'], item['date'], item['link'], item['summary'], 
                               item.get('cve_id', ''), item.get('cvss_score', ''), item.get('severity', '')])

        print(f"✅ Rozszerzony raport został wygenerowany w katalogu: {report_dir}")
        print(f"   - HTML: {report_filename}")
        print(f"   - JSON: {json_filename}")
        print(f"   - CSV: {csv_filename}")

        return report_filename

def main():
    """Funkcja główna programu"""
    print("🛡️ Rozszerzony System Monitorowania Cyberbezpieczeństwa")
    print("=" * 60)

    # Tworzenie instancji monitora
    monitor = AdvancedCyberSecurityMonitor()

    # Opcjonalnie ustaw klucze API (jeśli masz)
    # monitor.set_api_key('virustotal', '8799778183788c0622a0782a4a3547c8ac731249f82db2b781ca941463a5747c')
    # monitor.set_api_key('shodan', 'f5VVSrXsZefbrELI3eAxCTd5E4wd2Quk')

    try:
        # Zbieranie danych
        monitor.collect_all_data()

        # Generowanie raportu
        report_file = monitor.generate_enhanced_report()

        print(f"\n📊 Finalne podsumowanie:")
        print(f"   - Incydenty: {len(monitor.incidents)}")
        print(f"   - Zagrożenia: {len(monitor.threats)}")
        print(f"   - Luki: {len(monitor.vulnerabilities)}")
        print(f"\n✅ Rozszerzony raport: {report_file}")

    except KeyboardInterrupt:
        print("\n⚠️ Program przerwany przez użytkownika")
    except Exception as e:
        print(f"\n❌ Wystąpił błąd: {e}")

if __name__ == "__main__":
    main()
import subprocess

# --- Po wygenerowaniu raportu ---
try:
    print("\n🔁 Uruchamianie synchronizacji z GitHub...")
    subprocess.run(["python", "auto_sync_to_github.py"], shell=True)
except Exception as e:
    print("❌ Błąd podczas synchronizacji:", e)
