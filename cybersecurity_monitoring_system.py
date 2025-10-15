#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rozszerzony System Monitorowania Cyberbezpieczeństwa — PRO (Matrix Dark Dashboard)
Autor: Marek Z, AI Assistant
Data: 2025-10-14

Funkcje:
- Pobieranie danych z RSS + API (NVD, opcjonalnie: VirusTotal, Shodan, AlienVault OTX)
- Klasyfikacja: incydenty / zagrożenia / luki
- Dedup: usuwanie duplikatów po linku/tytule
- Raport HTML w stylu dark cyber (+ filtry High/Medium/Low, sort Data/CVSS, przełącznik motywu Matrix/Neo)
- Eksport JSON i CSV

Wymagania:
  pip install requests beautifulsoup4 feedparser

Klucze API (opcjonalne):
  Ustaw jako zmienne środowiskowe przed uruchomieniem:
    VT_API_KEY, SHODAN_API_KEY, OTX_API_KEY

Użycie:
  python cybersecurity_monitor_pro_matrix_final.py
"""

from __future__ import annotations

import os
import sys
import csv
import json
import time
import logging
import random
import xml.etree.ElementTree as ET
from string import Template
from typing import List, Dict, Any
from datetime import datetime, timedelta

import requests

# BeautifulSoup jest opcjonalny — jeśli brak, użyjemy regexu
try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None  # fallback w html2text

# -------------------------------------------
# Logowanie + konsola UTF-8 (Windows)
# -------------------------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CyberMonitorPRO")
try:
    if getattr(sys.stdout, "reconfigure", None):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# -------------------------------------------
# Helpery
# -------------------------------------------
def html2text(s: str) -> str:
    """Bezpieczne usunięcie HTML (działa także bez bs4)."""
    if not s:
        return ''
    try:
        if BeautifulSoup is not None:
            return BeautifulSoup(s, 'html.parser').get_text()
    except Exception:
        pass
    import re
    return re.sub(r'<[^>]+>', '', s)

# -------------------------------------------
# Klucze API — ENV lub set_api_key()
# -------------------------------------------
API_KEYS_DEFAULT = {
    'virustotal': os.getenv('VT_API_KEY'),
    'shodan': os.getenv('SHODAN_API_KEY'),
    'alienvault': os.getenv('OTX_API_KEY'),
}


class AdvancedCyberSecurityMonitor:
    def __init__(self):
        # RSS — kompletna lista źródeł (Twoja baza)
        self.rss_sources: Dict[str, str] = {
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
            'doar_e_rss': 'https://doar-e.github.io/feeds/rss.xml?_=0',
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
            'sean_heelan_rss': 'https://sean.heelan.io/feed/?_=',
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

        # NVD (okno 7 dni, UTC)
        self.api_sources = {
            'nvd_cve': {
                'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
                'params': {
                    'resultsPerPage': 20,
                    'startIndex': 0,
                    'pubStartDate': (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000'),
                    'pubEndDate': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000')
                }
            }
        }

        # Rotacja UA
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        ]
        self.headers = {'User-Agent': random.choice(self.user_agents)}

        # Kolekcje
        self.incidents: List[Dict[str, Any]] = []
        self.threats: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []

        self.api_keys = API_KEYS_DEFAULT.copy()

    # ---------- Utils ----------
    def set_api_key(self, service: str, key: str) -> None:
        self.api_keys[service] = key
        logger.info(f"✅ Ustawiono klucz API dla {service}")

    # ---------- RSS ----------
    def parse_simple_rss(self, url: str, source_name: str) -> List[Dict[str, Any]]:
        try:
            logger.info(f"📡 RSS (XML) → {source_name}")
            r = requests.get(url, headers=self.headers, timeout=20)
            if r.status_code != 200:
                logger.warning(f"❌ HTTP {r.status_code} dla {source_name}")
                return []
            try:
                root = ET.fromstring(r.content)
            except ET.ParseError as e:
                logger.warning(f"❌ XML parse dla {source_name}: {e}")
                return []
            entries = []
            for item in root.findall('.//item')[:10]:
                try:
                    title = (item.findtext('title') or 'Brak tytułu')
                    link = (item.findtext('link') or '')
                    description = (item.findtext('description') or '')
                    pub_date = (item.findtext('pubDate') or '')
                    if description:
                        description = html2text(description)
                        description = description[:300] + '...' if len(description) > 300 else description
                    entries.append({
                        'source': source_name,
                        'title': title,
                        'link': link,
                        'date': pub_date,
                        'summary': description,
                        'category': self.classify_news(f"{title} {description}")
                    })
                except Exception as e:
                    logger.debug(f"⚠️ RSS elem err: {e}")
            logger.info(f"✅ {source_name}: {len(entries)} wpisów")
            return entries
        except Exception as e:
            logger.error(f"❌ RSS pobieranie {source_name}: {e}")
            return []

    def parse_with_feedparser(self, url: str, source_name: str) -> List[Dict[str, Any]]:
        try:
            import feedparser  # lazy import
            logger.info(f"📡 RSS (feedparser) → {source_name}")
            feed = feedparser.parse(url)
            entries = []
            for entry in feed.entries[:10]:
                title = entry.get('title', 'Brak tytułu')
                link = entry.get('link', '')
                published = entry.get('published', entry.get('updated', ''))
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    published = datetime(*entry.published_parsed[:6]).strftime('%Y-%m-%d %H:%M')
                summary = entry.get('summary', entry.get('description', ''))
                if summary:
                    summary = html2text(summary)
                    summary = summary[:300] + '...' if len(summary) > 300 else summary
                entries.append({
                    'source': source_name,
                    'title': title,
                    'link': link,
                    'date': published,
                    'summary': summary,
                    'category': self.classify_news(f"{title} {summary}")
                })
            logger.info(f"✅ {source_name}: {len(entries)} wpisów")
            return entries
        except ImportError:
            logger.info("feedparser brak — fallback XML")
            return self.parse_simple_rss(url, source_name)
        except Exception as e:
            logger.error(f"❌ RSS feedparser {source_name}: {e}")
            return []

    # ---------- API: NVD ----------
    def fetch_nvd_cve_data(self) -> List[Dict[str, Any]]:
        try:
            logger.info("🔌 NVD CVE …")
            r = requests.get(self.api_sources['nvd_cve']['url'], params=self.api_sources['nvd_cve']['params'], headers=self.headers, timeout=30)
            if r.status_code != 200:
                logger.warning(f"NVD HTTP {r.status_code}")
                return []
            data = r.json()
            vulns: List[Dict[str, Any]] = []
            for cve in data.get('vulnerabilities', []):
                cve_data = cve.get('cve', {})
                cve_id = cve_data.get('id', 'N/A')
                published = cve_data.get('published', 'N/A')
                # opis EN
                description = ''
                for desc in cve_data.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
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
                vulns.append({
                    'source': 'NVD (NIST)',
                    'title': f"{cve_id} - {severity} ({cvss_score})",
                    'link': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    'date': published[:10] if published != 'N/A' else 'N/A',
                    'summary': (description[:300] + '...') if len(description) > 300 else description,
                    'category': 'vulnerability',
                    'cvss_score': cvss_score,
                    'severity': severity,
                    'cve_id': cve_id
                })
            logger.info(f"✅ NVD: {len(vulns)}")
            return vulns
        except Exception as e:
            logger.error(f"❌ NVD err: {e}")
            return []

    # ---------- API: VirusTotal ----------
    def fetch_virustotal_data(self) -> List[Dict[str, Any]]:
        key = self.api_keys.get('virustotal')
        if not key:
            logger.info("VT: brak klucza — pomijam")
            return []
        try:
            logger.info("🔌 VirusTotal intelligence …")
            headers = {'x-apikey': key, 'User-Agent': random.choice(self.user_agents)}
            url = 'https://www.virustotal.com/api/v3/intelligence/search'
            params = {'query': 'type:file positives:5+ fs:2024-09-01+', 'limit': 20}
            r = requests.get(url, headers=headers, params=params, timeout=30)
            if r.status_code != 200:
                logger.warning(f"VT HTTP {r.status_code}")
                return []
            data = r.json()
            threats: List[Dict[str, Any]] = []
            for item in data.get('data', []):
                attrs = item.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                total = sum(stats.values()) if stats else 0
                threats.append({
                    'source': 'VirusTotal',
                    'title': f"Malware wykryty przez {stats.get('malicious', 0)} silników",
                    'link': f"https://www.virustotal.com/gui/file/{item.get('id', '')}",
                    'date': datetime.utcnow().strftime('%Y-%m-%d'),
                    'summary': f"SHA256: {item.get('id','')[:16]}… | Wykrycia: {stats.get('malicious', 0)}/{total}",
                    'category': 'threat'
                })
            logger.info(f"✅ VT: {len(threats)}")
            return threats
        except Exception as e:
            logger.error(f"❌ VT err: {e}")
            return []

    # ---------- API: Shodan ----------
    def fetch_shodan_data(self) -> List[Dict[str, Any]]:
        key = self.api_keys.get('shodan')
        if not key:
            logger.info("Shodan: brak klucza — pomijam")
            return []
        try:
            logger.info("🔌 Shodan host/search …")
            url = 'https://api.shodan.io/shodan/host/search'
            params = {'key': key, 'query': 'vuln:CVE-2024 country:PL', 'limit': 20}
            r = requests.get(url, params=params, timeout=30)
            if r.status_code != 200:
                logger.warning(f"Shodan HTTP {r.status_code}")
                return []
            data = r.json()
            vulns: List[Dict[str, Any]] = []
            for match in data.get('matches', []):
                for vuln_id in (match.get('vulns', []) or []):
                    vulns.append({
                        'source': 'Shodan',
                        'title': f"Podatny system: {match.get('ip_str','N/A')} - {vuln_id}",
                        'link': f"https://www.shodan.io/host/{match.get('ip_str','')}",
                        'date': datetime.utcnow().strftime('%Y-%m-%d'),
                        'summary': f"IP: {match.get('ip_str','N/A')} | Port: {match.get('port','N/A')} | Org: {match.get('org','N/A')} | Kraj: {match.get('location',{}).get('country_name','N/A')}",
                        'category': 'vulnerability',
                        'cve_id': vuln_id,
                        'ip_address': match.get('ip_str','N/A'),
                        'port': match.get('port','N/A')
                    })
            logger.info(f"✅ Shodan: {len(vulns)}")
            return vulns
        except Exception as e:
            logger.error(f"❌ Shodan err: {e}")
            return []

    # ---------- API: AlienVault OTX ----------
    def fetch_alienvault_data(self) -> List[Dict[str, Any]]:
        key = self.api_keys.get('alienvault')
        if not key:
            logger.info("OTX: brak klucza — pomijam")
            return []
        try:
            logger.info("🔌 AlienVault OTX pulses …")
            headers = {'X-OTX-API-KEY': key, 'User-Agent': random.choice(self.user_agents)}
            url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
            params = {'limit': 20, 'modified_since': (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')}
            r = requests.get(url, headers=headers, params=params, timeout=30)
            if r.status_code != 200:
                logger.warning(f"OTX HTTP {r.status_code}")
                return []
            data = r.json()
            out: List[Dict[str, Any]] = []
            for pulse in data.get('results', []):
                desc = pulse.get('description', '') or 'Brak opisu'
                out.append({
                    'source': 'AlienVault OTX',
                    'title': pulse.get('name', 'Brak nazwy'),
                    'link': f"https://otx.alienvault.com/pulse/{pulse.get('id','')}",
                    'date': (pulse.get('created','')[:10] or datetime.utcnow().strftime('%Y-%m-%d')),
                    'summary': (desc[:400] + '…') if len(desc) > 400 else desc,
                    'category': 'threat',
                    'tags': ', '.join(pulse.get('tags', [])),
                    'indicators_count': len(pulse.get('indicators', []))
                })
            logger.info(f"✅ OTX: {len(out)}")
            return out
        except Exception as e:
            logger.error(f"❌ OTX err: {e}")
            return []

    # ---------- Kolekcja danych ----------
    def fetch_api_data(self) -> List[Dict[str, Any]]:
        data: List[Dict[str, Any]] = []
        data.extend(self.fetch_virustotal_data())
        data.extend(self.fetch_shodan_data())
        data.extend(self.fetch_alienvault_data())
        data.extend(self.fetch_nvd_cve_data())
        return data

    def collect_rss_news(self) -> List[Dict[str, Any]]:
        all_entries: List[Dict[str, Any]] = []
        for key, url in self.rss_sources.items():
            entries = self.parse_with_feedparser(url, key.replace('_rss', '').replace('_', ' ').title())
            all_entries.extend(entries)
            time.sleep(1)  # throttling
        for entry in all_entries:
            self.add_to_category(entry, entry.get('category', 'general'))
        return all_entries

    def collect_api_data(self) -> None:
        logger.info("🔌 API…")
        items = self.fetch_api_data()
        for it in items:
            self.add_to_category(it, it.get('category', 'general'))
        logger.info(f"✅ API razem: {len(items)}")

    def collect_all_data(self) -> None:
        logger.info("🔄 Start zbierania…")
        self.collect_rss_news()
        self.collect_api_data()
        self.dedupe_entries()
        logger.info(f"Zebrano → Incydenty: {len(self.incidents)} | Zagrożenia: {len(self.threats)} | Luki: {len(self.vulnerabilities)}")

    # ---------- Klasyfikacja i deduplikacja ----------
    def classify_news(self, text: str) -> str:
        """Ujednolicona klasyfikacja (ta sama w każdym layoucie)."""
        if not text:
            return 'general'
        t = text.lower()
        if any(k in t for k in ['cve', 'luka', 'vulnerability', 'exploit', 'patch', 'update', 'zero-day', 'bug', 'security flaw', 'backdoor', 'buffer overflow', 'injection', 'xss', 'csrf', 'rce', 'remote code execution', 'privilege escalation', 'authentication bypass']):
            return 'vulnerability'
        if any(k in t for k in ['malware', 'ransomware', 'phishing', 'trojan', 'virus', 'botnet', 'apt', 'campaign', 'spyware', 'adware', 'rootkit', 'keylogger', 'worm', 'stealer', 'cryptojacking', 'ddos', 'social engineering']):
            return 'threat'
        if any(k in t for k in ['atak', 'attack', 'breach', 'hack', 'incydent', 'naruszenie', 'wyciek', 'leak', 'data breach', 'cyber attack', 'compromise', 'intrusion', 'unauthorized access', 'security incident', 'cyber incident']):
            return 'incident'
        return 'general'

    def add_to_category(self, news_item: Dict[str, Any], category: str) -> None:
        if category == 'vulnerability':
            self.vulnerabilities.append(news_item)
        elif category == 'threat':
            self.threats.append(news_item)
        elif category == 'incident':
            self.incidents.append(news_item)

    def dedupe_entries(self) -> None:
        """Usuwa duplikaty po znormalizowanym linku (bez query) lub tytule."""
        def norm(u: str) -> str:
            u = (u or '').split('?')[0].strip().lower()
            return u
        def dedupe(col: List[Dict[str, Any]]):
            seen = set(); out: List[Dict[str, Any]] = []
            for it in col:
                k = norm(it.get('link')) or (it.get('title','').strip().lower())
                if k in seen:
                    continue
                seen.add(k); out.append(it)
            return out
        self.incidents = dedupe(self.incidents)
        self.threats = dedupe(self.threats)
        self.vulnerabilities = dedupe(self.vulnerabilities)

    # ---------- Raport HTML (Template: brak problemów z { } w f-stringach) ----------
    def generate_enhanced_report(self) -> str:
        today = datetime.now().strftime('%Y-%m-%d')
        report_dir = f"reports/{today}"
        os.makedirs(report_dir, exist_ok=True)
        report_filename = f"{report_dir}/index.html"

        def sort_by_date(items: List[Dict[str, Any]]):
            try:
                return sorted(items, key=lambda x: x.get('date', ''), reverse=True)
            except Exception:
                return items

        self.incidents = sort_by_date(self.incidents)
        self.threats = sort_by_date(self.threats)
        self.vulnerabilities = sort_by_date(self.vulnerabilities)

        def to_iso_date(s: str) -> str:
            if not s:
                return ''
            try:
                if len(s) >= 10 and s[4] == '-' and s[7] == '-':
                    return s[:10]
                return datetime.fromisoformat(s[:19]).strftime('%Y-%m-%d')
            except Exception:
                return s[:10] if len(s) >= 10 else s

        def cvss_num(item: Dict[str, Any]) -> float:
            try:
                sc = item.get('cvss_score', 'N/A')
                return float(sc) if sc != 'N/A' else -1.0
            except Exception:
                return -1.0

        # Karty: Incydenty
        inc_cards: List[str] = []
        for it in self.incidents[:20]:
            iso = to_iso_date(it.get('date', ''))
            inc_cards.append(
                (
                    '<div class="card news-item incident" data-sev="none" data-date="{iso}" data-cvss="-1">\n'
                    '  <div class="news-title">{title}</div>\n'
                    '  <div class="news-meta">\n'
                    '    <span class="badge">{source}</span>\n'
                    '    <span>{date}</span>\n'
                    '  </div>\n'
                    '  <div class="news-summary">{summary}</div>\n'
                    '  <a href="{link}" class="news-link" target="_blank" rel="noopener">Czytaj więcej →</a>\n'
                    '</div>'
                ).format(
                    iso=iso,
                    title=it.get('title',''),
                    source=it.get('source',''),
                    date=it.get('date',''),
                    summary=it.get('summary',''),
                    link=it.get('link','')
                )
            )

        # Karty: Zagrożenia
        thr_cards: List[str] = []
        for it in self.threats[:20]:
            iso = to_iso_date(it.get('date', ''))
            thr_cards.append(
                (
                    '<div class="card news-item threat" data-sev="none" data-date="{iso}" data-cvss="-1">\n'
                    '  <div class="news-title">{title}</div>\n'
                    '  <div class="news-meta">\n'
                    '    <span class="badge">{source}</span>\n'
                    '    <span>{date}</span>\n'
                    '  </div>\n'
                    '  <div class="news-summary">{summary}</div>\n'
                    '  <a href="{link}" class="news-link" target="_blank" rel="noopener">Czytaj więcej →</a>\n'
                    '</div>'
                ).format(
                    iso=iso,
                    title=it.get('title',''),
                    source=it.get('source',''),
                    date=it.get('date',''),
                    summary=it.get('summary',''),
                    link=it.get('link','')
                )
            )

        # Karty: Luki
        vuln_cards: List[str] = []
        for it in self.vulnerabilities[:20]:
            sc = cvss_num(it)
            sev_class = 'high' if sc >= 7.0 else ('medium' if sc >= 4.0 else 'low')
            iso = to_iso_date(it.get('date', ''))
            cve_info = ''
            if it.get('cve_id'):
                cve_info = (
                    '  <div class="cve-info">CVE ID: {cve} | CVSS: {cvss} | Severity: {sev}</div>\n'
                ).format(cve=it.get('cve_id',''), cvss=it.get('cvss_score','N/A'), sev=it.get('severity','N/A'))
            vuln_cards.append(
                (
                    '<div class="card news-item vulnerability" data-sev="{sev_class}" data-date="{iso}" data-cvss="{cvss}">\n'
                    '  <div class="news-title">{title}</div>\n'
                    '  <div class="news-meta">\n'
                    '    <span class="badge">{source}</span>\n'
                    '    <span>{date}</span>\n'
                    '  </div>\n'
                    '{cve_info}'
                    '  <div class="news-summary">{summary}</div>\n'
                    '  <a href="{link}" class="news-link" target="_blank" rel="noopener">Czytaj więcej →</a>\n'
                    '</div>'
                ).format(
                    sev_class=sev_class,
                    iso=iso,
                    cvss=sc,
                    title=it.get('title',''),
                    source=it.get('source',''),
                    date=it.get('date',''),
                    cve_info=cve_info,
                    summary=it.get('summary',''),
                    link=it.get('link','')
                )
            )

        html_tpl = Template(r'''<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Raport Cyberbezpieczeństwa — $TODAY</title>
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;700&family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0d1117;
      --panel: #0f1623;
      --panel-2: #111a2a;
      --text: #d7e2f0;
      --muted: #8aa0b6;
      --accent: #00bcd4;
      --accent-2: #35e0ff;
      --danger: #f44336;
      --warn: #ff9800;
      --violet: #9c27b0;
      --glow: 0 0 25px rgba(0,188,212,0.25);
      --border: 1px solid rgba(0,188,212,0.15);
    }
    body.matrix {
      --bg: #071207;
      --panel: #0a1a0a;
      --panel-2: #0c210c;
      --text: #e2ffe2;
      --muted: #9bdea3;
      --accent: #00ff84;
      --accent-2: #6bffb0;
      --danger: #ff6b6b;
      --warn: #ffd166;
      --violet: #7dffb5;
      --glow: 0 0 22px rgba(0, 255, 132, .25);
      --border: 1px solid rgba(0,255,132,.18);
      background-image:
        linear-gradient(rgba(0,0,0,.35), rgba(0,0,0,.35)),
        repeating-linear-gradient( to bottom, rgba(0,255,132,.05) 0px, rgba(0,255,132,.05) 2px, transparent 2px, transparent 4px ),
        radial-gradient(1200px 600px at 10% 0%, #051004 0%, #061006 55%, #041004 100%);
      background-attachment: fixed;
    }

    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0; background: radial-gradient(1200px 600px at 10% 0%, #0b1220 0%, #0d1117 55%, #0a0f18 100%);
      color: var(--text); font-family: 'Roboto', system-ui, -apple-system, Segoe UI, Arial, sans-serif;
    }
    .topbar { position: sticky; top: 0; z-index: 999; backdrop-filter: blur(8px); background: rgba(13,17,23,0.7); border-bottom: var(--border); }
    .nav { max-width: 1200px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; padding: 12px 18px; }
    .brand { display:flex; align-items:center; gap:10px; }
    .logo { width: 32px; height: 32px; border-radius: 8px; background: linear-gradient(135deg, var(--accent), var(--accent-2)); box-shadow: var(--glow); }
    .brand h1 { font-family: 'Orbitron', monospace; font-weight: 700; font-size: 1.05rem; letter-spacing: .06em; margin:0; color: #e6faff; text-shadow: 0 0 12px rgba(53,224,255,.25); }
    body.matrix .brand h1 { color:#d8ffe6; text-shadow: 0 0 12px rgba(0,255,132,.3); }
    .menu a { color: var(--text); text-decoration: none; margin-left: 12px; font-weight: 500; padding: 6px 10px; border-radius: 8px; border: var(--border); background: linear-gradient(180deg, rgba(0,188,212,0.06), rgba(0,188,212,0.03)); }
    .menu a:hover { color:#e6faff; border-color: rgba(53,224,255,.45); box-shadow: var(--glow); }

    .container { max-width: 1200px; margin: 24px auto; padding: 0 16px; }
    .hero { background: linear-gradient(180deg, rgba(0,188,212,0.06), rgba(0,188,212,0.02)); border: var(--border); border-radius: 16px; padding: 18px; box-shadow: var(--glow); }
    .hero h2 { margin: 0 0 6px 0; font-family: 'Orbitron', monospace; letter-spacing:.05em; color:#e6faff; text-shadow: 0 0 18px rgba(53,224,255,.25); }
    .sub { color: var(--muted); margin:0; }

    .controls { display:flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-top: 10px; }
    .chip { display:inline-flex; align-items:center; gap:8px; padding:6px 10px; border-radius:999px; border: var(--border); background: linear-gradient(180deg, rgba(0,188,212,.08), rgba(0,188,212,.03)); color: var(--text); font-size: .92rem; }
    .chip input { transform: translateY(1px); }
    .select { padding:6px 10px; border-radius:10px; border: var(--border); background: linear-gradient(180deg, rgba(0,188,212,.06), rgba(0,188,212,.02)); color: var(--text); }
    .btn { padding:6px 10px; border-radius:10px; border: var(--border); cursor:pointer; background: linear-gradient(180deg, rgba(0,188,212,.12), rgba(0,188,212,.05)); color: var(--text); }
    .btn:hover { border-color: rgba(53,224,255,.45); box-shadow: var(--glow); }

    .stats { display:grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap: 14px; margin-top: 14px; }
    .card { background: linear-gradient(180deg, var(--panel), var(--panel-2)); border: var(--border); border-radius: 14px; padding: 14px; transition: .2s; }
    .card:hover { transform: translateY(-3px); border-color: rgba(53,224,255,.45); box-shadow: var(--glow); }
    .kpi-num a { color: var(--accent-2); font-weight: 700; font-size: 1.9rem; text-decoration: none; }
    .kpi-label { color: var(--muted); font-size:.95rem; margin-top: 4px; }

    .section { margin-top: 22px; }
    .section h3 { font-family:'Orbitron', monospace; letter-spacing:.04em; color:#e6faff; margin: 0 0 12px 0; text-shadow: 0 0 14px rgba(53,224,255,.22); display:flex; align-items:center; gap:8px; }
    .news-grid { display:grid; grid-template-columns: repeat(auto-fit,minmax(320px,1fr)); gap: 14px; }

    .news-item { border-left:5px solid #2bbbd0; }
    .news-item.incident { border-left-color: var(--danger); }
    .news-item.threat { border-left-color: var(--warn); }
    .news-item.vulnerability { border-left-color: var(--violet); }

    .news-title { font-weight:700; color:#e9f7ff; margin-bottom: 6px; }
    .news-meta { font-size: .85rem; color: var(--muted); margin-bottom: 10px; display:flex; justify-content: space-between; }
    .badge { background: rgba(0,188,212,.14); border: 1px solid rgba(0,188,212,.25); padding: 2px 8px; border-radius: 999px; }
    .news-summary { color:#bfd2e6; line-height:1.45; }
    .news-link { display:inline-block; margin-top: 8px; color: var(--accent-2); font-weight: 700; text-decoration:none; }
    .news-link:hover { text-decoration: underline; }

    .cve-info { background: rgba(156,39,176,.08); border: 1px solid rgba(156,39,176,.25); padding:8px; border-radius:8px; margin: 8px 0; color:#f2e6ff; }
    body.matrix .cve-info { background: rgba(0,255,132,.08); border-color: rgba(0,255,132,.25); color:#dbffe8; }

    .divider { height:1px; background: linear-gradient(90deg, rgba(0,188,212,.0), rgba(0,188,212,.35), rgba(0,188,212,.0)); margin: 18px 0; }
    .back-top { display:inline-block; margin-top:12px; padding:8px 12px; border-radius:10px; border: var(--border); color:#e6faff; text-decoration:none; background: linear-gradient(180deg, rgba(0,188,212,0.12), rgba(0,188,212,0.05)); }
    .back-top:hover { border-color: rgba(53,224,255,.45); box-shadow: var(--glow); }

    .footer { margin-top:22px; color: var(--muted); font-size:.9rem; text-align:center; padding: 14px; border-top: var(--border); }
  </style>
</head>
<body id="top">
  <div class="topbar">
    <div class="nav">
      <div class="brand">
        <div class="logo"></div>
        <h1>CYBERSEC • ROZSZERZONY RAPORT CYBER</h1>
      </div>
      <div class="menu">
        <a href="#incidents">Incydenty</a>
        <a href="#threats">Zagrożenia</a>
        <a href="#vulnerabilities">Luki</a>
        <a href="#top">Góra</a>
      </div>
    </div>
  </div>

  <div class="container">
    <div class="hero">
      <h2>🛡️ Raport Cyberbezpieczeństwa</h2>
      <p class="sub">Dane z RSS i API | $TODAY</p>

      <div class="controls">
        <label class="chip"><input type="checkbox" id="filterHigh" checked> High</label>
        <label class="chip"><input type="checkbox" id="filterMedium" checked> Medium</label>
        <label class="chip"><input type="checkbox" id="filterLow" checked> Low</label>

        <select id="sorter" class="select" title="Sortowanie">
          <option value="date_desc">Sortuj: Data ↓</option>
          <option value="date_asc">Sortuj: Data ↑</option>
          <option value="cvss_desc">Sortuj: CVSS ↓</option>
          <option value="cvss_asc">Sortuj: CVSS ↑</option>
        </select>

        <button class="btn" id="toggleTheme">Motyw: Matrix Green</button>
      </div>

      <div class="stats">
        <div class="card"><div class="kpi-num"><a href="#incidents">$INC</a></div><div class="kpi-label">Incydenty</div></div>
        <div class="card"><div class="kpi-num"><a href="#threats">$THR</a></div><div class="kpi-label">Zagrożenia</div></div>
        <div class="card"><div class="kpi-num"><a href="#vulnerabilities">$VULN</a></div><div class="kpi-label">Luki</div></div>
        <div class="card"><div class="kpi-num"><a href="#top">$TOTAL</a></div><div class="kpi-label">Łącznie</div></div>
      </div>
    </div>

    <div class="divider"></div>

    <div class="section" id="incidents">
      <h3>🚨 Incydenty Bezpieczeństwa ($INC)</h3>
      <div class="news-grid" data-grid="incidents">
$INCIDENTS
      </div>
      <a href="#top" class="back-top">⬆ Powrót na górę</a>
    </div>

    <div class="divider"></div>

    <div class="section" id="threats">
      <h3>⚠️ Nowe Zagrożenia ($THR)</h3>
      <div class="news-grid" data-grid="threats">
$THREATS
      </div>
      <a href="#top" class="back-top">⬆ Powrót na górę</a>
    </div>

    <div class="divider"></div>

    <div class="section" id="vulnerabilities">
      <h3>🔓 Wykryte Luki ($VULN)</h3>
      <div class="news-grid" data-grid="vulnerabilities">
$VULNERABILITIES
      </div>
      <a href="#top" class="back-top">⬆ Powrót na górę</a>
    </div>

    <div class="footer">
      <div><strong>Źródła:</strong> RSS + API (NVD, opcjonalnie: VirusTotal, Shodan, AlienVault OTX)</div>
      <div>Raport wygenerowano: $STAMP</div>
    </div>
  </div>

  <script>
    (function() {
      const filterHigh = document.getElementById('filterHigh');
      const filterMedium = document.getElementById('filterMedium');
      const filterLow = document.getElementById('filterLow');
      const sorter = document.getElementById('sorter');
      const toggleTheme = document.getElementById('toggleTheme');

      const vulnGrid = document.querySelector('[data-grid="vulnerabilities"]');

      function applyFilters() {
        if (!vulnGrid) return;
        const cards = Array.from(vulnGrid.children);
        cards.forEach(card => {
          const sev = card.getAttribute('data-sev'); // high | medium | low
          if (!sev || sev === 'none') {
            card.style.display = '';
            return;
          }
          let show = true;
          if (sev === 'high' && !filterHigh.checked) show = false;
          if (sev === 'medium' && !filterMedium.checked) show = false;
          if (sev === 'low' && !filterLow.checked) show = false;
          card.style.display = show ? '' : 'none';
        });
      }

      function applySort() {
        const mode = sorter.value; // date_desc | date_asc | cvss_desc | cvss_asc
        const grids = document.querySelectorAll('[data-grid]');
        grids.forEach(grid => {
          const cards = Array.from(grid.children);
          let cmp = null;

          if (mode === 'cvss_desc' || mode === 'cvss_asc') {
            // tylko dla sekcji luk
            if (grid.getAttribute('data-grid') !== 'vulnerabilities') return;
            cmp = (a, b) => {
              const ca = Number(a.getAttribute('data-cvss') || '-1');
              const cb = Number(b.getAttribute('data-cvss') || '-1');
              if (isNaN(ca) && isNaN(cb)) return 0;
              if (isNaN(ca)) return 1;
              if (isNaN(cb)) return -1;
              return mode === 'cvss_desc' ? (cb - ca) : (ca - cb);
            };
          } else {
            // data dla wszystkich sekcji
            const key = (el) => {
              const s = (el.getAttribute('data-date') || '').replaceAll('/', '-');
              if (!s) return 0;
              const t = Date.parse(s);
              return isNaN(t) ? 0 : t;
            };
            cmp = (a, b) => mode === 'date_desc' ? (key(b) - key(a)) : (key(a) - key(b));
          }

          if (cmp) cards.sort(cmp).forEach(c => grid.appendChild(c));
        });
      }

      filterHigh.addEventListener('change', applyFilters);
      filterMedium.addEventListener('change', applyFilters);
      filterLow.addEventListener('change', applyFilters);
      sorter.addEventListener('change', () => { applySort(); });

      toggleTheme.addEventListener('click', () => {
        document.body.classList.toggle('matrix');
        toggleTheme.textContent = document.body.classList.contains('matrix') ? 'Motyw: Neo Turquoise' : 'Motyw: Matrix Green';
      });

      applyFilters();
      applySort();
    })();
  </script>
</body>
</html>
''')

        html = html_tpl.substitute(
            TODAY=today,
            INC=len(self.incidents),
            THR=len(self.threats),
            VULN=len(self.vulnerabilities),
            TOTAL=len(self.incidents) + len(self.threats) + len(self.vulnerabilities),
            INCIDENTS="\n".join(inc_cards),
            THREATS="\n".join(thr_cards),
            VULNERABILITIES="\n".join(vuln_cards),
            STAMP=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html)

        # JSON + CSV
        json_filename = f"{report_dir}/enhanced_cybersecurity_data_{today}.json"
        csv_filename = f"{report_dir}/enhanced_cybersecurity_summary_{today}.csv"
        data = {
            'date': today,
            'incidents': self.incidents,
            'threats': self.threats,
            'vulnerabilities': self.vulnerabilities
        }
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Kategoria', 'Źródło', 'Tytuł', 'Data', 'Link', 'Podsumowanie', 'CVE_ID', 'CVSS_Score', 'Severity'])
            for item in self.incidents:
                writer.writerow(['Incydent', item.get('source',''), item.get('title',''), item.get('date',''), item.get('link',''), item.get('summary',''), '', '', ''])
            for item in self.threats:
                writer.writerow(['Zagrożenie', item.get('source',''), item.get('title',''), item.get('date',''), item.get('link',''), item.get('summary',''), '', '', ''])
            for item in self.vulnerabilities:
                writer.writerow(['Luka', item.get('source',''), item.get('title',''), item.get('date',''), item.get('link',''), item.get('summary',''), item.get('cve_id',''), item.get('cvss_score',''), item.get('severity','')])

        logger.info(f"✅ Raport wygenerowany: {report_filename}")
        logger.info(f"📁 JSON: {json_filename}")
        logger.info(f"📁 CSV:  {csv_filename}")
        return report_filename


# -------------------------------------------
# main
# -------------------------------------------

def main():
    import subprocess

    print("🛡️ Rozszerzony System Monitorowania Cyberbezpieczeństwa — PRO (Matrix)")
    print("=" * 80)

    monitor = AdvancedCyberSecurityMonitor()

    # (opcjonalnie) ręczne ustawienie kluczy — NIE commitować prawdziwych!
    # monitor.set_api_key('virustotal', 'YOUR_VT_KEY')
    # monitor.set_api_key('shodan', 'YOUR_SHODAN_KEY')
    # monitor.set_api_key('alienvault', 'YOUR_OTX_KEY')

    try:
        monitor.collect_all_data()
        report_file = monitor.generate_enhanced_report()

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

