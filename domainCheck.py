#!/usr/bin/env python3
"""
Domain Validation and Threat Scoring Tool - CTI Enhanced Version with Selenium
SOC Analyst - Domain Investigation Automation with Advanced Threat Intelligence
"""

import json
import re
import argparse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
import sys
import socket

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] ERROR: dnspython library not found!", file=sys.stderr)
    print("[!] Please install it with: pip install dnspython", file=sys.stderr)
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] WARNING: requests library not found. ASN lookups will be limited.", file=sys.stderr)
    print("[!] Install with: pip install requests", file=sys.stderr)
    requests = None

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    print("[!] INFO: python-whois not installed. Domain age checks disabled.", file=sys.stderr)
    print("[!] Install with: pip install python-whois", file=sys.stderr)
    WHOIS_AVAILABLE = False

# Selenium for JavaScript redirect detection (optional)
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import WebDriverException, TimeoutException
    SELENIUM_AVAILABLE = True
except ImportError:
    print("[!] INFO: selenium not installed. JavaScript redirect detection disabled.", file=sys.stderr)
    print("[!] Install with: pip install selenium", file=sys.stderr)
    print("[!] Also requires ChromeDriver: https://googlechromelabs.github.io/chrome-for-testing/", file=sys.stderr)
    SELENIUM_AVAILABLE = False

@dataclass
class DomainRecord:
    """Store DNS records for a domain"""
    domain: str
    a_records: List[str]
    aaaa_records: List[str]
    ns_records: List[str]
    mx_records: List[str]
    txt_records: List[str]
    timestamp: str

@dataclass
class HostingIntelligence:
    """Advanced hosting context and threat intelligence"""
    asn: str
    provider: str
    country: str
    hosting_type: str  # cloud_vps, dedicated, residential, bulletproof
    tier: str  # tier1_cloud, tier2_vps, tier3_budget, bulletproof
    reputation_score: int  # 0-10 (0=clean, 10=known malicious)
    abuse_indicators: List[str]
    cti_notes: List[str]

@dataclass
class ThreatIntelligence:
    """Store threat intelligence data"""
    email_capable: bool
    spf_present: bool
    dkim_present: bool
    dmarc_present: bool
    spf_misconfigured: bool
    dmarc_misconfigured: bool
    hosting_intel: List[HostingIntelligence]
    cdn_detected: bool
    suspicious_hosting: bool
    suspicious_hosting_score: int  # 0-10 scoring
    suspicious_hosting_reasoning: str
    domain_age_days: Optional[int] = None
    is_newly_registered: bool = False

@dataclass
class DomainScore:
    """Store scoring information"""
    total_score: int
    priority: str
    score_breakdown: Dict[str, int]
    indicators: List[str]
    cti_assessment: str = ""


@dataclass
class DomainAnalysis:
    """Complete domain analysis result"""
    dns_records: DomainRecord
    threat_intel: ThreatIntelligence
    score: DomainScore


# ============================================================================
# SELENIUM REDIRECT DETECTION - Standalone Function
# ============================================================================

def check_redirect_selenium(domain: str, verbose: bool = False) -> dict:
        """
        STEALTH version with anti-detection measures
        Tries to evade bot detection by mimicking real browser behavior
        """
        if not SELENIUM_AVAILABLE:
            return {
                'suspicious': False,
                'final_url': f"http://{domain}",
                'final_domain': domain,
                'anti_bot': False,
                'bouncy': False,
                'reasons': [],
                'chain': [],
                'clicked_button': False,
                'error': "Selenium not installed"
            }
        
        try:
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from urllib.parse import urlparse, parse_qs
            import time
            import random
        except ImportError as e:
            return {
                'suspicious': False,
                'final_url': f"http://{domain}",
                'final_domain': domain,
                'anti_bot': False,
                'bouncy': False,
                'reasons': [],
                'chain': [],
                'clicked_button': False,
                'error': f"Import error: {e}"
            }
        
        SUSPICIOUS_PATHS = ['bouncy', 'redirect', 'gate', 'click', 'go', 'forward', 'redir', 'out', 'jump', 'link', 'tracker']
        
        try:
            if verbose:
                print(f"[*] Selenium STEALTH: Checking {domain}", file=sys.stderr)
            
            # STEALTH MEASURE 1: More realistic Chrome options
            options = Options()
            options.add_argument('--headless=new')  # New headless mode (harder to detect)
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-blink-features=AutomationControlled')  # Hide automation
            
            # STEALTH MEASURE 2: Realistic window size
            options.add_argument('--window-size=1920,1080')
            
            # STEALTH MEASURE 3: Real user agent (current Chrome on Windows)
            options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')
            
            # STEALTH MEASURE 4: Accept language
            options.add_argument('--lang=en-US,en')
            
            # STEALTH MEASURE 5: Disable automation flags
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option('useAutomationExtension', False)
            
            driver = webdriver.Chrome(options=options)
            
            # STEALTH MEASURE 6: Override navigator.webdriver
            driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                'source': '''
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined
                    });
                    
                    // Add missing properties that real browsers have
                    window.chrome = {
                        runtime: {}
                    };
                    
                    // Fake plugins
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [1, 2, 3, 4, 5]
                    });
                    
                    // Fake languages
                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['en-US', 'en']
                    });
                '''
            })
            
            driver.set_page_load_timeout(20)
            
            url = f"http://{domain}" if not domain.startswith('http') else domain
            
            anti_bot_detected = False
            clicked_button = False
            url_chain = [url]
            
            try:
                driver.get(url)
                
                # STEALTH MEASURE 7: Random human-like delay
                time.sleep(random.uniform(2.5, 4.0))
                
                current_url = driver.current_url
                if current_url != url:
                    url_chain.append(current_url)
                
                if verbose:
                    print(f"[*] Selenium STEALTH: After load: {current_url[:80]}...", file=sys.stderr)
                
                # STEALTH MEASURE 8: Scroll page (human behavior)
                try:
                    driver.execute_script("window.scrollTo(0, 300);")
                    time.sleep(random.uniform(0.5, 1.0))
                except:
                    pass
                
                # Try to find and click buttons
                button_selectors = [
                    "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'continue')]",
                    "//a[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'continue')]",
                    "//button[contains(@class, 'continue')]",
                    "//input[@type='submit']",
                    "//button[@type='submit']",
                    "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'proceed')]",
                    "//button",
                ]
                
                for selector in button_selectors:
                    try:
                        element = WebDriverWait(driver, 2).until(
                            EC.presence_of_element_located((By.XPATH, selector))
                        )
                        
                        if element.is_displayed():
                            # STEALTH MEASURE 9: Move mouse to element (simulate human)
                            try:
                                from selenium.webdriver.common.action_chains import ActionChains
                                actions = ActionChains(driver)
                                actions.move_to_element(element).perform()
                                time.sleep(random.uniform(0.3, 0.7))
                            except:
                                pass
                            
                            button_text = element.text[:50] if element.text else element.get_attribute('value')
                            if verbose:
                                print(f"[*] Selenium STEALTH: Found button: {button_text}", file=sys.stderr)
                            
                            # Click!
                            element.click()
                            clicked_button = True
                            
                            if verbose:
                                print(f"[*] Selenium STEALTH: Clicked!", file=sys.stderr)
                            
                            # STEALTH MEASURE 10: Wait like a human would
                            time.sleep(random.uniform(4.0, 6.0))
                            
                            new_url = driver.current_url
                            if new_url != url_chain[-1]:
                                url_chain.append(new_url)
                                if verbose:
                                    print(f"[*] Selenium STEALTH: After click: {new_url[:80]}...", file=sys.stderr)
                            
                            break
                            
                    except:
                        continue
                
                final_url = driver.current_url
                if final_url not in url_chain:
                    url_chain.append(final_url)
                    
            except (WebDriverException, TimeoutException) as e:
                error_msg = str(e)
                if 'ERR_CONNECTION_CLOSED' in error_msg or 'ERR_CONNECTION_REFUSED' in error_msg:
                    anti_bot_detected = True
                    final_url = url
                    if verbose:
                        print(f"[!] Selenium STEALTH: Still detected (advanced evasion)", file=sys.stderr)
                else:
                    raise
            
            driver.quit()
            
            # Analyze
            initial_domain = urlparse(url).netloc.lower()
            final_domain = urlparse(final_url).netloc.lower()
            final_path = urlparse(final_url).path.lower()
            final_params = parse_qs(urlparse(final_url).query)
            
            suspicious = False
            reasons = []
            bouncy_detected = False
            
            if anti_bot_detected:
                suspicious = True
                reasons.append("Anti-bot protection (ADVANCED EVASION)")
            
            if final_domain != initial_domain and not anti_bot_detected:
                suspicious = True
                reasons.append(f"Domain changed to {final_domain}")
            
            for pattern in SUSPICIOUS_PATHS:
                if pattern in final_path:
                    suspicious = True
                    bouncy_detected = True
                    reasons.append(f"Redirect infrastructure: {pattern}")
                    break
            
            for param, values in final_params.items():
                for value in values:
                    if len(value) > 100:
                        suspicious = True
                        reasons.append("Obfuscated parameters")
                        break
            
            if any(p in final_url.lower() for p in ['redirecttype', 'redirect', 'goto', 'continue']):
                suspicious = True
                reasons.append("Redirect parameters")
            
            if final_path not in ['/', ''] and initial_domain == final_domain and not anti_bot_detected:
                suspicious = True
                reasons.append(f"Internal redirect: {final_path}")
            
            if len(url_chain) > 2:
                suspicious = True
                reasons.append(f"Multi-hop redirect ({len(url_chain)} hops)")
            
            if verbose and suspicious:
                print(f"[!] Selenium STEALTH: Suspicious - {', '.join(reasons)}", file=sys.stderr)
            
            if verbose and clicked_button:
                print(f"[✓] Selenium STEALTH: Successfully bypassed button!", file=sys.stderr)
            
            return {
                'suspicious': suspicious,
                'final_url': final_url,
                'final_domain': final_domain,
                'anti_bot': anti_bot_detected,
                'bouncy': bouncy_detected,
                'reasons': reasons,
                'chain': url_chain,
                'clicked_button': clicked_button
            }
            
        except Exception as e:
            if verbose:
                print(f"[!] Selenium STEALTH error: {type(e).__name__}", file=sys.stderr)
            return {
                'suspicious': False,
                'final_url': f"http://{domain}",
                'final_domain': domain,
                'anti_bot': False,
                'bouncy': False,
                'reasons': [],
                'chain': [],
                'clicked_button': False,
                'error': f"Error: {type(e).__name__}"
            }


class DomainValidator:
    """Main class for domain validation and threat analysis with CTI approach"""
    
    # Known CDN/Security providers
    CDN_PROVIDERS = [
        'cloudflare', 'akamai', 'fastly', 'cloudfront', 'incapsula',
        'imperva', 'cdn77', 'stackpath', 'sucuri', 'ddos-guard'
    ]
    
    # Tier 1 Cloud Providers (NEUTRAL - high volume but low abuse density)
    TIER1_CLOUD = {
        'AS16509': 'Amazon AWS',
        'AS8075': 'Microsoft Azure',
        'AS15169': 'Google Cloud',
        'AS13335': 'Cloudflare',
        'AS20940': 'Akamai',
    }
    
    # Tier 2 VPS Providers (MONITOR - legitimate but frequently abused)
    TIER2_VPS = {
        'AS14061': 'DigitalOcean',
        'AS63949': 'Linode',
        'AS20473': 'Vultr (Choopa)',
        'AS24940': 'Hetzner',
        'AS16276': 'OVH',
    }
    
    # Tier 3 Budget Hosting (CAUTION - cheap, easy signup, minimal verification)
    TIER3_BUDGET = {
        'AS47583': 'Hostinger',
        'AS13335': 'Namecheap',
        'AS21100': 'Contabo',
        'AS48854': 'Hostwinds',
    }
    
    # Bulletproof / High-Risk ASNs (HIGH RISK - poor abuse handling)
    BULLETPROOF_ASNS = {
        'AS8100': 'QuadraNet (known bulletproof history)',
        'AS36352': 'ColoCrossing (poor abuse handling)',
        'AS55720': 'Gigabit Hosting (bulletproof reputation)',
        'AS19871': 'Network Solutions (lax policies)',
        'AS62240': 'Clouvider (bulletproof history)',
    }
    
    # Lure keywords for phishing detection
    LURE_KEYWORDS = [
        'login', 'signin', 'sign-in', 'signon',
        'payment', 'pay', 'billing',
        'portal', 
        'support', 'help', 'helpdesk',
        'secure', 'security', 'verification', 'verify', 'validated',
        'update', 'renew', 'confirm', 'activate',
        'account', 'myaccount', 'user',
        'admin', 'administrator',
        'mfa', 'sso', '2fa',
        'vpn', 
        'webmail', 'email',
        'wallet', 'crypto',
        'banking', 'bank',
        'connect'
    ]
    
    # Legitimate domains whitelist - ONLY YOUR LEGITIMATE DOMAINS
    LEGITIMATE_DOMAINS = [
        'revantage.eu',
        'revantage.com'
        # All other domains are considered for threat analysis
    ]
    
    # Protected brands for typosquatting detection
    PROTECTED_BRANDS = [
        'revantage',
        'rivantage', 
        '-revantage',
        'revantage-',
        # Add more variants/typos if you observe them
    ]
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 10
        self.resolver.lifetime = 10
        
    def log(self, message: str):
        """Print verbose logging"""
        if self.verbose:
            print(f"[*] {message}", file=sys.stderr)
    
    def query_dns(self, domain: str, record_type: str) -> List[str]:
        """Query DNS records using dnspython"""
        try:
            self.log(f"Querying {record_type} records for {domain}")
            answers = self.resolver.resolve(domain, record_type)
            
            results = []
            for rdata in answers:
                if record_type == 'MX':
                    results.append(f"{rdata.exchange.to_text()} {rdata.preference}")
                elif record_type == 'TXT':
                    txt_data = b''.join(rdata.strings).decode('utf-8', errors='ignore')
                    results.append(txt_data)
                else:
                    results.append(rdata.to_text())
            
            return results
            
        except dns.resolver.NXDOMAIN:
            self.log(f"Domain {domain} does not exist (NXDOMAIN)")
            return []
        except dns.resolver.NoAnswer:
            self.log(f"No {record_type} records found for {domain}")
            return []
        except dns.resolver.NoNameservers:
            self.log(f"No nameservers available for {domain}")
            return []
        except dns.exception.Timeout:
            self.log(f"Timeout querying {record_type} for {domain}")
            return []
        except Exception as e:
            self.log(f"Error querying {record_type} for {domain}: {str(e)}")
            return []
    
    def get_dns_records(self, domain: str) -> DomainRecord:
        """Fetch all DNS records for a domain"""
        self.log(f"Starting DNS enumeration for {domain}")
        
        return DomainRecord(
            domain=domain,
            a_records=self.query_dns(domain, 'A'),
            aaaa_records=self.query_dns(domain, 'AAAA'),
            ns_records=self.query_dns(domain, 'NS'),
            mx_records=self.query_dns(domain, 'MX'),
            txt_records=self.query_dns(domain, 'TXT'),
            timestamp=datetime.now().isoformat()
        )
    
    def get_domain_age(self, domain: str) -> Optional[int]:
        """Get domain age in days using WHOIS"""
        if not WHOIS_AVAILABLE:
            return None
        
        try:
            self.log(f"Querying WHOIS for {domain}")
            w = whois.whois(domain)
            
            if w.creation_date:
                creation_date = w.creation_date
                # Handle list of dates (some registrars return multiple)
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                age_days = (datetime.now() - creation_date).days
                return age_days
        except Exception as e:
            self.log(f"WHOIS lookup failed for {domain}: {str(e)}")
            return None
        
        return None
    
    def resolve_ip_to_asn(self, ip: str) -> Optional[Dict[str, str]]:
        """Resolve IP to ASN using ipinfo.io API"""
        try:
            if requests is None:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    return {
                        'ip': ip,
                        'asn': 'Unknown',
                        'country': 'Unknown',
                        'provider': hostname
                    }
                except:
                    return {
                        'ip': ip,
                        'asn': 'Unknown',
                        'country': 'Unknown',
                        'provider': 'Unknown'
                    }
            
            try:
                response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
            except Exception as e:
                self.log(f"Request to ipinfo.io failed for {ip}: {type(e).__name__}")
                return {'ip': ip, 'asn': 'Unknown', 'country': 'Unknown', 'provider': 'Unknown (Connection Error)'}
            
            if response.status_code == 200:
                data = response.json()
                org = data.get('org', 'Unknown')
                
                asn = 'Unknown'
                provider = org
                if org.startswith('AS'):
                    parts = org.split(' ', 1)
                    asn = parts[0].replace('AS', '')
                    provider = parts[1] if len(parts) > 1 else org
                
                return {
                    'ip': ip,
                    'asn': asn,
                    'country': data.get('country', 'Unknown'),
                    'provider': provider
                }
            
            return {'ip': ip, 'asn': 'Unknown', 'country': 'Unknown', 'provider': 'Unknown'}
            
        except Exception as e:
            self.log(f"Error resolving ASN for {ip}: {str(e)}")
            return {'ip': ip, 'asn': 'Unknown', 'country': 'Unknown', 'provider': 'Unknown'}
    
    def classify_hosting_tier(self, asn: str, provider: str) -> Tuple[str, str]:
        """Classify hosting into tiers based on ASN"""
        asn_key = f"AS{asn}"
        
        if asn_key in self.TIER1_CLOUD:
            return "tier1_cloud", "cloud_vps"
        elif asn_key in self.TIER2_VPS:
            return "tier2_vps", "cloud_vps"
        elif asn_key in self.TIER3_BUDGET:
            return "tier3_budget", "budget_hosting"
        elif asn_key in self.BULLETPROOF_ASNS:
            return "bulletproof", "bulletproof"
        else:
            # Default classification based on provider name
            provider_lower = provider.lower()
            if any(cloud in provider_lower for cloud in ['aws', 'azure', 'google', 'gcp']):
                return "tier1_cloud", "cloud_vps"
            elif any(vps in provider_lower for vps in ['digital', 'linode', 'vultr', 'ovh']):
                return "tier2_vps", "cloud_vps"
            else:
                return "unknown", "unknown"
    
    def calculate_hosting_reputation(self, asn: str, tier: str, provider: str) -> Tuple[int, List[str]]:
        """
        Calculate hosting reputation score (0-10) based on CTI principles
        0 = Clean/Neutral, 10 = Known Malicious
        """
        reputation = 0
        reasons = []
        
        asn_key = f"AS{asn}"
        
        # Bulletproof hosting = High reputation risk
        if asn_key in self.BULLETPROOF_ASNS:
            reputation = 8
            reasons.append(f"Known bulletproof/lax abuse handling: {self.BULLETPROOF_ASNS[asn_key]}")
        
        # Tier 1 Cloud = Neutral (0-1)
        elif tier == "tier1_cloud":
            reputation = 0
            reasons.append("Tier-1 cloud provider: neutral baseline")
        
        # Tier 2 VPS = Low risk baseline (1-2)
        elif tier == "tier2_vps":
            reputation = 1
            reasons.append("Tier-2 VPS provider: monitor but neutral baseline")
        
        # Tier 3 Budget = Medium baseline (3-4)
        elif tier == "tier3_budget":
            reputation = 3
            reasons.append("Budget hosting: minimal verification, easier abuse")
        
        # Unknown = Neutral (0)
        else:
            reputation = 0
            reasons.append("Unknown provider: neutral baseline")
        
        return reputation, reasons
    
    def analyze_suspicious_hosting(self, hosting_intel: List[HostingIntelligence], 
                                   dns_records: DomainRecord, domain_age: Optional[int]) -> Tuple[bool, int, str]:
        """
        CTI-driven suspicious hosting analysis
        Returns: (is_suspicious, score_0_10, reasoning)
        """
        if not hosting_intel:
            return False, 0, "No hosting information available"
        
        total_suspicion = 0
        cti_signals = []
        
        # Get primary hosting intel
        primary_host = hosting_intel[0]
        base_reputation = primary_host.reputation_score
        
        # === CTI SIGNAL 1: Base ASN Reputation ===
        total_suspicion += base_reputation
        if base_reputation >= 7:
            cti_signals.append(f"High-risk ASN baseline ({base_reputation}/10)")
        elif base_reputation >= 3:
            cti_signals.append(f"Budget/abused-prone hosting ({base_reputation}/10)")
        
        # === CTI SIGNAL 2: Domain Age + Cloud Hosting Correlation ===
        if domain_age is not None and domain_age < 30:
            if primary_host.tier in ["tier2_vps", "tier3_budget"]:
                total_suspicion += 2
                cti_signals.append(f"Newly registered (<30 days) + VPS/budget hosting (+2)")
            elif primary_host.tier == "tier1_cloud" and domain_age < 7:
                total_suspicion += 1
                cti_signals.append(f"Very new domain (<7 days) on cloud (+1)")
        
        # === CTI SIGNAL 3: Missing Email Infrastructure ===
        if not dns_records.mx_records:
            if primary_host.tier != "tier1_cloud":  # MX missing + non-tier1 = suspicious
                total_suspicion += 1
                cti_signals.append("No MX records + non-enterprise hosting (+1)")
        
        # === CTI SIGNAL 4: Weak Email Security Posture ===
        # (Will be evaluated in get_threat_intelligence)
        
        # === CTI SIGNAL 5: CDN Masking (informational) ===
        # Handled separately in CDN detection
        
        # Cap at 10
        total_suspicion = min(total_suspicion, 10)
        
        # Build CTI reasoning
        reasoning_parts = []
        reasoning_parts.append(f"Hosting Context: {primary_host.provider} (ASN {primary_host.asn})")
        reasoning_parts.append(f"Tier Classification: {primary_host.tier}")
        reasoning_parts.append(f"Base Reputation: {base_reputation}/10")
        
        if domain_age is not None:
            reasoning_parts.append(f"Domain Age: {domain_age} days")
        
        if cti_signals:
            reasoning_parts.append("CTI Signals: " + "; ".join(cti_signals))
        
        # Determine if suspicious based on score
        is_suspicious = total_suspicion >= 5
        
        reasoning = " | ".join(reasoning_parts)
        
        return is_suspicious, total_suspicion, reasoning
    
    def analyze_spf(self, txt_records: List[str]) -> Tuple[bool, bool]:
        """Analyze SPF records"""
        spf_records = [r for r in txt_records if 'v=spf1' in r.lower()]
        
        if not spf_records:
            return False, False
        
        spf_text = ' '.join(spf_records).lower()
        misconfigured = False
        
        if len(spf_records) > 1:
            misconfigured = True
        
        if '+all' in spf_text or '?all' in spf_text:
            misconfigured = True
        
        include_count = spf_text.count('include:')
        a_count = spf_text.count(' a') + spf_text.count(' a:')
        mx_count = spf_text.count(' mx')
        
        if (include_count + a_count + mx_count) > 10:
            misconfigured = True
        
        return True, misconfigured
    
    def analyze_dmarc(self, domain: str) -> Tuple[bool, bool]:
        """Check DMARC record"""
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_records = self.query_dns(dmarc_domain, 'TXT')
        
        if not dmarc_records:
            return False, False
        
        dmarc_text = ' '.join(dmarc_records).lower()
        
        if 'v=dmarc1' not in dmarc_text:
            return False, False
        
        misconfigured = False
        if 'p=none' in dmarc_text:
            misconfigured = True
        
        return True, misconfigured
    
    def check_dkim(self, txt_records: List[str]) -> bool:
        """Check for DKIM indicators"""
        dkim_patterns = ['v=dkim1', 'k=rsa', 'p=mig']
        
        for record in txt_records:
            record_lower = record.lower()
            if any(pattern in record_lower for pattern in dkim_patterns):
                return True
        
        return False
    
    def get_threat_intelligence(self, dns_records: DomainRecord) -> ThreatIntelligence:
        """Gather threat intelligence with advanced hosting analysis"""
        self.log(f"Analyzing threat intelligence for {dns_records.domain}")
        
        # Email capability
        email_capable = len(dns_records.mx_records) > 0
        
        # SPF/DKIM/DMARC analysis
        spf_present, spf_misconfigured = self.analyze_spf(dns_records.txt_records)
        dmarc_present, dmarc_misconfigured = self.analyze_dmarc(dns_records.domain)
        dkim_present = self.check_dkim(dns_records.txt_records)
        
        # Domain age
        domain_age = self.get_domain_age(dns_records.domain)
        is_newly_registered = domain_age is not None and domain_age < 30
        
        # Advanced hosting intelligence
        hosting_intel_list = []
        all_ips = dns_records.a_records + dns_records.aaaa_records
        
        for ip in all_ips[:5]:  # Limit to first 5 IPs
            asn_data = self.resolve_ip_to_asn(ip)
            if asn_data and asn_data['asn'] != 'Unknown':
                tier, hosting_type = self.classify_hosting_tier(
                    asn_data['asn'], 
                    asn_data['provider']
                )
                
                reputation, abuse_notes = self.calculate_hosting_reputation(
                    asn_data['asn'],
                    tier,
                    asn_data['provider']
                )
                
                hosting_intel = HostingIntelligence(
                    asn=asn_data['asn'],
                    provider=asn_data['provider'],
                    country=asn_data['country'],
                    hosting_type=hosting_type,
                    tier=tier,
                    reputation_score=reputation,
                    abuse_indicators=[],
                    cti_notes=abuse_notes
                )
                
                hosting_intel_list.append(hosting_intel)
        
        # CDN detection
        cdn_detected = False
        if hosting_intel_list:
            provider_lower = hosting_intel_list[0].provider.lower()
            if any(cdn in provider_lower for cdn in self.CDN_PROVIDERS):
                cdn_detected = True
        
        # CTI-driven suspicious hosting analysis
        suspicious_hosting, sus_score, sus_reasoning = self.analyze_suspicious_hosting(
            hosting_intel_list,
            dns_records,
            domain_age
        )
        
        return ThreatIntelligence(
            email_capable=email_capable,
            spf_present=spf_present,
            dkim_present=dkim_present,
            dmarc_present=dmarc_present,
            spf_misconfigured=spf_misconfigured,
            dmarc_misconfigured=dmarc_misconfigured,
            hosting_intel=hosting_intel_list,
            cdn_detected=cdn_detected,
            suspicious_hosting=suspicious_hosting,
            suspicious_hosting_score=sus_score,
            suspicious_hosting_reasoning=sus_reasoning,
            domain_age_days=domain_age,
            is_newly_registered=is_newly_registered
        )
    
    def check_ct_logs(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check Certificate Transparency logs for recent TLS certificate issuance
        Uses crt.sh API
        Returns: (found, age_description)
        """
        try:
            if requests is None:
                self.log("Requests library not available - skipping CT check")
                return False, "Requests library not installed"
            
            self.log(f"Checking CT logs for {domain}")
            
            # Query crt.sh API
            base_url = "https://crt.sh/"
            params = {
                'q': domain,
                'output': 'json'
            }
            
            self.log(f"CT Query: {base_url} with q={domain}")
            
            try:
                response = requests.get(base_url, params=params, timeout=10, verify=True)
            except requests.exceptions.SSLError as ssl_error:
                self.log(f"SSL error connecting to crt.sh: {ssl_error}")
                return False, "SSL certificate verification error"
            except requests.exceptions.ConnectionError as conn_error:
                self.log(f"Connection error to crt.sh: {conn_error}")
                return False, "Connection error"
            except requests.exceptions.Timeout:
                self.log(f"Timeout connecting to crt.sh")
                return False, "Request timeout"
            except Exception as req_error:
                self.log(f"Request error: {req_error}")
                return False, f"Request error"
            
            self.log(f"CT Response status: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    content_type = response.headers.get('content-type', '')
                    if 'html' in content_type.lower():
                        self.log(f"Response is HTML, not JSON")
                        return False, ""
                    
                    certs = response.json()
                    self.log(f"CT Response parsed: {len(certs) if certs else 0} certificates found")
                except ValueError as json_error:
                    self.log(f"JSON decode error: {json_error}")
                    return False, "JSON parsing failed"
                except Exception as json_error:
                    self.log(f"Failed to parse JSON response: {json_error}")
                    return False, "API response parsing error"
                
                if not certs:
                    self.log(f"No certificates found in CT logs for {domain}")
                    return False, None
                
                # Check for certificates issued in last 90 days
                cutoff_date = datetime.now() - timedelta(days=90)
                recent_certs = []
                
                for cert in certs:
                    try:
                        not_before_str = cert.get('not_before', '')
                        if not_before_str:
                            cert_date = datetime.strptime(not_before_str[:19], '%Y-%m-%dT%H:%M:%S')
                            if cert_date > cutoff_date:
                                recent_certs.append(cert)
                    except Exception as parse_error:
                        self.log(f"Failed to parse certificate date: {not_before_str}")
                        continue
                
                if recent_certs:
                    latest_cert = max(recent_certs, key=lambda x: x.get('not_before', ''))
                    days_ago = (datetime.now() - datetime.strptime(
                        latest_cert['not_before'][:19], '%Y-%m-%dT%H:%M:%S'
                    )).days
                    
                    cert_count = len(certs)
                    recent_count = len(recent_certs)
                    
                    self.log(f"Found {recent_count} recent certificates out of {cert_count} total")
                    return True, f"{days_ago} days ago ({recent_count} recent, {cert_count} total)"
                else:
                    cert_count = len(certs)
                    self.log(f"Found {cert_count} certificates but none recent")
                    return False, f"({cert_count} total, all older than 90 days)"
            else:
                self.log(f"CT API returned status code: {response.status_code}")
                return False, f"API error (status {response.status_code})"
                
        except Exception as e:
            self.log(f"CT log check failed for {domain}: {str(e)}")
            return False, f"Error: {str(e)[:50]}"
        
        return False, None
    
    def check_typosquatting(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check if domain contains 'revantage' or variants but is NOT a legitimate domain
        """
        domain_lower = domain.lower()
        
        # First check: Is this one of our legitimate domains?
        if domain_lower in ['revantage.eu', 'revantage.com']:
            return False, None
        
        # Second check: Does the domain contain any of our protected brands?
        for brand in self.PROTECTED_BRANDS:
            if brand.lower() in domain_lower:
                return True, brand
        
        return False, None
    
    def calculate_score(self, domain: str, dns_records: DomainRecord, 
                       threat_intel: ThreatIntelligence) -> DomainScore:
        """Calculate threat score with exact specification scoring + Selenium redirect detection"""
        score = 0
        breakdown = {}
        indicators = []
        checked_indicators = []
        cti_notes = []
        
        # Check whitelist
        domain_lower = domain.lower()
        is_whitelisted = any(legit in domain_lower for legit in self.LEGITIMATE_DOMAINS)
        
        if is_whitelisted:
            return DomainScore(
                total_score=0,
                priority="LEGITIMATE (Whitelisted)",
                score_breakdown={},
                indicators=["✓ Domain is in legitimate whitelist"],
                cti_assessment="Whitelisted legitimate domain"
            )
        
        # === INDICATOR 1: Lure keywords (+3) ===
        checked_indicators.append("[ ] Lure Keywords")
        lure_found = [kw for kw in self.LURE_KEYWORDS if kw in domain_lower]
        if lure_found:
            score += 3
            breakdown['lure_keywords'] = 3
            indicators.append(f"[+3] Lure keywords: {', '.join(lure_found[:3])}")
            checked_indicators[-1] = f"[✓] Lure Keywords (+3): {', '.join(lure_found[:3])}"
            cti_notes.append(f"Phishing-related keywords in domain name")
        else:
            checked_indicators[-1] = "[ ] Lure Keywords: None detected"
        
        # === INDICATOR 2: MX present / Email-capable (+3) ===
        checked_indicators.append("[ ] Email Capability")
        if threat_intel.email_capable:
            score += 3
            breakdown['email_capable'] = 3
            indicators.append(f"[+3] Email-capable (MX records present)")
            checked_indicators[-1] = f"[✓] Email Capability (+3): MX records present"
            cti_notes.append("Email infrastructure configured (phishing/BEC risk)")
        else:
            checked_indicators[-1] = "[ ] Email Capability: No MX records"
        
        # === INDICATOR 3: Resolves / A or AAAA exists (+2) ===
        checked_indicators.append("[ ] DNS Resolution (A/AAAA)")
        resolves = bool(dns_records.a_records or dns_records.aaaa_records)
        if resolves:
            score += 2
            breakdown['resolves'] = 2
            ip_summary = ', '.join(dns_records.a_records[:2])
            indicators.append(f"[+2] Domain resolves: {ip_summary}")
            checked_indicators[-1] = f"[✓] DNS Resolution (+2): {ip_summary}"
        else:
            checked_indicators[-1] = "[ ] DNS Resolution: NXDOMAIN (not active)"
            cti_notes.append("Domain not resolving - likely defensive registration")
        
        # === INDICATOR 4: CT Certificate / Recent TLS certificate (+2) ===
        checked_indicators.append("[ ] CT Certificate (TLS)")
        ct_found, ct_age = self.check_ct_logs(domain)
        if ct_found:
            score += 2
            breakdown['ct_certificate'] = 2
            indicators.append(f"[+2] Recent TLS certificate: {ct_age}")
            checked_indicators[-1] = f"[✓] CT Certificate (+2): Issued {ct_age}"
            cti_notes.append(f"TLS certificate issued recently ({ct_age})")
        else:
            if ct_age and 'error' not in ct_age.lower():
                checked_indicators[-1] = f"[ ] CT Certificate: {ct_age}"
            else:
                checked_indicators[-1] = "[ ] CT Certificate: No recent certs found"
        
        # === INDICATOR 5: High similarity / Typosquatting (+2) ===
        checked_indicators.append("[ ] Brand Similarity (Typosquatting)")
        is_typosquat, matched_brand = self.check_typosquatting(domain)
        if is_typosquat:
            score += 2
            breakdown['typosquatting'] = 2
            indicators.append(f"[+2] Typosquatting detected: {matched_brand}")
            checked_indicators[-1] = f"[✓] Brand Similarity (+2): Mimics '{matched_brand}'"
            cti_notes.append(f"Domain mimics protected brand: {matched_brand}")
        else:
            checked_indicators[-1] = "[ ] Brand Similarity: No typosquatting detected"
        
        # === INDICATOR 6: Suspicious hosting (+1) ===
        checked_indicators.append("[ ] Suspicious Hosting")
        if threat_intel.suspicious_hosting and resolves:
            score += 1
            breakdown['suspicious_hosting'] = 1
            sus_score = threat_intel.suspicious_hosting_score
            indicators.append(f"[+1] Suspicious hosting (CTI Score: {sus_score}/10)")
            checked_indicators[-1] = f"[✓] Suspicious Hosting (+1): Score {sus_score}/10"
            cti_notes.append(f"Hosting: {threat_intel.suspicious_hosting_reasoning}")
        else:
            if not resolves:
                checked_indicators[-1] = "[ ] Suspicious Hosting: N/A (not resolving)"
            else:
                checked_indicators[-1] = "[ ] Suspicious Hosting: Clean"
        
        # === INDICATOR 7: Suspicious Redirect (Selenium) (+2) ===
        checked_indicators.append("[ ] Redirects (JavaScript)")
        
        if resolves:
            selenium_result = check_redirect_selenium(domain, verbose=self.verbose)
            
            if selenium_result.get('suspicious'):
                score += 2
                breakdown['suspicious_redirect'] = 2
                
                reasons = ', '.join(selenium_result['reasons'][:2])
                indicators.append(f"[+2] Suspicious redirect: {reasons}")
                checked_indicators[-1] = f"[✓] Suspicious Redirect (+2): {selenium_result['final_domain']}"
                
                for reason in selenium_result['reasons']:
                    cti_notes.append(f"Redirect: {reason}")
            else:
                if 'error' not in selenium_result:
                    checked_indicators[-1] = f"[ ] Redirects: Clean"
                else:
                    checked_indicators[-1] = "[ ] Redirects: Not checked (Selenium unavailable)"
        else:
            checked_indicators[-1] = "[ ] Redirects: N/A (not resolving)"
        
        # Additional context (not scored)
        if threat_intel.email_capable:
            if not threat_intel.spf_present:
                indicators.append("    ⚠ No SPF record (spoofing risk)")
            if not threat_intel.dmarc_present:
                indicators.append("    ⚠ No DMARC record")
        
        if threat_intel.is_newly_registered:
            indicators.append(f"    ℹ Domain age: {threat_intel.domain_age_days} days (newly registered)")
        
        if threat_intel.cdn_detected:
            indicators.append("    ℹ CDN detected (origin IP hidden)")
        
        # Determine priority based on exact specification
        if score >= 8:
            priority = "P1 - CRITICAL"
        elif score >= 4:
            priority = "P2 - HIGH"
        else:
            priority = "MONITOR"
        
        # Build CTI assessment
        cti_assessment = " | ".join(cti_notes) if cti_notes else "No significant threat indicators detected"
        
        return DomainScore(
            total_score=score,
            priority=priority,
            score_breakdown=breakdown,
            indicators=checked_indicators + indicators,
            cti_assessment=cti_assessment
        )
    
    def analyze_domain(self, domain: str) -> DomainAnalysis:
        """Perform complete CTI-driven domain analysis"""
        domain = domain.strip().lower()
        
        dns_records = self.get_dns_records(domain)
        threat_intel = self.get_threat_intelligence(dns_records)
        score = self.calculate_score(domain, dns_records, threat_intel)
        
        return DomainAnalysis(
            dns_records=dns_records,
            threat_intel=threat_intel,
            score=score
        )
    
    def format_text_report(self, analysis: DomainAnalysis) -> str:
        """Format CTI-enhanced analysis report"""
        lines = []
        lines.append("=" * 80)
        lines.append(f"DOMAIN THREAT INTELLIGENCE REPORT: {analysis.dns_records.domain}")
        lines.append("=" * 80)
        lines.append(f"Timestamp: {analysis.dns_records.timestamp}")
        lines.append(f"Priority: {analysis.score.priority}")
        lines.append(f"Threat Score: {analysis.score.total_score}/15")
        lines.append("")
        lines.append("Priority Scale: 8+ = P1 (Critical) | 4-7 = P2 (High) | 0-3 = Monitor")
        if analysis.threat_intel.domain_age_days:
            lines.append(f"Domain Age: {analysis.threat_intel.domain_age_days} days")
        lines.append("")
        
        # DNS Query Results
        lines.append("=" * 80)
        lines.append("DNS QUERY RESULTS")
        lines.append("=" * 80)
        lines.append("")
        
        lines.append(f"# dig +short A {analysis.dns_records.domain}")
        if analysis.dns_records.a_records:
            for record in analysis.dns_records.a_records:
                lines.append(f"{record}")
        else:
            lines.append("# No A records found")
        lines.append("")
        
        lines.append(f"# dig +short AAAA {analysis.dns_records.domain}")
        if analysis.dns_records.aaaa_records:
            for record in analysis.dns_records.aaaa_records:
                lines.append(f"{record}")
        else:
            lines.append("# No AAAA records found")
        lines.append("")
        
        lines.append(f"# dig +short NS {analysis.dns_records.domain}")
        if analysis.dns_records.ns_records:
            for record in analysis.dns_records.ns_records:
                lines.append(f"{record}")
        else:
            lines.append("# No NS records found")
        lines.append("")
        
        lines.append(f"# dig +short MX {analysis.dns_records.domain}")
        if analysis.dns_records.mx_records:
            for record in analysis.dns_records.mx_records:
                lines.append(f"{record}")
        else:
            lines.append("# No MX records found")
        lines.append("")
        
        lines.append(f"# dig +short TXT {analysis.dns_records.domain}")
        if analysis.dns_records.txt_records:
            for record in analysis.dns_records.txt_records:
                lines.append(f'"{record}"')
        else:
            lines.append("# No TXT records found")
        lines.append("")
        lines.append("=" * 80)
        lines.append("")
        
        # Certificate Transparency Logs
        lines.append("=" * 80)
        lines.append("CERTIFICATE TRANSPARENCY (CT) LOGS")
        lines.append("=" * 80)
        lines.append("")
        
        ct_found, ct_age = self.check_ct_logs(analysis.dns_records.domain)
        
        if ct_found:
            lines.append(f"✓ TLS/SSL Certificate Found")
            lines.append(f"  Most Recent Certificate: Issued {ct_age}")
            lines.append(f"  Source: crt.sh (Certificate Transparency logs)")
            lines.append("")
            lines.append("  View full certificate history at:")
            lines.append(f"  https://crt.sh/?q={analysis.dns_records.domain}")
        elif ct_age:
            lines.append(f"✗ No recent TLS/SSL certificates found (last 90 days)")
            if "error" in ct_age.lower() or "status" in ct_age.lower():
                lines.append(f"  Note: {ct_age}")
            else:
                lines.append(f"  Note: {ct_age}")
            lines.append("")
            lines.append("  Check full history at:")
            lines.append(f"  https://crt.sh/?q={analysis.dns_records.domain}")
        else:
            lines.append(f"✗ No TLS/SSL certificates found")
            lines.append(f"  This domain has never obtained a certificate.")
            lines.append("")
            lines.append("  Check at:")
            lines.append(f"  https://crt.sh/?q={analysis.dns_records.domain}")
        
        lines.append("")
        lines.append("=" * 80)
        lines.append("")
        
        # CTI-Driven Hosting Intelligence
        lines.append("=" * 80)
        lines.append("HOSTING INTELLIGENCE (CTI-DRIVEN)")
        lines.append("=" * 80)
        
        if analysis.threat_intel.hosting_intel:
            for idx, host in enumerate(analysis.threat_intel.hosting_intel, 1):
                lines.append(f"\nIP #{idx}: {host.provider}")
                lines.append(f"  ASN: AS{host.asn}")
                lines.append(f"  Country: {host.country}")
                lines.append(f"  Tier Classification: {host.tier.replace('_', ' ').title()}")
                lines.append(f"  Hosting Type: {host.hosting_type.replace('_', ' ').title()}")
                lines.append(f"  Base Reputation Score: {host.reputation_score}/10")
                
                if host.cti_notes:
                    lines.append(f"  CTI Assessment:")
                    for note in host.cti_notes:
                        lines.append(f"    • {note}")
        else:
            lines.append("\n  No hosting information available (domain does not resolve)")
        
        lines.append("")
        
        # Suspicious Hosting Analysis
        if analysis.threat_intel.suspicious_hosting:
            lines.append("⚠️ SUSPICIOUS HOSTING DETECTED")
            lines.append(f"  Suspicion Score: {analysis.threat_intel.suspicious_hosting_score}/10")
            lines.append(f"  Analysis: {analysis.threat_intel.suspicious_hosting_reasoning}")
        else:
            lines.append("✓ HOSTING ANALYSIS: No suspicious indicators")
            if analysis.threat_intel.hosting_intel:
                lines.append(f"  Analysis: {analysis.threat_intel.suspicious_hosting_reasoning}")
        
        lines.append("")
        lines.append("=" * 80)
        lines.append("")
        
        # Redirect Analysis (Selenium)
        lines.append("=" * 80)
        lines.append("REDIRECT ANALYSIS")
        lines.append("=" * 80)
        lines.append("")
        
        # Check if redirect detection was performed
        if 'suspicious_redirect' in analysis.score.score_breakdown:
            # Re-run selenium check to get detailed results for report
            resolves = bool(analysis.dns_records.a_records or analysis.dns_records.aaaa_records)
            if resolves:
                selenium_result = check_redirect_selenium(analysis.dns_records.domain, verbose=False)
                
                if selenium_result.get('suspicious'):
                    lines.append("🚨 SUSPICIOUS REDIRECT DETECTED")
                    lines.append("")
                    
                    
                    lines.append("Threat Indicators:")
                    for reason in selenium_result['reasons']:
                        lines.append(f"  • {reason}")
                    lines.append("")
                    
                    if selenium_result.get('anti_bot'):
                        lines.append("⚠️  ANTI-BOT PROTECTION DETECTED:")
                        lines.append("  The site blocked automated browser access.")
                        lines.append("  This behavior is typical of phishing/malware sites hiding from security tools.")
                        lines.append("")
                    
                    if selenium_result.get('bouncy'):
                        lines.append("🚨 REDIRECT INFRASTRUCTURE:")
                        lines.append("  Site uses intermediate redirect pages (bouncy infrastructure).")
                        lines.append("  This is common in phishing campaigns to evade detection.")
                        lines.append("")
                    
                    if selenium_result.get('chain') and len(selenium_result['chain']) > 1:
                        lines.append("Redirect Chain:")
                        for i, url in enumerate(selenium_result['chain'], 1):
                            if i == 1:
                                marker = "INITIAL"
                            elif i == len(selenium_result['chain']):
                                marker = "FINAL ⚠️"
                            else:
                                marker = f"HOP {i-1}"
                            lines.append(f"  {i}. [{marker:9}] {url}")
                        lines.append("")
                    
                    lines.append(f"Initial Domain: {analysis.dns_records.domain}")
                    lines.append(f"Final Domain:   {selenium_result['final_domain']}")
                    
                    if selenium_result['final_domain'] != analysis.dns_records.domain:
                        lines.append("")
                        lines.append(f"⚠️  DOMAIN CHANGED: {analysis.dns_records.domain} → {selenium_result['final_domain']}")
                        lines.append(f"   This is the ACTUAL FINAL DESTINATION!")
                    
                    lines.append("")
                elif 'error' in selenium_result:
                    lines.append(f"⊗ Redirect check not performed: {selenium_result['error']}")
                    lines.append("")
                else:
                    lines.append("✓ No suspicious redirects detected")
                    lines.append(f"  Domain: {selenium_result['final_domain']}")
                    lines.append("")
            else:
                lines.append("⊗ Redirect check skipped (domain does not resolve)")
                lines.append("")
        else:
            lines.append("⊗ No redirect identified.")
            
        
        lines.append("=" * 80)
        lines.append("")
        
        # Email Security
        lines.append("EMAIL SECURITY POSTURE:")
        lines.append(f"  Email Capable: {'YES' if analysis.threat_intel.email_capable else 'NO'}")
        if analysis.threat_intel.email_capable:
            lines.append(f"  SPF: {'Present' if analysis.threat_intel.spf_present else 'Missing'}" +
                        (' (⚠ Misconfigured)' if analysis.threat_intel.spf_misconfigured else ''))
            lines.append(f"  DMARC: {'Present' if analysis.threat_intel.dmarc_present else 'Missing'}" +
                        (' (⚠ Weak)' if analysis.threat_intel.dmarc_misconfigured else ''))
            lines.append(f"  DKIM: {'Detected' if analysis.threat_intel.dkim_present else 'Not detected'}")
        lines.append("")
        
        # Scoring Breakdown
        lines.append("=" * 80)
        lines.append("THREAT INDICATORS CHECKLIST:")
        lines.append("=" * 80)
        
        for indicator in analysis.score.indicators:
            if indicator.startswith("[") and "]" in indicator:
                lines.append(f"  {indicator}")
        
        lines.append("")
        lines.append("THREAT SCORING:")
        if analysis.score.score_breakdown:
            for indicator, points in analysis.score.score_breakdown.items():
                lines.append(f"  {indicator.replace('_', ' ').title()}: +{points}")
            lines.append(f"  {'='*40}")
            lines.append(f"  Total Score: {analysis.score.total_score}/15")
            lines.append(f"  Priority: {analysis.score.priority}")
        
        lines.append("")
        lines.append("ADDITIONAL CONTEXT:")
        for indicator in analysis.score.indicators:
            if not indicator.startswith("[") or "]" not in indicator:
                lines.append(f"  {indicator}")
        
        lines.append("")
        
        lines.append("CTI ANALYST ASSESSMENT:")
        lines.append(f"  {analysis.score.cti_assessment}")
        lines.append("")
        
        lines.append("THREAT INDICATORS:")
        for indicator in analysis.score.indicators:
            lines.append(f"  {indicator}")
        
        lines.append("")
        lines.append("=" * 80)
        
        return '\n'.join(lines)
    
    def format_json_report(self, analysis: DomainAnalysis) -> str:
        """Format analysis as JSON"""
        data = {
            'dns_records': asdict(analysis.dns_records),
            'threat_intelligence': asdict(analysis.threat_intel),
            'score': asdict(analysis.score)
        }
        return json.dumps(data, indent=2)
    
    def format_csv_line(self, analysis: DomainAnalysis) -> str:
        """Format analysis as triage sheet CSV line - 7 indicators"""
        lure = "✓" if 'lure_keywords' in analysis.score.score_breakdown else "☐"
        email = "✓" if 'email_capable' in analysis.score.score_breakdown else "☐"
        resolves = "✓" if 'resolves' in analysis.score.score_breakdown else "☐"
        ct_cert = "✓" if 'ct_certificate' in analysis.score.score_breakdown else "☐"
        typosquat = "✓" if 'typosquatting' in analysis.score.score_breakdown else "☐"
        sus_host = "✓" if 'suspicious_hosting' in analysis.score.score_breakdown else "☐"
        sus_redirect = "✓" if 'suspicious_redirect' in analysis.score.score_breakdown else "☐"
        
        return f"{analysis.dns_records.domain}," \
               f"{analysis.score.total_score}," \
               f"{analysis.score.priority}," \
               f"{lure}," \
               f"{email}," \
               f"{resolves}," \
               f"{ct_cert}," \
               f"{typosquat}," \
               f"{sus_host}," \
               f"{sus_redirect}"


def main():
    parser = argparse.ArgumentParser(
        description='Domain Validation and Threat Scoring Tool - CTI Enhanced with Selenium',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
CTI-Enhanced Features:
  - 7 threat indicators (0-15 points scoring)
  - Selenium-based JavaScript redirect detection
  - Anti-bot protection detection
  - Bouncy infrastructure detection
  - Tier-based ASN classification
  - Advanced hosting intelligence

Examples:
  python domain_validator_WITH_SELENIUM.py -d suspicious-domain.com
  python domain_validator_WITH_SELENIUM.py -f domains.txt -o individual --save index.txt
        """
    )
    
    parser.add_argument('-f', '--file', help='Input file with domains (one per line)')
    parser.add_argument('-d', '--domain', help='Single domain to analyze')
    parser.add_argument('-o', '--output', choices=['text', 'json', 'csv', 'individual'], 
                       default='text', help='Output format')
    parser.add_argument('--save', help='Save output to file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not args.file and not args.domain:
        parser.error("Either --file or --domain must be specified")
    
    validator = DomainValidator(verbose=args.verbose)
    
    # Collect domains
    domains = []
    if args.domain:
        domains.append(args.domain)
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"[!] ERROR: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    
    # Analyze domains
    results = []
    output_lines = []
    individual_files = []
    
    if args.output == 'csv':
        output_lines.append("Domain,Score,Priority,Lure_Keywords,Email_Capable,Resolves,CT_Certificate,Typosquatting,Suspicious_Hosting,Suspicious_Redirect")
    
    if args.output == 'individual':
        import os
        output_dir = 'reports'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        print(f"[*] Creating CTI reports in: {output_dir}/", file=sys.stderr)
    
    for i, domain in enumerate(domains, 1):
        print(f"\n[{i}/{len(domains)}] Analyzing: {domain}", file=sys.stderr)
        
        try:
            analysis = validator.analyze_domain(domain)
            results.append(analysis)
            
            if args.output == 'text':
                output_lines.append(validator.format_text_report(analysis))
            elif args.output == 'json':
                output_lines.append(validator.format_json_report(analysis))
            elif args.output == 'csv':
                output_lines.append(validator.format_csv_line(analysis))
            elif args.output == 'individual':
                safe_domain = domain.replace('.', '_').replace('/', '_')
                filename = f"{output_dir}/{safe_domain}_cti_report.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(validator.format_text_report(analysis))
                individual_files.append(filename)
                print(f"    → Saved: {filename}", file=sys.stderr)
                
        except Exception as e:
            print(f"[!] ERROR analyzing {domain}: {str(e)}", file=sys.stderr)
            import traceback
            if args.verbose:
                traceback.print_exc()
            continue
    
    # Output results
    if args.output == 'individual':
        print(f"\n[+] Generated {len(individual_files)} CTI report files", file=sys.stderr)
        if args.save:
            with open(args.save, 'w', encoding='utf-8') as f:
                f.write("CTI-ENHANCED DOMAIN ANALYSIS INDEX\n")
                f.write("=" * 80 + "\n\n")
                for analysis in results:
                    f.write(f"{analysis.dns_records.domain}\n")
                    f.write(f"  Priority: {analysis.score.priority}\n")
                    f.write(f"  Score: {analysis.score.total_score}/15\n")
                    f.write(f"  Suspicious Hosting: {analysis.threat_intel.suspicious_hosting_score}/10\n")
                    f.write(f"  Report: domain_reports/{analysis.dns_records.domain.replace('.', '_')}_cti_report.txt\n\n")
            print(f"[+] Index saved to: {args.save}", file=sys.stderr)
    else:
        output_text = '\n'.join(output_lines)
        
        if args.save:
            with open(args.save, 'w', encoding='utf-8') as f:
                f.write(output_text)
            print(f"\n[+] Results saved to: {args.save}", file=sys.stderr)
        else:
            print("\n" + output_text)
    
    # Summary
    print(f"\n{'='*80}", file=sys.stderr)
    print(f"CTI ANALYSIS COMPLETE", file=sys.stderr)
    print(f"{'='*80}", file=sys.stderr)
    print(f"Total domains analyzed: {len(results)}", file=sys.stderr)
    
    p1_count = sum(1 for r in results if 'P1' in r.score.priority)
    p2_count = sum(1 for r in results if 'P2' in r.score.priority)
    monitor_count = sum(1 for r in results if 'MONITOR' in r.score.priority)
    
    print(f"  P1 (Critical): {p1_count}", file=sys.stderr)
    print(f"  P2 (High): {p2_count}", file=sys.stderr)
    print(f"  Monitor: {monitor_count}", file=sys.stderr)


if __name__ == '__main__':
    main()