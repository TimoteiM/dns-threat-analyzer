#!/usr/bin/env python3
"""
Smart Redirect Detector - Works despite anti-bot protection
Detects suspicious patterns even if site blocks automation
"""
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
import time
from urllib.parse import urlparse, parse_qs

TEST_DOMAIN = "groupprogram.payments-revantage.ph"

print("=" * 80)
print(f"Smart Redirect Detection: {TEST_DOMAIN}")
print("=" * 80)
print()

# Suspicious path patterns (common phishing infrastructure)
SUSPICIOUS_PATHS = [
    'bouncy', 'redirect', 'gate', 'click', 'go', 'forward',
    'redir', 'out', 'away', 'jump', 'link', 'tracker'
]

# Suspicious parameter patterns
SUSPICIOUS_PARAMS = [
    'redirect', 'url', 'goto', 'target', 'dest', 'continue',
    'next', 'return', 'ref', 'redir'
]

chrome_options = Options()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--disable-gpu')
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--ignore-certificate-errors')
chrome_options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64)')

print("Starting browser...")

try:
    driver = webdriver.Chrome(options=chrome_options)
    driver.set_page_load_timeout(15)
    
    if not TEST_DOMAIN.startswith('http'):
        initial_url = f"http://{TEST_DOMAIN}"
    else:
        initial_url = TEST_DOMAIN
    
    print(f"Testing: {initial_url}")
    print()
    
    # Try to load page
    try:
        driver.get(initial_url)
        time.sleep(3)  # Wait for any immediate redirects
        
        final_url = driver.current_url
        connection_successful = True
        
    except WebDriverException as e:
        error_msg = str(e)
        connection_successful = False
        
        if 'ERR_CONNECTION_CLOSED' in error_msg:
            print("⚠️  Connection closed by remote site")
            print("   → Site detected automated browser (anti-bot protection)")
            print("   → This itself is SUSPICIOUS (phishing sites hide from bots)")
            print()
            
            # Even though connection failed, this is suspicious
            final_url = initial_url
            
        else:
            raise
    
    # Analyze what we got
    initial_domain = urlparse(initial_url).netloc.lower()
    final_domain = urlparse(final_url).netloc.lower()
    final_path = urlparse(final_url).path.lower()
    final_params = parse_qs(urlparse(final_url).query)
    
    print("=" * 80)
    print("ANALYSIS:")
    print("=" * 80)
    print(f"Initial:  {initial_url}")
    print(f"Final:    {final_url if connection_successful else '[Connection blocked]'}")
    print()
    
    # Detect suspicious indicators
    is_suspicious = False
    reasons = []
    score = 0
    
    # Indicator 1: Anti-bot protection (connection closed)
    if not connection_successful:
        is_suspicious = True
        reasons.append("⚠️  Anti-bot protection detected (connection blocked)")
        reasons.append("   Phishing sites often block automated access")
        score += 2
    
    # Indicator 2: Domain changed
    if connection_successful and final_domain != initial_domain:
        is_suspicious = True
        reasons.append(f"🚨 Domain changed: {initial_domain} → {final_domain}")
        score += 2
    
    # Indicator 3: Suspicious path
    if connection_successful:
        for pattern in SUSPICIOUS_PATHS:
            if pattern in final_path:
                is_suspicious = True
                reasons.append(f"🚨 Suspicious path pattern: '{pattern}' in {final_path}")
                score += 2
                break
    
    # Indicator 4: Suspicious parameters
    if connection_successful:
        for param in final_params.keys():
            if any(sus in param.lower() for sus in SUSPICIOUS_PARAMS):
                is_suspicious = True
                reasons.append(f"⚠️  Redirect parameter: '{param}'")
                score += 1
                break
    
    # Indicator 5: Long encoded parameters (obfuscation)
    if connection_successful:
        for param, values in final_params.items():
            for value in values:
                if len(value) > 100:  # Very long parameter = encoded redirect
                    is_suspicious = True
                    reasons.append(f"⚠️  Long encoded parameter (obfuscation): {param}={value[:50]}...")
                    score += 1
                    break
    
    # Indicator 6: Path changed but domain same (internal redirect)
    if connection_successful and final_path != '/' and final_path != '':
        if initial_domain == final_domain:
            is_suspicious = True
            reasons.append(f"⚠️  Internal redirect to: {final_path}")
            score += 1
    
    print("=" * 80)
    print("VERDICT:")
    print("=" * 80)
    
    if is_suspicious:
        print(f"🚨 SUSPICIOUS REDIRECT DETECTED! (Score: {score}/10)")
        print()
        print("Indicators:")
        for reason in reasons:
            print(f"  {reason}")
        print()
        print("✅ This would score +2 points in domain validator!")
        print()
        print("Recommendation: INVESTIGATE MANUALLY")
        print(f"  1. Open in VDI: {initial_url}")
        print(f"  2. Monitor where it redirects")
        print(f"  3. Check for credential harvesting")
    else:
        print("✓ No suspicious redirect detected")
    
    driver.quit()
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()

print()
print("=" * 80)
print()
print("KEY INSIGHT:")
print("When phishing sites BLOCK automated tools, that itself is suspicious!")
print("Legitimate sites don't hide from security scanners.")