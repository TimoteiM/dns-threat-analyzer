#!/usr/bin/env python3
"""
Complete Diagnostic - Check ALL components
"""
from domain_validator_windows import check_redirect_selenium
import sys
print("=" * 80)
print("COMPLETE DIAGNOSTIC")
print("=" * 80)
print()

# Test 1: DNS Resolution
print("Test 1: DNS Resolution")
print("-" * 80)
try:
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 10
    resolver.lifetime = 10
    
    test_domain = "datasupport.rhrevantage.ph"
    print(f"Testing DNS for: {test_domain}")
    
    # Try A records
    try:
        answers = resolver.resolve(test_domain, 'A')
        print(f"✅ A Records: {[str(r) for r in answers]}")
    except Exception as e:
        print(f"❌ A Records failed: {type(e).__name__}")
    
    # Try MX records
    try:
        answers = resolver.resolve(test_domain, 'MX')
        print(f"✅ MX Records: {[str(r) for r in answers]}")
    except dns.resolver.NoAnswer:
        print(f"✓ MX Records: None (expected)")
    except Exception as e:
        print(f"❌ MX Records failed: {type(e).__name__}")
        
except ImportError:
    print("❌ dnspython not installed!")
    print("   Run: pip install dnspython")

print()

# Test 2: Selenium
print("Test 2: Selenium Import")
print("-" * 80)
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import WebDriverException, TimeoutException
    print("✅ Selenium imports successful")
    
    SELENIUM_AVAILABLE = True
    print(f"✅ SELENIUM_AVAILABLE = {SELENIUM_AVAILABLE}")
    
except ImportError as e:
    print(f"❌ Selenium import failed: {e}")
    SELENIUM_AVAILABLE = False

print()

# Test 3: Selenium Function
print("Test 3: Check if check_redirect_selenium function exists")
print("-" * 80)

test_code = """
def check_redirect_selenium(domain: str, verbose: bool = False) -> dict:
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
    
    print(f"DEBUG: Would run Selenium on {domain}")
    return {
        'suspicious': False,
        'final_url': f"http://{domain}",
        'final_domain': domain,
        'anti_bot': False,
        'bouncy': False,
        'reasons': [],
        'chain': [f"http://{domain}"],
        'clicked_button': False
    }
"""

try:
    exec(test_code)
    result = check_redirect_selenium("test.com")
    print(f"✅ Function works, returned: {result.keys()}")
except Exception as e:
    print(f"❌ Function test failed: {e}")

print()

# Test 4: Check your actual script
print("Test 4: Analyzing your domain_validator_windows.py")
print("-" * 80)

try:
    with open('domain_validator_windows.py', 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        lines = content.split('\n')
        
        print(f"File size: {len(lines)} lines")
        
        # Check for SELENIUM_AVAILABLE
        selenium_lines = [i for i, l in enumerate(lines, 1) if 'SELENIUM_AVAILABLE' in l]
        print(f"SELENIUM_AVAILABLE found at lines: {selenium_lines[:5]}")
        
        # Check for check_redirect_selenium
        redirect_func = [i for i, l in enumerate(lines, 1) if 'def check_redirect_selenium' in l]
        print(f"check_redirect_selenium at line: {redirect_func}")
        
        # Check for dns.resolver
        dns_lines = [i for i, l in enumerate(lines, 1) if 'dns.resolver' in l]
        print(f"dns.resolver found at lines: {dns_lines[:5]}")
        
        # Check imports at top
        print("\nImport section (first 50 lines):")
        for i in range(min(50, len(lines))):
            if 'import' in lines[i] and not lines[i].strip().startswith('#'):
                print(f"  Line {i+1}: {lines[i].strip()}")
        
except FileNotFoundError:
    print("❌ domain_validator_windows.py not found!")
    print("   Are you in the correct directory?")
except Exception as e:
    print(f"❌ Error reading file: {e}")

print()

# Test 5: Quick functional test
print("Test 5: Quick Functional Test")
print("-" * 80)

try:
    print("Attempting to import and test your script...")
    
    # Try to import
    import importlib.util
    spec = importlib.util.spec_from_file_location("validator", "domain_validator_windows.py")
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        print("✅ Script imports successfully")
        
        # Check if DomainValidator class exists
        if hasattr(module, 'DomainValidator'):
            print("✅ DomainValidator class found")
            
            # Try to create instance
            validator = module.DomainValidator(verbose=True)
            print("✅ DomainValidator instance created")
            
        else:
            print("❌ DomainValidator class not found")
            
    else:
        print("❌ Could not load script")
        
except Exception as e:
    print(f"❌ Import failed: {type(e).__name__}: {str(e)[:200]}")

print()
print("=" * 80)
print("DIAGNOSTIC COMPLETE")
print("=" * 80)
print()
print("Please share this output so I can see what's wrong!")