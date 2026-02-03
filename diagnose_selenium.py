# Selenium Diagnostic Script
# Run this to check what's wrong with Selenium import

print("=" * 80)
print("SELENIUM DIAGNOSTIC")
print("=" * 80)
print()

# Test 1: Check if selenium is installed
print("Test 1: Checking if selenium package exists...")
try:
    import selenium
    print(f"✅ Selenium installed: version {selenium.__version__}")
except ImportError as e:
    print(f"❌ Selenium NOT installed: {e}")
    print()
    print("FIX: Run this command:")
    print("pip install selenium")
    exit(1)

print()

# Test 2: Check webdriver import
print("Test 2: Checking webdriver import...")
try:
    from selenium import webdriver
    print("✅ webdriver import successful")
except ImportError as e:
    print(f"❌ webdriver import failed: {e}")
    exit(1)

print()

# Test 3: Check Options import
print("Test 3: Checking Options import...")
try:
    from selenium.webdriver.chrome.options import Options
    print("✅ Options import successful")
except ImportError as e:
    print(f"❌ Options import failed: {e}")
    exit(1)

print()

# Test 4: Check exception imports
print("Test 4: Checking exception imports...")
try:
    from selenium.common.exceptions import WebDriverException, TimeoutException
    print("✅ Exception imports successful")
except ImportError as e:
    print(f"❌ Exception imports failed: {e}")
    exit(1)

print()

# Test 5: Check if ChromeDriver exists
print("Test 5: Checking for ChromeDriver...")
import os
import sys

chromedriver_locations = [
    ".\\chrome-win64\\chromedriver.exe",
    "chromedriver.exe",
    "C:\\chromedriver\\chromedriver.exe"
]

chromedriver_found = False
for location in chromedriver_locations:
    if os.path.exists(location):
        print(f"✅ ChromeDriver found: {location}")
        chromedriver_found = True
        break

if not chromedriver_found:
    print("⚠️  ChromeDriver not found in common locations")
    print("   Download from: https://googlechromelabs.github.io/chrome-for-testing/")

print()

# Test 6: Try to start Chrome
print("Test 6: Trying to start Chrome with Selenium...")
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    
    options = Options()
    options.add_argument('--headless=new')
    options.add_argument('--no-sandbox')
    
    print("   Starting Chrome...")
    driver = webdriver.Chrome(options=options)
    print("   ✅ Chrome started successfully!")
    
    print("   Loading test page...")
    driver.get('http://example.com')
    print(f"   ✅ Loaded: {driver.current_url}")
    
    driver.quit()
    print("   ✅ Chrome closed successfully")
    
except Exception as e:
    print(f"   ❌ Failed to start Chrome: {type(e).__name__}")
    print(f"   Error: {str(e)[:200]}")
    print()
    print("   Common causes:")
    print("   1. ChromeDriver version doesn't match Chrome browser version")
    print("   2. ChromeDriver not in PATH or script directory")
    print("   3. Chrome browser not installed")
    exit(1)

print()
print("=" * 80)
print("✅ ALL TESTS PASSED - Selenium is working correctly!")
print("=" * 80)
print()
print("If your script still says Selenium is not available,")
print("there might be a different Python environment being used.")
print()
print("Current Python:")
print(f"  Path: {sys.executable}")
print(f"  Version: {sys.version}")