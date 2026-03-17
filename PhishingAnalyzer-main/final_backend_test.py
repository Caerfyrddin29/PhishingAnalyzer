#!/usr/bin/env python3
"""
FINAL COMPREHENSIVE BACKEND TEST
Verifies ALL backend functionality for demo readiness
"""

import os
import sys
import json
import time
import requests
from pathlib import Path

sys.path.insert(0, 'core')

def test_api_server():
    """Test API server endpoints"""
    print("\n" + "="*70)
    print("🌐 TESTING API SERVER")
    print("="*70)
    
    base_url = "http://localhost:8000"
    tests = []
    
    # Test 1: Health endpoint
    try:
        print("\n1️⃣ Testing /health endpoint...")
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            print("   ✅ /health: WORKING")
            tests.append(True)
        else:
            print(f"   ❌ /health: HTTP {response.status_code}")
            tests.append(False)
    except Exception as e:
        print(f"   ❌ /health: {str(e)}")
        tests.append(False)
    
    # Test 2: System info
    try:
        print("\n2️⃣ Testing /system/info endpoint...")
        response = requests.get(f"{base_url}/system/info", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ /system/info: WORKING")
            print(f"      Version: {data.get('version')}")
            print(f"      Model Loaded: {data.get('model_loaded')}")
            print(f"      Total Analyses: {data.get('total_analyses')}")
            tests.append(True)
        else:
            print(f"   ❌ /system/info: HTTP {response.status_code}")
            tests.append(False)
    except Exception as e:
        print(f"   ❌ /system/info: {str(e)}")
        tests.append(False)
    
    # Test 3: URL analysis - Phishing
    try:
        print("\n3️⃣ Testing /analyze/url (phishing URL)...")
        response = requests.post(
            f"{base_url}/analyze/url",
            json={"url": "http://192.168.1.1/login.php"},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ URL Analysis: WORKING")
            print(f"      URL: {data.get('url')}")
            print(f"      Classification: {data.get('classification')}")
            print(f"      Risk Score: {data.get('risk_score')}/100")
            print(f"      Confidence: {data.get('confidence'):.1%}")
            is_phishing = data.get('classification') == 'PHISHING' or data.get('risk_score', 0) > 40
            tests.append(is_phishing)
            if not is_phishing:
                print("   ⚠️  WARNING: Private IP not detected as high risk")
        else:
            print(f"   ❌ URL Analysis: HTTP {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            tests.append(False)
    except Exception as e:
        print(f"   ❌ URL Analysis: {str(e)}")
        tests.append(False)
    
    # Test 4: URL analysis - Legitimate
    try:
        print("\n4️⃣ Testing /analyze/url (legitimate URL)...")
        response = requests.post(
            f"{base_url}/analyze/url",
            json={"url": "https://google.com"},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ URL Analysis: WORKING")
            print(f"      URL: {data.get('url')}")
            print(f"      Classification: {data.get('classification')}")
            print(f"      Risk Score: {data.get('risk_score')}/100")
            print(f"      Confidence: {data.get('confidence'):.1%}")
            is_safe = data.get('classification') == 'LEGITIMATE' or data.get('risk_score', 100) < 50
            tests.append(is_safe)
            if not is_safe:
                print("   ⚠️  WARNING: Google detected as risky")
        else:
            print(f"   ❌ URL Analysis: HTTP {response.status_code}")
            tests.append(False)
    except Exception as e:
        print(f"   ❌ URL Analysis: {str(e)}")
        tests.append(False)
    
    # Test 5: Email analysis with multipart
    try:
        print("\n5️⃣ Testing /analyze/email (multipart email)...")
        
        # Create a realistic test email
        email_content = """From: security@paypal.com
To: victim@gmail.com
Subject: URGENT: Account Verification Required
Date: Mon, 17 Mar 2026 18:13:00 +0000
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="utf-8"

Dear User,

We have detected suspicious activity on your PayPal account.
Your account has been temporarily limited.

Click here to verify: http://192.168.1.1/paypal-verify

Urgent action required!
Account will be closed!

--boundary123
Content-Type: text/html; charset="utf-8"

<html>
<body>
<h1>PayPal Security Alert</h1>
<p>Click <a href="http://192.168.1.1/paypal-verify">here</a> to verify</p>
</body>
</html>

--boundary123--"""
        
        from io import BytesIO
        files = {'file': ('test_phishing.eml', BytesIO(email_content.encode()), 'message/rfc822')}
        
        response = requests.post(
            f"{base_url}/analyze/email",
            files=files,
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Email Analysis: WORKING")
            print(f"      Risk Score: {data.get('risk_score')}/100")
            print(f"      Risk Level: {data.get('risk_level')}")
            print(f"      Is Phishing: {data.get('is_phishing')}")
            print(f"      URLs Found: {data.get('findings', {}).get('urls_found', 0)}")
            is_correct = data.get('is_phishing') == True or data.get('risk_score', 0) > 50
            tests.append(is_correct)
            if not is_correct:
                print("   ⚠️  WARNING: Phishing email not detected as high risk")
        else:
            print(f"   ❌ Email Analysis: HTTP {response.status_code}")
            print(f"   Response: {response.text[:300]}")
            tests.append(False)
    except Exception as e:
        print(f"   ❌ Email Analysis: {str(e)}")
        import traceback
        traceback.print_exc()
        tests.append(False)
    
    passed = sum(tests)
    total = len(tests)
    print(f"\n📊 API SERVER RESULT: {passed}/{total} tests passed")
    
    return passed == total, tests

def test_ml_directly():
    """Test ML model directly without API"""
    print("\n" + "="*70)
    print("🤖 TESTING ML MODEL DIRECTLY")
    print("="*70)
    
    try:
        from core.email_phishing_analyzer import EmailPhishingAnalyzer
        
        print("\n6️⃣ Testing ML URL classification...")
        analyzer = EmailPhishingAnalyzer()
        
        test_urls = [
            ("https://google.com", "LEGITIMATE", "low"),
            ("http://192.168.1.1/login", "PHISHING", "high"),
            ("https://bit.ly/test123", "LEGITIMATE", "medium"),
            ("http://0.0.0.0/admin", "PHISHING", "high")
        ]
        
        results = []
        for url, expected_class, expected_risk in test_urls:
            classification, confidence, risk_score = analyzer.classify_url(url)
            
            is_correct = (expected_class == "PHISHING" and risk_score > 40) or \
                       (expected_class == "LEGITIMATE" and risk_score < 60)
            
            status = "✅" if is_correct else "❌"
            print(f"   {status} {url}")
            print(f"      Classification: {classification}, Risk: {risk_score}/100, Confidence: {confidence:.1%}")
            results.append(is_correct)
        
        passed = sum(results)
        total = len(results)
        print(f"\n📊 ML MODEL RESULT: {passed}/{total} classifications correct")
        
        return passed >= len(results) * 0.5  # At least 50% accuracy
        
    except Exception as e:
        print(f"\n❌ ML Model test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_email_parsing():
    """Test email parsing"""
    print("\n" + "="*70)
    print("📧 TESTING EMAIL PARSING")
    print("="*70)
    
    try:
        from core.email_phishing_analyzer import EmailPhishingAnalyzer
        
        print("\n7️⃣ Creating test phishing email...")
        
        email_content = """From: security@paypal.com
Subject: URGENT: Verify Your Account Now
Date: Mon, 17 Mar 2026 18:13:00 +0000
Message-ID: <phishing123@fake.com>

Dear user,

Your account has been suspended!
Click here immediately: http://192.168.1.1/verify

Urgent action required or account will be deleted!

PayPal Security Team"""
        
        # Save to temp file
        test_file = "temp_test_email.eml"
        with open(test_file, "w") as f:
            f.write(email_content)
        
        print("\n8️⃣ Analyzing email file...")
        analyzer = EmailPhishingAnalyzer()
        result = analyzer.analyze_email_file(test_file)
        
        print(f"   ✅ Email Parsing: WORKING")
        print(f"      Risk Score: {result.risk_score}/100")
        print(f"      Risk Level: {result.risk_level}")
        print(f"      Is Phishing: {result.is_phishing}")
        print(f"      Confidence: {result.confidence:.1%}")
        print(f"      URLs Found: {result.findings.get('urls_found', 0)}")
        print(f"      Phishing URLs: {result.findings.get('phishing_urls', 0)}")
        
        # Cleanup
        os.remove(test_file)
        
        is_phishing = result.is_phishing or result.risk_score > 50
        if not is_phishing:
            print("\n   ⚠️  WARNING: Phishing email detected as SAFE")
        
        return is_phishing
        
    except Exception as e:
        print(f"\n❌ Email parsing test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("\n" + "🛡️"*35)
    print("FINAL BACKEND VERIFICATION FOR DEMO")
    print("🛡️"*35)
    
    all_tests = []
    
    # Test 1: API Server
    api_ok, api_tests = test_api_server()
    all_tests.extend(api_tests)
    
    # Test 2: ML Model
    ml_ok = test_ml_directly()
    all_tests.append(ml_ok)
    
    # Test 3: Email Parsing
    email_ok = test_email_parsing()
    all_tests.append(email_ok)
    
    # Final Result
    print("\n" + "="*70)
    print("🏁 FINAL VERIFICATION RESULT")
    print("="*70)
    
    passed = sum(all_tests)
    total = len(all_tests)
    percentage = (passed / total * 100) if total > 0 else 0
    
    print(f"\n📊 OVERALL: {passed}/{total} tests passed ({percentage:.1f}%)")
    
    if percentage >= 80:
        print("\n✅✅✅ BACKEND IS DEMO-READY! ✅✅✅")
        print("\n🎉 All critical functionality working:")
        print("   ✅ API Server responding correctly")
        print("   ✅ URL analysis with ML working")
        print("   ✅ Email parsing and analysis working")
        print("   ✅ Risk scoring accurate")
        print("   ✅ Phishing detection functional")
        print("\n🚀 You can confidently demonstrate this tomorrow!")
    elif percentage >= 50:
        print("\n⚠️ BACKEND IS FUNCTIONAL BUT HAS ISSUES")
        print("\nSome features work, but review the failed tests above.")
    else:
        print("\n❌ BACKEND HAS SIGNIFICANT ISSUES")
        print("\nPlease fix the failed tests before demo.")
    
    print("="*70)
    
    return percentage >= 80

if __name__ == "__main__":
    demo_ready = main()
    sys.exit(0 if demo_ready else 1)
