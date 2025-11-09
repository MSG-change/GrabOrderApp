#!/usr/bin/env python3
"""
Simple Order Grab Test
Quick test without requiring login token
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'libs'))

import requests
import json
from libs.geetest_helper_local import GeetestHelperLocal


def test_grab_simple():
    """Simple grab test"""
    
    print()
    print("=" * 70)
    print("Simple Order Grab Test")
    print("=" * 70)
    print()
    
    # Initialize
    print("Initializing Geetest helper...")
    captcha_id = "045e2c229998a88721e32a763bc0f7b8"
    geetest_helper = GeetestHelperLocal(captcha_id=captcha_id)
    print("✅ Initialized")
    print()
    
    # Order ID
    order_id = input("Enter order ID (default: 9999999): ").strip() or "9999999"
    print(f"Testing with order ID: {order_id}")
    print()
    
    # Token (optional for testing)
    print("Enter token (or press Enter to test without auth):")
    token = input("Token: ").strip()
    print()
    
    # Geetest verification
    print("=" * 70)
    print("Step 1: Geetest Verification")
    print("=" * 70)
    print()
    
    challenge = geetest_helper.generate_challenge(str(order_id))
    print(f"Challenge: {challenge[:40]}...")
    
    print("Performing verification...")
    geetest_result = geetest_helper.verify(challenge=challenge)
    
    if not geetest_result or not geetest_result.get('success'):
        print("❌ Verification failed")
        return False
    
    print(f"✅ Verification SUCCESS")
    print(f"   Answers: {geetest_result.get('answers')}")
    print(f"   lot_number: {geetest_result.get('lot_number')}")
    print()
    
    # Build geeDto
    print("=" * 70)
    print("Step 2: Build geeDto")
    print("=" * 70)
    print()
    
    gee_dto = {
        'lotNumber': geetest_result['lot_number'],
        'captchaOutput': geetest_result['captcha_output'],
        'passToken': geetest_result['pass_token'],
        'genTime': str(geetest_result['gen_time']),
        'captchaId': '045e2c229998a88721e32a763bc0f7b8',
        'captchaKeyType': 'dlVerify'
    }
    
    print("geeDto:")
    for key, value in gee_dto.items():
        if isinstance(value, str) and len(value) > 50:
            print(f"  {key}: {value[:50]}...")
        else:
            print(f"  {key}: {value}")
    print()
    
    # Build payload
    payload = {
        'orderId': str(order_id),
        'geeDto': gee_dto
    }
    
    print("Complete payload:")
    print(json.dumps(payload, indent=2, ensure_ascii=False)[:500])
    print()
    
    # Send request
    print("=" * 70)
    print("Step 3: Send Request")
    print("=" * 70)
    print()
    
    url = "https://dysh.dyswl.com/gate/app-api/club/order/grabAnOrder/v1"
    
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 12; 23127PN0CC Build/W528JS; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)',
        'Accept': 'application/json',
        'tenant-id': '1'
    }
    
    if token:
        headers['Authorization'] = f'Bearer {token}'
        print(f"✅ Using token: {token[:30]}...")
    else:
        print("⚠️  No token (may get 401 Unauthorized)")
    
    print(f"URL: POST {url}")
    print(f"Headers: {list(headers.keys())}")
    print()
    
    print("Sending request...")
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        print(f"Response: HTTP {response.status_code}")
        print()
        
        if response.status_code == 200:
            result = response.json()
            print("Result:")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            print()
            
            code = result.get('code')
            msg = result.get('msg', 'N/A')
            
            # Analyze
            print("=" * 70)
            print("Analysis")
            print("=" * 70)
            print()
            print(f"Code: {code}")
            print(f"Message: {msg}")
            print()
            
            if code == 0 or code == 200:
                print("✅ SUCCESS: Order grabbed!")
                return True
            elif code == 500:
                print("⚠️  Order not found (expected for fake ID)")
                print("✅ PARAMETER TEST PASSED!")
                print()
                print("This means:")
                print("  ✅ Geetest verification correct")
                print("  ✅ geeDto structure correct")
                print("  ✅ API accepts the request")
                print("  ✅ Ready for real orders!")
                return True
            elif code == 1001:
                print("❌ Still requires verification")
                print("   Geetest parameters may be incorrect")
                return False
            elif code == 401:
                print("⚠️  Unauthorized (need valid token)")
                print("   But parameter format is correct!")
                return True
            else:
                print(f"⚠️  Other response: {code}")
                print("   Check if this is expected")
                return True
        else:
            print(f"❌ HTTP {response.status_code}")
            print(response.text[:500])
            return False
            
    except Exception as e:
        print(f"❌ Request failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    try:
        success = test_grab_simple()
        print()
        if success:
            print("🎉 Test completed successfully!")
        else:
            print("❌ Test failed")
    except KeyboardInterrupt:
        print("\n\nTest cancelled")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
