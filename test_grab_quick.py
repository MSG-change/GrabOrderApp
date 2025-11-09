#!/usr/bin/env python3
"""
Quick Order Grab Test
Test parameter format without waiting for network
"""

import sys
import os
import time
import json

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'libs'))

from libs.geetest_helper_local import GeetestHelperLocal


def test_grab_parameters():
    """Test grab order parameters"""
    
    print()
    print("=" * 70)
    print("Quick Order Grab Parameter Test")
    print("=" * 70)
    print()
    
    # Initialize Geetest
    print("Initializing Geetest helper...")
    captcha_id = "045e2c229998a88721e32a763bc0f7b8"
    geetest_helper = GeetestHelperLocal(captcha_id=captcha_id)
    print("✅ Initialized")
    print()
    
    # Test order ID
    order_id = "9999999"
    print(f"Testing with order ID: {order_id}")
    print()
    
    # Perform Geetest verification
    print("=" * 70)
    print("Step 1: Geetest Verification")
    print("=" * 70)
    print()
    
    challenge = geetest_helper.generate_challenge(str(order_id))
    print(f"Challenge: {challenge}")
    print()
    
    print("Performing verification...")
    geetest_result = geetest_helper.verify(challenge=challenge)
    
    if not geetest_result or not geetest_result.get('success'):
        print("❌ Verification failed")
        return
    
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
    
    print("geeDto structure:")
    for key, value in gee_dto.items():
        if isinstance(value, str) and len(value) > 60:
            print(f"  {key}: {value[:60]}...")
        else:
            print(f"  {key}: {value}")
    print()
    
    # Build complete payload
    print("=" * 70)
    print("Step 3: Build Complete Payload")
    print("=" * 70)
    print()
    
    payload = {
        'orderId': str(order_id),
        'geeDto': gee_dto
    }
    
    print("Complete payload:")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print()
    
    # Verify structure
    print("=" * 70)
    print("Step 4: Verify Structure")
    print("=" * 70)
    print()
    
    checks = []
    
    # Check orderId
    if 'orderId' in payload:
        if isinstance(payload['orderId'], str):
            checks.append(("✅", "orderId is string", payload['orderId']))
        else:
            checks.append(("❌", "orderId should be string", type(payload['orderId'])))
    else:
        checks.append(("❌", "orderId missing", None))
    
    # Check geeDto
    if 'geeDto' in payload:
        checks.append(("✅", "geeDto exists", None))
        
        gee_dto = payload['geeDto']
        required_fields = ['lotNumber', 'captchaOutput', 'passToken', 'genTime', 'captchaId', 'captchaKeyType']
        
        for field in required_fields:
            if field in gee_dto:
                checks.append(("✅", f"geeDto.{field} exists", None))
            else:
                checks.append(("❌", f"geeDto.{field} missing", None))
    else:
        checks.append(("❌", "geeDto missing", None))
    
    # Print checks
    for status, message, value in checks:
        if value:
            print(f"{status} {message}: {value}")
        else:
            print(f"{status} {message}")
    
    print()
    
    # Summary
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    print()
    
    all_passed = all(status == "✅" for status, _, _ in checks)
    
    if all_passed:
        print("✅ ALL CHECKS PASSED")
        print()
        print("Parameter structure is correct!")
        print()
        print("Ready to send to API:")
        print(f"  POST /gate/app-api/club/order/grabAnOrder/v1")
        print(f"  Body: {json.dumps(payload, ensure_ascii=False)[:100]}...")
        print()
        print("Expected responses:")
        print("  - Code 0/200: Order grabbed successfully")
        print("  - Code 500: Order not found (normal for fake ID)")
        print("  - Code 1001: Geetest verification failed (should not happen)")
        print("  - Code 401: Unauthorized (need valid token)")
        print()
    else:
        print("❌ SOME CHECKS FAILED")
        print()
        print("Please fix the issues above")
        print()
    
    return all_passed


if __name__ == '__main__':
    try:
        success = test_grab_parameters()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
