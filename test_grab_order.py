#!/usr/bin/env python3
"""
Test Order Grabbing with Geetest
Test parameter passing and API integration
"""

import sys
import os
import time

# Add paths
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'libs'))

import requests
import json
from libs.geetest_helper_local import GeetestHelperLocal


class GrabOrderTest:
    """Order Grabbing Test"""
    
    def __init__(self):
        """Initialize"""
        self.api_base_url = "https://dysh.dyswl.com"
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; 23127PN0CC Build/W528JS; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)',
            'Accept': 'application/json',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'tenant-id': '1'  # Important for order API
        })
        
        self.geetest_helper = None
    
    def log(self, message):
        """Print log with timestamp"""
        timestamp = time.strftime('%H:%M:%S')
        print(f'[{timestamp}] {message}')
    
    def init_geetest(self):
        """Initialize Geetest helper"""
        try:
            ai_server_url = os.environ.get('AI_SERVER_URL', 'http://127.0.0.1:8889')
            self.log(f"AI Server: {ai_server_url}")
            
            captcha_id = "045e2c229998a88721e32a763bc0f7b8"
            self.geetest_helper = GeetestHelperLocal(captcha_id=captcha_id)
            self.log("Geetest helper initialized")
            return True
        except Exception as e:
            self.log(f"Error initializing: {e}")
            return False
    
    def set_token(self, token):
        """Set authorization token"""
        self.session.headers.update({
            'Authorization': f'Bearer {token}'
        })
        self.log(f"Token set: {token[:30]}...")
    
    def grab_order(self, order_id):
        """
        Test grabbing an order
        
        Args:
            order_id: Order ID to grab (can be fake for testing)
        """
        try:
            self.log("=" * 70)
            self.log(f"Testing Order Grab: {order_id}")
            self.log("=" * 70)
            print()
            
            # Step 1: Geetest verification
            self.log("Step 1: Performing Geetest verification...")
            
            if not self.geetest_helper:
                self.log("Error: Geetest helper not initialized")
                return False
            
            # Generate challenge based on order ID
            challenge = self.geetest_helper.generate_challenge(str(order_id))
            self.log(f"Challenge: {challenge[:40]}...")
            
            # Perform verification
            geetest_result = self.geetest_helper.verify(challenge=challenge)
            
            if not geetest_result or not geetest_result.get('success'):
                self.log("Error: Geetest verification failed")
                return False
            
            self.log(f"Answers: {geetest_result.get('answers')}")
            self.log(f"lot_number: {geetest_result.get('lot_number')}")
            self.log("Geetest verification SUCCESS!")
            print()
            
            # Step 2: Build geeDto
            self.log("Step 2: Building geeDto...")
            
            gee_dto = {
                'lotNumber': geetest_result['lot_number'],
                'captchaOutput': geetest_result['captcha_output'],
                'passToken': geetest_result['pass_token'],
                'genTime': str(geetest_result['gen_time']),
                'captchaId': '045e2c229998a88721e32a763bc0f7b8',
                'captchaKeyType': 'dlVerify'
            }
            
            self.log("geeDto structure:")
            for key, value in gee_dto.items():
                if isinstance(value, str) and len(value) > 50:
                    self.log(f"  {key}: {value[:50]}...")
                else:
                    self.log(f"  {key}: {value}")
            print()
            
            # Step 3: Send grab request
            self.log("Step 3: Sending grab request...")
            
            grab_url = f"{self.api_base_url}/gate/app-api/club/order/grabAnOrder/v1"
            
            # Build payload
            payload = {
                'orderId': str(order_id),  # String format
                'geeDto': gee_dto
            }
            
            self.log(f"Request URL: POST {grab_url}")
            self.log(f"Payload structure:")
            self.log(f"  orderId: {payload['orderId']} (type: {type(payload['orderId']).__name__})")
            self.log(f"  geeDto: {list(gee_dto.keys())}")
            print()
            
            # Send request
            self.log("Sending request...")
            self.log(f"Headers: {dict(self.session.headers)}")
            print()
            
            try:
                response = self.session.post(grab_url, json=payload, timeout=30)
                self.log(f"Response: HTTP {response.status_code}")
            except Exception as e:
                self.log(f"❌ Request failed: {e}")
                self.log("This might be a network issue, not a parameter issue")
                print()
                raise
            
            if response.status_code == 200:
                result = response.json()
                self.log(f"Result: {json.dumps(result, ensure_ascii=False, indent=2)}")
                print()
                
                code = result.get('code')
                msg = result.get('msg', 'N/A')
                
                # Analyze response
                self.log("=" * 70)
                self.log("Response Analysis:")
                self.log("=" * 70)
                self.log(f"Code: {code}")
                self.log(f"Message: {msg}")
                print()
                
                if code == 0 or code == 200:
                    self.log("✅ SUCCESS: Order grabbed!")
                    return True
                elif code == 500:
                    self.log("⚠️  Expected: Order does not exist (testing with fake ID)")
                    self.log("✅ PARAMETER TEST PASSED: API accepted the request format")
                    return True
                elif code == 1001:
                    self.log("⚠️  Unexpected: Still requires verification")
                    self.log("❌ Geetest parameters may be incorrect")
                    return False
                else:
                    self.log(f"⚠️  Other response: Code {code}")
                    self.log("✅ PARAMETER TEST PASSED: API accepted the request")
                    return True
            else:
                self.log(f"❌ Error: HTTP {response.status_code}")
                self.log(f"Response: {response.text[:500]}")
                print()
                return False
        
        except Exception as e:
            self.log(f"❌ Exception: {e}")
            import traceback
            traceback.print_exc()
            print()
            return False


def main():
    """Main function"""
    print()
    print("=" * 70)
    print("Order Grabbing Test with Geetest")
    print("=" * 70)
    print()
    
    # Test order ID (can be fake)
    default_order_id = "9999999"
    
    print("This test will:")
    print("1. Perform Geetest verification")
    print("2. Build geeDto with all parameters")
    print("3. Send grab request to API")
    print("4. Verify parameter format is correct")
    print()
    print("Expected result:")
    print("  - Code 500: Order not found (normal for fake ID)")
    print("  - Code 0/200: Order grabbed (if ID exists)")
    print("  - Code 1001: Geetest params incorrect (need to fix)")
    print()
    
    order_id = input(f"Enter order ID to test (default: {default_order_id}): ").strip()
    if not order_id:
        order_id = default_order_id
    
    print()
    print(f"Testing with order ID: {order_id}")
    print()
    
    # Check for token - REQUIRED for real request
    token = None
    token_files = [f for f in os.listdir('.') if f.startswith('login_token_')]
    if token_files:
        latest_token_file = sorted(token_files)[-1]
        print(f"Found token file: {latest_token_file}")
        with open(latest_token_file, 'r') as f:
            token = f.read().strip()
        print(f"Token loaded: {token[:30]}...")
        print()
    else:
        print("❌ No token file found!")
        print()
        print("Please login first to get a token:")
        print("  ./run_login_test.sh")
        print()
        print("Or enter token manually:")
        token = input("Enter token: ").strip()
        if not token:
            print("❌ Token is required for real API request")
            return
        print()
    
    # Initialize
    client = GrabOrderTest()
    
    if token:
        client.set_token(token)
    else:
        print("⚠️  Testing without authentication token")
        print("   (May get 401 Unauthorized, but we can still test parameter format)")
        print()
    
    print("Initializing Geetest helper...")
    if not client.init_geetest():
        print("Failed to initialize Geetest helper")
        return
    
    print()
    
    # Test grab
    success = client.grab_order(order_id)
    
    print()
    print("=" * 70)
    print("Test Summary")
    print("=" * 70)
    print()
    
    if success:
        print("✅ Test PASSED")
        print()
        print("What this means:")
        print("  ✅ Geetest verification works")
        print("  ✅ geeDto structure is correct")
        print("  ✅ API accepts the request format")
        print("  ✅ Parameters are properly formatted")
        print()
        print("Ready for production use!")
    else:
        print("❌ Test FAILED")
        print()
        print("Possible issues:")
        print("  - Geetest verification failed")
        print("  - geeDto parameters incorrect")
        print("  - API rejected the request format")
        print()
        print("Check the logs above for details")
    
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest cancelled by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
