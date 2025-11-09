#!/usr/bin/env python3
"""
Login Test - Command Line Version
No UI dependencies, pure terminal interface
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


class LoginTestCLI:
    """Login Test - Command Line Interface"""
    
    def __init__(self):
        """Initialize"""
        self.api_base_url = "https://dysh.dyswl.com"
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; 23127PN0CC Build/W528JS; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)',
            'Accept': 'application/json',
            'Accept-Language': 'zh-CN,zh;q=0.9'
        })
        
        self.geetest_helper = None
    
    def log(self, message):
        """Print log with timestamp"""
        timestamp = time.strftime('%H:%M:%S')
        print(f'[{timestamp}] {message}')
    
    def init_geetest(self):
        """Initialize Geetest helper"""
        try:
            # Check AI server
            ai_server_url = os.environ.get('AI_SERVER_URL')
            if ai_server_url:
                self.log(f"AI Server: {ai_server_url}")
            else:
                self.log("Warning: AI_SERVER_URL not set")
                self.log("Using default: http://127.0.0.1:8889")
            
            # Initialize helper
            captcha_id = "045e2c229998a88721e32a763bc0f7b8"
            self.geetest_helper = GeetestHelperLocal(captcha_id=captcha_id)
            self.log("Geetest helper initialized")
            return True
        except Exception as e:
            self.log(f"Error initializing: {e}")
            return False
    
    def send_code(self, phone):
        """Send SMS code"""
        try:
            self.log("=" * 70)
            self.log("Step 1: Sending SMS code...")
            self.log("=" * 70)
            
            # Geetest verification
            self.log("Performing Geetest verification...")
            
            if not self.geetest_helper:
                self.log("Error: Geetest helper not initialized")
                return False
            
            challenge = self.geetest_helper.generate_challenge(f"send_{phone}_{time.time()}")
            self.log(f"Challenge: {challenge[:40]}...")
            
            geetest_result = self.geetest_helper.verify(challenge=challenge)
            
            if not geetest_result or not geetest_result.get('success'):
                self.log("Error: Geetest verification failed")
                return False
            
            self.log(f"Answers: {geetest_result.get('answers')}")
            self.log(f"lot_number: {geetest_result.get('lot_number')}")
            self.log("Geetest verification SUCCESS!")
            print()
            
            # Send SMS
            self.log("Sending SMS code...")
            
            send_code_url = f"{self.api_base_url}/gate/app-api/club/auth/sendLoginCode"
            
            send_data = {
                'mobile': phone,
                'lotNumber': geetest_result['lot_number'],
                'captchaOutput': geetest_result['captcha_output'],
                'passToken': geetest_result['pass_token'],
                'genTime': str(geetest_result['gen_time']),
                'captchaId': '045e2c229998a88721e32a763bc0f7b8',
                'captchaKeyType': 'dlVerify'
            }
            
            self.log(f"Request: POST {send_code_url}")
            self.log(f"Data keys: {list(send_data.keys())}")
            print()
            
            response = self.session.post(send_code_url, json=send_data, timeout=10)
            
            self.log(f"Response: HTTP {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                self.log(f"Result: {json.dumps(result, ensure_ascii=False)}")
                print()
                
                if result.get('code') == 0 or result.get('success'):
                    self.log("✅ SUCCESS: SMS code sent!")
                    self.log("Please check your phone for SMS code")
                    print()
                    return True
                else:
                    error_msg = result.get('msg') or result.get('message') or 'Unknown error'
                    self.log(f"❌ Error: {error_msg}")
                    print()
                    return False
            else:
                self.log(f"❌ Error: HTTP {response.status_code}")
                self.log(f"Response: {response.text[:200]}")
                print()
                return False
        
        except Exception as e:
            self.log(f"❌ Exception: {e}")
            import traceback
            traceback.print_exc()
            print()
            return False
    
    def login(self, phone, sms_code):
        """Login with SMS code"""
        try:
            self.log("=" * 70)
            self.log("Step 2: Logging in...")
            self.log("=" * 70)
            
            login_url = f"{self.api_base_url}/gate/app-api/club/auth/login"
            
            login_data = {
                'mobile': phone,
                'code': sms_code,
                'loginType': 'sms'
            }
            
            self.log(f"Request: POST {login_url}")
            self.log(f"Data: {json.dumps(login_data, ensure_ascii=False)}")
            print()
            
            response = self.session.post(login_url, json=login_data, timeout=10)
            
            self.log(f"Response: HTTP {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                self.log(f"Result: {json.dumps(result, ensure_ascii=False)}")
                print()
                
                if result.get('code') == 0 or result.get('success'):
                    self.log("✅ SUCCESS: Login successful!")
                    
                    data = result.get('data', {})
                    token = data.get('token') or data.get('accessToken')
                    
                    if token:
                        self.log(f"Token: {token[:50]}...")
                        
                        # Save token
                        save_file = f"login_token_{int(time.time())}.txt"
                        with open(save_file, 'w') as f:
                            f.write(token)
                        self.log(f"Saved: {save_file}")
                        print()
                        return True
                else:
                    error_msg = result.get('msg') or result.get('message') or 'Unknown error'
                    self.log(f"❌ Error: {error_msg}")
                    print()
                    return False
            else:
                self.log(f"❌ Error: HTTP {response.status_code}")
                self.log(f"Response: {response.text[:200]}")
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
    print("Login Test with Geetest - Command Line Version")
    print("=" * 70)
    print()
    
    # Default phone number
    default_phone = "18113011654"
    
    print(f"Default phone: {default_phone}")
    phone = input(f"Enter phone number (press Enter for default): ").strip()
    if not phone:
        phone = default_phone
    
    print()
    print(f"Using phone: {phone}")
    print()
    
    # Initialize
    client = LoginTestCLI()
    
    print("Initializing Geetest helper...")
    if not client.init_geetest():
        print("Failed to initialize Geetest helper")
        return
    
    print()
    
    # Send code
    if client.send_code(phone):
        print()
        sms_code = input("Enter SMS code from your phone: ").strip()
        
        if sms_code:
            print()
            # Login
            if client.login(phone, sms_code):
                print("=" * 70)
                print("🎉 Test completed successfully!")
                print("=" * 70)
                print()
                print("Summary:")
                print("✅ Geetest verification: SUCCESS")
                print("✅ SMS code sent: SUCCESS")
                print("✅ Login: SUCCESS")
                print("✅ Token saved: SUCCESS")
                print()
            else:
                print("Login failed")
        else:
            print("No SMS code entered")
    else:
        print("Failed to send SMS code")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest cancelled by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
