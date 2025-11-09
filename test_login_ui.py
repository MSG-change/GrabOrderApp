#!/usr/bin/env python3
"""
Login Test App with Geetest Verification
English UI to avoid Chinese character encoding issues
"""

import sys
import os
import time

# Add paths
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'libs'))

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.clock import Clock, mainthread
from kivy.core.window import Window

import requests
import json
from libs.geetest_helper_local import GeetestHelperLocal


class LoginTestApp(App):
    """Login Test Application"""
    
    def build(self):
        """Build UI"""
        Window.clearcolor = (0.95, 0.95, 0.95, 1)
        
        # Main layout
        layout = BoxLayout(orientation='vertical', padding=20, spacing=15)
        
        # Title
        title = Label(
            text='Login Test with Geetest',
            size_hint_y=None,
            height=50,
            font_size='24sp',
            bold=True,
            color=(0.2, 0.2, 0.2, 1)
        )
        layout.add_widget(title)
        
        # Phone input
        phone_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=50, spacing=10)
        phone_label = Label(text='Phone:', size_hint_x=0.3, color=(0.2, 0.2, 0.2, 1))
        self.phone_input = TextInput(
            text='18113011654',
            multiline=False,
            size_hint_x=0.7,
            font_size='16sp',
            background_color=(1, 1, 1, 1),
            foreground_color=(0, 0, 0, 1)
        )
        phone_layout.add_widget(phone_label)
        phone_layout.add_widget(self.phone_input)
        layout.add_widget(phone_layout)
        
        # SMS Code input
        code_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=50, spacing=10)
        code_label = Label(text='SMS Code:', size_hint_x=0.3, color=(0.2, 0.2, 0.2, 1))
        self.code_input = TextInput(
            text='',
            multiline=False,
            size_hint_x=0.7,
            font_size='16sp',
            background_color=(1, 1, 1, 1),
            foreground_color=(0, 0, 0, 1)
        )
        code_layout.add_widget(code_label)
        code_layout.add_widget(self.code_input)
        layout.add_widget(code_layout)
        
        # Buttons
        btn_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=60, spacing=10)
        
        self.send_btn = Button(
            text='Send Code',
            font_size='18sp',
            background_color=(0.2, 0.6, 0.9, 1),
            color=(1, 1, 1, 1)
        )
        self.send_btn.bind(on_press=self.on_send_code)
        
        self.login_btn = Button(
            text='Login',
            font_size='18sp',
            background_color=(0.3, 0.7, 0.3, 1),
            color=(1, 1, 1, 1)
        )
        self.login_btn.bind(on_press=self.on_login)
        
        btn_layout.add_widget(self.send_btn)
        btn_layout.add_widget(self.login_btn)
        layout.add_widget(btn_layout)
        
        # Log area
        log_label = Label(
            text='Log:',
            size_hint_y=None,
            height=30,
            color=(0.2, 0.2, 0.2, 1),
            halign='left',
            valign='middle'
        )
        log_label.bind(size=log_label.setter('text_size'))
        layout.add_widget(log_label)
        
        # Scrollable log
        scroll = ScrollView(size_hint=(1, 1))
        self.log_label = Label(
            text='Ready...\n',
            size_hint_y=None,
            color=(0.2, 0.2, 0.2, 1),
            halign='left',
            valign='top',
            markup=True
        )
        self.log_label.bind(texture_size=self.log_label.setter('size'))
        self.log_label.bind(size=self.log_label.setter('text_size'))
        scroll.add_widget(self.log_label)
        layout.add_widget(scroll)
        
        # Initialize
        self.api_base_url = "https://dysh.dyswl.com"
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; 23127PN0CC Build/W528JS; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)',
            'Accept': 'application/json',
            'Accept-Language': 'zh-CN,zh;q=0.9'
        })
        
        self.geetest_helper = None
        self.log("Initializing Geetest helper...")
        Clock.schedule_once(self.init_geetest, 0.5)
        
        return layout
    
    @mainthread
    def log(self, message):
        """Add log message"""
        timestamp = time.strftime('%H:%M:%S')
        self.log_label.text += f'[{timestamp}] {message}\n'
    
    def init_geetest(self, dt):
        """Initialize Geetest helper"""
        try:
            # Check AI server
            ai_server_url = os.environ.get('AI_SERVER_URL')
            if ai_server_url:
                self.log(f"AI Server: {ai_server_url}")
            else:
                self.log("Warning: AI_SERVER_URL not set")
            
            # Initialize helper
            captcha_id = "045e2c229998a88721e32a763bc0f7b8"
            self.geetest_helper = GeetestHelperLocal(captcha_id=captcha_id)
            self.log("Geetest helper initialized")
            self.log("Ready to test!")
        except Exception as e:
            self.log(f"Error initializing: {e}")
    
    def on_send_code(self, instance):
        """Send SMS code"""
        phone = self.phone_input.text.strip()
        if not phone:
            self.log("Error: Phone number required")
            return
        
        self.send_btn.disabled = True
        self.log("=" * 50)
        self.log("Step 1: Sending SMS code...")
        
        # Run in background
        import threading
        threading.Thread(target=self._send_code_thread, args=(phone,), daemon=True).start()
    
    def _send_code_thread(self, phone):
        """Send code in background thread"""
        try:
            # Geetest verification
            self.log("Performing Geetest verification...")
            
            if not self.geetest_helper:
                self.log("Error: Geetest helper not initialized")
                Clock.schedule_once(lambda dt: setattr(self.send_btn, 'disabled', False), 0)
                return
            
            challenge = self.geetest_helper.generate_challenge(f"send_{phone}_{time.time()}")
            self.log(f"Challenge: {challenge[:30]}...")
            
            geetest_result = self.geetest_helper.verify(challenge=challenge)
            
            if not geetest_result or not geetest_result.get('success'):
                self.log("Error: Geetest verification failed")
                Clock.schedule_once(lambda dt: setattr(self.send_btn, 'disabled', False), 0)
                return
            
            self.log(f"Answers: {geetest_result.get('answers')}")
            self.log("Geetest verification success!")
            
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
            
            response = self.session.post(send_code_url, json=send_data, timeout=10)
            
            self.log(f"Response: HTTP {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                self.log(f"Result: {result}")
                
                if result.get('code') == 0 or result.get('success'):
                    self.log("SUCCESS: SMS code sent!")
                    self.log("Please check your phone")
                else:
                    error_msg = result.get('msg') or result.get('message') or 'Unknown error'
                    self.log(f"Error: {error_msg}")
            else:
                self.log(f"Error: HTTP {response.status_code}")
                self.log(f"Response: {response.text[:200]}")
        
        except Exception as e:
            self.log(f"Exception: {e}")
            import traceback
            self.log(traceback.format_exc()[:500])
        
        finally:
            Clock.schedule_once(lambda dt: setattr(self.send_btn, 'disabled', False), 0)
    
    def on_login(self, instance):
        """Login with SMS code"""
        phone = self.phone_input.text.strip()
        sms_code = self.code_input.text.strip()
        
        if not phone or not sms_code:
            self.log("Error: Phone and SMS code required")
            return
        
        self.login_btn.disabled = True
        self.log("=" * 50)
        self.log("Step 2: Logging in...")
        
        # Run in background
        import threading
        threading.Thread(target=self._login_thread, args=(phone, sms_code), daemon=True).start()
    
    def _login_thread(self, phone, sms_code):
        """Login in background thread"""
        try:
            login_url = f"{self.api_base_url}/gate/app-api/club/auth/login"
            
            login_data = {
                'mobile': phone,
                'code': sms_code,
                'loginType': 'sms'
            }
            
            self.log(f"Request: POST {login_url}")
            
            response = self.session.post(login_url, json=login_data, timeout=10)
            
            self.log(f"Response: HTTP {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                self.log(f"Result: {result}")
                
                if result.get('code') == 0 or result.get('success'):
                    self.log("SUCCESS: Login successful!")
                    
                    data = result.get('data', {})
                    token = data.get('token') or data.get('accessToken')
                    
                    if token:
                        self.log(f"Token: {token[:50]}...")
                        
                        # Save token
                        save_file = f"login_token_{int(time.time())}.txt"
                        with open(save_file, 'w') as f:
                            f.write(token)
                        self.log(f"Saved: {save_file}")
                else:
                    error_msg = result.get('msg') or result.get('message') or 'Unknown error'
                    self.log(f"Error: {error_msg}")
            else:
                self.log(f"Error: HTTP {response.status_code}")
                self.log(f"Response: {response.text[:200]}")
        
        except Exception as e:
            self.log(f"Exception: {e}")
            import traceback
            self.log(traceback.format_exc()[:500])
        
        finally:
            Clock.schedule_once(lambda dt: setattr(self.login_btn, 'disabled', False), 0)


if __name__ == '__main__':
    LoginTestApp().run()
