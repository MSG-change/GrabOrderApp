#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida Token Service
Automatically captures tokens from target app via Frida Hook
"""

import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    print("⚠️ Frida not installed, using file monitoring mode")


class FridaTokenService:
    """Frida Token Service"""
    
    def __init__(self, target_package="com.your.target.app", log_callback=None):
        """
        Initialize
        
        Args:
            target_package: Target app package name
            log_callback: Log callback function
        """
        self.target_package = target_package
        self.log_callback = log_callback
        
        self.running = False
        self.thread = None
        
        # Token data
        self.token_data = {
            'token': '',
            'club_id': '',
            'role_id': '',
            'tenant_id': '',
            'timestamp': 0
        }
        
        # Token update callback
        self.token_callback = None
        
        # Frida related
        self.device = None
        self.session = None
        self.script = None
        
        # Token file path
        self.token_file = "/sdcard/grab_order_token.json"
        
        # Usage mode
        self.use_frida = FRIDA_AVAILABLE
        self.use_file_watch = True  # Always enable file monitoring as backup
    
    def set_token_callback(self, callback):
        """Set token update callback"""
        self.token_callback = callback
    
    def start(self):
        """Start service"""
        if self.running:
            self.log("⚠️ Frida service already running")
            return False
        
        self.running = True
        
        # Try to start Frida Hook
        if self.use_frida:
            success = self._start_frida_hook()
            if not success:
                self.log("⚠️ Frida Hook failed to start, switching to file monitoring mode")
                self.use_frida = False
        
        # Start file monitoring (backup solution)
        if self.use_file_watch:
            self.thread = threading.Thread(target=self._watch_token_file, daemon=True)
            self.thread.start()
            self.log("✅ Token file monitoring started")
        
        return True
    
    def stop(self):
        """Stop service"""
        self.running = False
        
        if self.script:
            try:
                self.script.unload()
            except:
                pass
        
        if self.session:
            try:
                self.session.detach()
            except:
                pass
        
        if self.thread:
            self.thread.join(timeout=2)
        
        self.log("⏹️ Frida service stopped")
    
    def _start_frida_hook(self):
        """Start Frida Hook"""
        try:
            self.log("🔧 Connecting to Frida...")
            
            # Get USB device
            self.device = frida.get_usb_device(timeout=5)
            self.log(f"✅ Connected to device: {self.device}")
            
            # Check if target app is running
            try:
                # Try to attach to running process
                self.log(f"📱 Attaching to: {self.target_package}")
                self.session = self.device.attach(self.target_package)
                self.log("✅ Attached to target app")
            except frida.ProcessNotFoundError:
                self.log(f"⚠️ Target app not running: {self.target_package}")
                self.log("   Please start the target app first, then restart this service")
                return False
            
            # Load Frida script
            script_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'frida_token_grabber.js'
            )
            
            if not os.path.exists(script_path):
                self.log(f"❌ Frida script not found: {script_path}")
                return False
            
            with open(script_path, 'r', encoding='utf-8') as f:
                script_code = f.read()
            
            self.log("🔧 Loading Frida script...")
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_frida_message)
            self.script.load()
            
            self.log("✅ Frida Hook activated")
            self.log("   Waiting for target app to send network requests...")
            
            return True
            
        except Exception as e:
            self.log(f"❌ Frida Hook startup failed: {e}")
            import traceback
            self.log(traceback.format_exc()[:200])
            return False
    
    def _on_frida_message(self, message, data):
        """Handle Frida messages"""
        try:
            if message['type'] == 'send':
                payload = message['payload']
                
                if payload.get('type') == 'token_update':
                    # Token update
                    token_data = payload.get('data', {})
                    self._update_token(token_data)
                    
            elif message['type'] == 'error':
                self.log(f"⚠️ Frida error: {message.get('description', 'Unknown')}")
                
        except Exception as e:
            self.log(f"❌ Failed to handle Frida message: {e}")
    
    def _watch_token_file(self):
        """Monitor token file (backup solution)"""
        self.log("📂 Token file monitoring started")
        
        last_mtime = 0
        
        while self.running:
            try:
                if os.path.exists(self.token_file):
                    mtime = os.path.getmtime(self.token_file)
                    
                    if mtime > last_mtime:
                        last_mtime = mtime
                        
                        # Read file
                        with open(self.token_file, 'r') as f:
                            data = json.load(f)
                        
                        # Update Token
                        if data.get('token'):
                            self._update_token(data)
                
            except Exception as e:
                pass  # Silent error to avoid spamming
            
            time.sleep(0.5)  # Check every 0.5 seconds
    
    def _update_token(self, data):
        """Update Token"""
        # Check if there are changes
        changed = False
        
        token = data.get('token', '').replace('Bearer ', '').strip()
        club_id = data.get('club_id', '')
        role_id = data.get('role_id', '')
        tenant_id = data.get('tenant_id', '')
        
        if token and token != self.token_data['token']:
            self.token_data['token'] = token
            changed = True
            self.log(f"🎯 Token updated: {token[:20]}...")
        
        if club_id and club_id != self.token_data['club_id']:
            self.token_data['club_id'] = str(club_id)
            changed = True
            self.log(f"   Club-ID: {club_id}")
        
        if role_id and role_id != self.token_data['role_id']:
            self.token_data['role_id'] = str(role_id)
            changed = True
            self.log(f"   Role-ID: {role_id}")
        
        if tenant_id and tenant_id != self.token_data['tenant_id']:
            self.token_data['tenant_id'] = str(tenant_id)
            changed = True
            self.log(f"   Tenant-ID: {tenant_id}")
        
        if changed:
            self.token_data['timestamp'] = int(time.time())
            
            # Callback notification
            if self.token_callback:
                self.token_callback(self.token_data)
    
    def get_token_data(self):
        """Get current token data"""
        return self.token_data.copy()
    
    def log(self, message):
        """Output log message"""
        if self.log_callback:
            self.log_callback(message)
        else:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")


class FridaTokenServiceSimple:
    """Simplified Frida Token Service (file monitoring only)"""
    
    def __init__(self, log_callback=None):
        """Initialize"""
        self.log_callback = log_callback
        self.running = False
        self.thread = None
        
        self.token_data = {
            'token': '',
            'club_id': '',
            'role_id': '',
            'tenant_id': '',
            'timestamp': 0
        }
        
        self.token_callback = None
        self.token_file = "/sdcard/grab_order_token.json"
        
        # Try to start external Frida server if available
        self._try_start_external_frida()
    
    def _try_start_external_frida(self):
        """Try to start external Frida server for MuMu emulator"""
        try:
            # Check if we're in Android environment
            try:
                import android
                is_android = True
            except ImportError:
                is_android = False
            
            if not is_android:
                return  # Not in Android, skip
            
            # Check if Frida server is already running
            result = subprocess.run(['ps'], capture_output=True, text=True, timeout=2)
            if 'frida-server' in result.stdout:
                self.log("External Frida server already running")
                return
            
            # Try to start Frida server if it exists
            frida_paths = [
                '/data/local/tmp/frida-server',
                '/data/local/tmp/frida-server-arm64',
                '/system/bin/frida-server'
            ]
            
            for path in frida_paths:
                if os.path.exists(path):
                    try:
                        # Start in background
                        subprocess.Popen([path, '-D'], 
                                       stdout=subprocess.DEVNULL, 
                                       stderr=subprocess.DEVNULL)
                        self.log(f"Started external Frida server: {path}")
                        time.sleep(1)  # Give it time to start
                        return
                    except Exception as e:
                        self.log(f"Failed to start {path}: {e}")
            
            self.log("No external Frida server found, using file monitoring only")
            
        except Exception as e:
            self.log(f"External Frida check error: {e}")
    
    def set_token_callback(self, callback):
        """Set callback"""
        self.token_callback = callback
    
    def start(self):
        """Start"""
        if self.running:
            return False
        
        self.running = True
        self.thread = threading.Thread(target=self._watch_file, daemon=True)
        self.thread.start()
        
        self.log("✅ Token monitoring started")
        self.log(f"   Monitoring file: {self.token_file}")
        self.log("   Please ensure Frida script is running on PC or other terminal")
        
        return True
    
    def stop(self):
        """Stop"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        self.log("⏹️ Token monitoring stopped")
    
    def _watch_file(self):
        """Monitor file"""
        last_mtime = 0
        
        while self.running:
            try:
                if os.path.exists(self.token_file):
                    mtime = os.path.getmtime(self.token_file)
                    
                    if mtime > last_mtime:
                        last_mtime = mtime
                        
                        with open(self.token_file, 'r') as f:
                            data = json.load(f)
                        
                        if data.get('token'):
                            self._update_token(data)
            except:
                pass
            
            time.sleep(0.5)
    
    def _update_token(self, data):
        """Update Token"""
        changed = False
        
        token = data.get('token', '').replace('Bearer ', '').strip()
        if token and token != self.token_data['token']:
            self.token_data['token'] = token
            changed = True
            self.log(f"🎯 Token: {token[:20]}...")
        
        for key in ['club_id', 'role_id', 'tenant_id']:
            value = str(data.get(key, ''))
            if value and value != self.token_data[key]:
                self.token_data[key] = value
                changed = True
                self.log(f"   {key}: {value}")
        
        if changed:
            self.token_data['timestamp'] = int(time.time())
            if self.token_callback:
                self.token_callback(self.token_data)
    
    def get_token_data(self):
        """Get token"""
        return self.token_data.copy()
    
    def log(self, message):
        """Log"""
        if self.log_callback:
            self.log_callback(message)
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

