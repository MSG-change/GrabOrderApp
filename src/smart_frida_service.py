#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smart Frida Service - Intelligent Environment Detection and Architecture Selection
智能 Frida 服务 - 环境检测和架构智能选择

Automatically detects runtime environment (MuMu emulator, ARM64 device, x86 PC)
and selects the optimal Frida service architecture with automatic fallback.
"""

import os
import sys
import json
import time
import platform
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

# Frida imports with fallback
try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

try:
    from jnius import autoclass, cast
    ANDROID_AVAILABLE = True
except ImportError:
    ANDROID_AVAILABLE = False


class EnvironmentDetector:
    """Smart environment detector for Frida service selection"""

    def __init__(self):
        self.environment_info = {}
        self._detect_environment()

    def _detect_environment(self):
        """Detect comprehensive runtime environment"""
        self.environment_info = {
            'platform': platform.system().lower(),
            'architecture': platform.machine().lower(),
            'python_version': platform.python_version(),
            'is_android': False,
            'is_emulator': False,
            'emulator_type': None,
            'android_api': None,
            'android_abi': None,
            'frida_available': FRIDA_AVAILABLE,
            'kivy_available': False,
            'recommended_service': None,
            'fallback_services': []
        }

        # Detect Kivy
        try:
            import kivy
            self.environment_info['kivy_available'] = True
            self.environment_info['kivy_version'] = kivy.__version__
        except ImportError:
            pass

        # Detect Android environment
        if ANDROID_AVAILABLE:
            try:
                from kivy.utils import platform as kivy_platform
                if kivy_platform == 'android':
                    self.environment_info['is_android'] = True
                    self._detect_android_details()
            except:
                pass

        # Detect emulator
        self._detect_emulator()

        # Determine recommended service
        self._determine_recommended_service()

    def _detect_android_details(self):
        """Detect Android specific details"""
        try:
            # Get Android API level
            result = subprocess.run(
                ['getprop', 'ro.build.version.sdk'],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                self.environment_info['android_api'] = int(result.stdout.decode().strip())

            # Get Android ABI
            result = subprocess.run(
                ['getprop', 'ro.product.cpu.abi'],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                abi = result.stdout.decode().strip()
                self.environment_info['android_abi'] = abi

                # Update architecture based on ABI
                if 'arm64' in abi:
                    self.environment_info['architecture'] = 'aarch64'
                elif 'armeabi' in abi:
                    self.environment_info['architecture'] = 'arm'
        except:
            pass

    def _detect_emulator(self):
        """Detect if running in emulator"""
        try:
            # Check for MuMu emulator - expanded detection
            mumu_indicators = [
                'nemu',
                'mumu',
                'netEase',
                'MuMuPlayer',
                'nox',  # NOX emulator
                'bluestacks',  # BlueStacks
                'ldplayer'  # LDPlayer
            ]

            # Check system properties
            if self.environment_info['is_android']:
                try:
                    # Enhanced MuMu detection
                    result = subprocess.run(
                        ['getprop', 'ro.product.manufacturer'],
                        capture_output=True, timeout=5
                    )
                    manufacturer = result.stdout.decode().strip().lower() if result.returncode == 0 else ""

                    result = subprocess.run(
                        ['getprop', 'ro.product.model'],
                        capture_output=True, timeout=5
                    )
                    model = result.stdout.decode().strip().lower() if result.returncode == 0 else ""
                    
                    # Check brand as well
                    result = subprocess.run(
                        ['getprop', 'ro.product.brand'],
                        capture_output=True, timeout=5
                    )
                    brand = result.stdout.decode().strip().lower() if result.returncode == 0 else ""
                    
                    # Check hardware
                    result = subprocess.run(
                        ['getprop', 'ro.hardware'],
                        capture_output=True, timeout=5
                    )
                    hardware = result.stdout.decode().strip().lower() if result.returncode == 0 else ""

                    # Combined check for MuMu
                    combined_check = f"{manufacturer} {model} {brand} {hardware}"
                    for indicator in mumu_indicators:
                        if indicator.lower() in combined_check:
                            self.environment_info['is_emulator'] = True
                            self.environment_info['emulator_type'] = 'mumu'
                            self.log(f"MuMu emulator detected: {indicator} found in {combined_check}")
                            break

                    # Additional emulator detection
                    if not self.environment_info['is_emulator']:
                        # Check for common emulator signatures
                        emulator_props = [
                            'ro.kernel.qemu',
                            'ro.hardware',
                            'ro.product.device',
                            'ro.build.characteristics'
                        ]

                        for prop in emulator_props:
                            result = subprocess.run(
                                ['getprop', prop],
                                capture_output=True, timeout=5
                            )
                            if result.returncode == 0:
                                value = result.stdout.decode().strip().lower()
                                if any(term in value for term in ['qemu', 'emulator', 'sdk', 'generic', 'vbox']):
                                    self.environment_info['is_emulator'] = True
                                    self.environment_info['emulator_type'] = 'generic_android'
                                    break

                except Exception as e:
                    self.log(f"Android emulator detection error: {e}")
            else:
                # PC environment - check for emulator processes
                try:
                    result = subprocess.run(['pgrep', '-f', 'mumu'],
                                          capture_output=True, timeout=5)
                    if result.returncode == 0:
                        self.environment_info['is_emulator'] = True
                        self.environment_info['emulator_type'] = 'mumu_pc'
                except:
                    pass

        except Exception as e:
            self.log(f"Emulator detection error: {e}")

    def _determine_recommended_service(self):
        """Determine the recommended Frida service based on environment"""
        env = self.environment_info

        # Special handling for MuMu emulator - Use external Frida server approach
        if env['is_emulator'] and env['emulator_type'] == 'mumu':
            self.log("MuMu emulator detected - using external Frida server approach")
            # For MuMu, try external Frida server first, then APK service
            self.environment_info['recommended_service'] = 'MuMuFridaService'
            self.environment_info['fallback_services'] = [
                'FridaAPKService', 'FridaManager', 'FridaTokenServiceSimple'
            ]
            return

        # Priority 1: Pure APK Frida (works everywhere in APK)
        if env['is_android']:
            # Check if Frida is actually available and compatible
            if env['frida_available']:
                self.environment_info['recommended_service'] = 'FridaAPKService'
                self.environment_info['fallback_services'] = [
                    'FridaManager', 'FridaTokenServiceSimple'
                ]
            else:
                # Try external Frida server if internal Frida not available
                self.environment_info['recommended_service'] = 'MuMuFridaService'
                self.environment_info['fallback_services'] = [
                    'FridaAPKService', 'FridaManager', 'FridaTokenServiceSimple'
                ]
            return

        # Priority 2: PC with Frida (for development/testing)
        if not env['is_android'] and env['frida_available']:
            self.environment_info['recommended_service'] = 'FridaManager'
            self.environment_info['fallback_services'] = [
                'FridaTokenServiceSimple'
            ]
            return

        # Priority 3: File-based fallback (works everywhere)
        self.environment_info['recommended_service'] = 'FridaTokenServiceSimple'
        self.environment_info['fallback_services'] = []

    def get_environment_info(self) -> Dict[str, Any]:
        """Get comprehensive environment information"""
        return self.environment_info.copy()

    def is_arm64_environment(self) -> bool:
        """Check if current environment is ARM64"""
        arch = self.environment_info['architecture']
        return arch in ['aarch64', 'arm64']

    def is_mumu_emulator(self) -> bool:
        """Check if running in MuMu emulator"""
        return (self.environment_info['is_emulator'] and
                self.environment_info['emulator_type'] == 'mumu')

    def supports_frida_native(self) -> bool:
        """Check if environment supports native Frida operations"""
        env = self.environment_info

        # ARM64 Android environments generally support Frida
        if env['is_android'] and self.is_arm64_environment():
            return True

        # PC environments with Frida installed
        if not env['is_android'] and env['frida_available']:
            return True

        return False

    def log(self, message: str):
        """Log message with environment context"""
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] [SmartDetector] {message}")


class SmartFridaService:
    """
    Smart Frida Service with intelligent environment detection and architecture selection

    Features:
    - Automatic environment detection (MuMu, ARM64 device, x86 PC)
    - Dynamic service architecture selection
    - Automatic fallback and error recovery
    - Intelligent problem diagnosis and repair
    """

    def __init__(self, target_package="com.dys.shzs", log_callback=None):
        """
        Initialize Smart Frida Service

        Args:
            target_package: Target APP package name
            log_callback: Log callback function
        """
        self.target_package = target_package
        self.log_callback = log_callback

        # Environment detection
        self.detector = EnvironmentDetector()
        self.env_info = self.detector.get_environment_info()

        # Service management
        self.current_service = None
        self.service_instances = {}
        self.running = False

        # Token management
        self.token_data = {
            'token': '',
            'club_id': '',
            'role_id': '',
            'tenant_id': '',
            'timestamp': 0
        }
        self.token_callback = None

        # Performance metrics
        self.metrics = {
            'service_switches': 0,
            'errors_recovered': 0,
            'start_time': 0,
            'last_successful_service': None
        }

        self.log("Smart Frida Service initialized")
        self._log_environment_info()

    def set_token_callback(self, callback):
        """Set token update callback"""
        self.token_callback = callback
        # Propagate to current service if available
        if self.current_service and hasattr(self.current_service, 'set_token_callback'):
            self.current_service.set_token_callback(callback)

    def start(self) -> bool:
        """Start the smart Frida service with automatic selection"""
        if self.running:
            self.log("Service already running")
            return True

        self.running = True
        self.metrics['start_time'] = time.time()

        self.log("Starting Smart Frida Service...")

        # Try services in priority order
        success = self._try_services_priority_order()

        if success:
            self.log("✅ Smart Frida Service started successfully")
            self._log_service_status()
        else:
            self.log("❌ Failed to start any Frida service")
            self.running = False

        return success

    def _try_services_priority_order(self) -> bool:
        """Try services in priority order with intelligent fallback"""

        # Get service priority list
        services_to_try = [self.env_info['recommended_service']]
        services_to_try.extend(self.env_info['fallback_services'])

        self.log(f"Trying services in order: {services_to_try}")

        for service_name in services_to_try:
            if not service_name:
                continue

            self.log(f"Attempting to start: {service_name}")

            try:
                # Create and configure service
                service = self._create_service_instance(service_name)
                if not service:
                    self.log(f"Failed to create {service_name} instance")
                    continue

                # Try to start service
                if hasattr(service, 'start') and service.start():
                    self.current_service = service
                    self.metrics['last_successful_service'] = service_name
                    self.log(f"✅ Successfully started {service_name}")

                    # Set token callback
                    if self.token_callback and hasattr(service, 'set_token_callback'):
                        service.set_token_callback(self.token_callback)

                    return True
                else:
                    self.log(f"❌ {service_name} failed to start")

            except Exception as e:
                self.log(f"❌ {service_name} error: {e}")
                self.metrics['errors_recovered'] += 1

        return False

    def _create_service_instance(self, service_name: str):
        """Create service instance with proper configuration"""
        try:
            if service_name == 'MuMuFridaService':
                # MuMu专用服务 - 使用外部Frida server
                from .mumu_frida_service import MuMuFridaService
                return MuMuFridaService(
                    target_package=self.target_package,
                    log_callback=self._service_log_callback
                )
                
            elif service_name == 'FridaAPKService':
                from .frida_apk_service import FridaAPKService
                return FridaAPKService(
                    target_package=self.target_package,
                    log_callback=self._service_log_callback
                )

            elif service_name == 'FridaManager':
                from .frida_manager import FridaManager
                # FridaManager needs special handling for token management
                return FridaManagerProxy(
                    target_package=self.target_package,
                    log_callback=self._service_log_callback
                )

            elif service_name == 'FridaTokenServiceSimple':
                from .frida_service import FridaTokenServiceSimple
                return FridaTokenServiceSimple(
                    log_callback=self._service_log_callback
                )

            else:
                self.log(f"Unknown service: {service_name}")
                return None

        except ImportError as e:
            self.log(f"Failed to import {service_name}: {e}")
            # If MuMuFridaService not available, fall back to FridaAPKService
            if service_name == 'MuMuFridaService':
                self.log("MuMuFridaService not available, trying FridaAPKService")
                return self._create_service_instance('FridaAPKService')
            return None
        except Exception as e:
            self.log(f"Failed to create {service_name}: {e}")
            return None

    def _service_log_callback(self, message: str):
        """Handle service log messages"""
        self.log(f"[Service] {message}")

    def stop(self):
        """Stop the current service"""
        if not self.running:
            return

        self.log("Stopping Smart Frida Service...")

        if self.current_service and hasattr(self.current_service, 'stop'):
            try:
                self.current_service.stop()
                self.log("✅ Service stopped successfully")
            except Exception as e:
                self.log(f"⚠️ Error stopping service: {e}")

        self.current_service = None
        self.running = False

        self._log_final_metrics()

    def get_token_data(self) -> Dict[str, Any]:
        """Get current token data"""
        if self.current_service and hasattr(self.current_service, 'get_token_data'):
            return self.current_service.get_token_data()
        return self.token_data.copy()

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive service status"""
        status = {
            'running': self.running,
            'environment': self.env_info,
            'current_service': None,
            'service_status': None,
            'metrics': self.metrics.copy(),
            'token_data': self.get_token_data()
        }

        if self.current_service:
            status['current_service'] = self.current_service.__class__.__name__
            if hasattr(self.current_service, 'get_status'):
                status['service_status'] = self.current_service.get_status()

        return status

    def force_service_switch(self, service_name: str) -> bool:
        """Force switch to a specific service"""
        if not self.running:
            self.log("Service not running, cannot switch")
            return False

        self.log(f"Forcing switch to: {service_name}")

        # Stop current service
        if self.current_service:
            self.current_service.stop()

        # Try new service
        try:
            new_service = self._create_service_instance(service_name)
            if new_service and hasattr(new_service, 'start') and new_service.start():
                self.current_service = new_service
                self.metrics['service_switches'] += 1
                self.metrics['last_successful_service'] = service_name

                if self.token_callback and hasattr(new_service, 'set_token_callback'):
                    new_service.set_token_callback(self.token_callback)

                self.log(f"✅ Successfully switched to {service_name}")
                return True
            else:
                self.log(f"❌ Failed to switch to {service_name}")
                # Try to restart previous service
                return self._try_services_priority_order()

        except Exception as e:
            self.log(f"❌ Error during service switch: {e}")
            return False

    def diagnose_issues(self) -> Dict[str, Any]:
        """Diagnose potential issues and provide solutions"""
        diagnosis = {
            'issues': [],
            'recommendations': [],
            'severity': 'low'
        }

        env = self.env_info

        # Check Frida availability
        if not env['frida_available'] and not env['is_android']:
            diagnosis['issues'].append("Frida not available in PC environment")
            diagnosis['recommendations'].append("Install Frida: pip install frida-tools")
            diagnosis['severity'] = 'high'

        # Check architecture compatibility
        if env['is_android'] and not self.detector.is_arm64_environment():
            diagnosis['issues'].append("Non-ARM64 Android environment detected")
            diagnosis['recommendations'].append("Ensure device/emulator supports ARM64")
            diagnosis['severity'] = 'medium'

        # Check service status
        if not self.running:
            diagnosis['issues'].append("Smart Frida Service not running")
            diagnosis['recommendations'].append("Call start() to initialize service")
            diagnosis['severity'] = 'high'

        # Check current service
        if self.running and not self.current_service:
            diagnosis['issues'].append("No active Frida service")
            diagnosis['recommendations'].append("Check service initialization logs")
            diagnosis['severity'] = 'high'

        return diagnosis

    def _log_environment_info(self):
        """Log detected environment information"""
        env = self.env_info
        self.log("Environment Detection Results:")
        self.log(f"  Platform: {env['platform']}")
        self.log(f"  Architecture: {env['architecture']}")
        self.log(f"  Android: {env['is_android']}")
        self.log(f"  Emulator: {env['is_emulator']} ({env['emulator_type'] or 'None'})")
        self.log(f"  Frida Available: {env['frida_available']}")
        self.log(f"  Recommended Service: {env['recommended_service']}")

    def _log_service_status(self):
        """Log current service status"""
        if self.current_service:
            service_name = self.current_service.__class__.__name__
            self.log(f"Active Service: {service_name}")
        else:
            self.log("No active service")

    def _log_final_metrics(self):
        """Log final performance metrics"""
        runtime = time.time() - self.metrics['start_time']
        self.log(f"Session Summary:")
        self.log(f"  Runtime: {runtime:.1f} seconds")
        self.log(f"  Service switches: {self.metrics['service_switches']}")
        self.log(f"  Errors recovered: {self.metrics['errors_recovered']}")
        self.log(f"  Last successful service: {self.metrics['last_successful_service']}")

    def log(self, message: str):
        """Log message with timestamp"""
        if self.log_callback:
            self.log_callback(message)
        else:
            timestamp = time.strftime("%H:%M:%S")
            print(f"[{timestamp}] [SmartFrida] {message}")


class FridaManagerProxy:
    """
    Proxy for FridaManager to adapt it to the token service interface
    This allows FridaManager to work with the Smart Frida Service
    """

    def __init__(self, target_package, log_callback=None):
        self.target_package = target_package
        self.log_callback = log_callback
        self.manager = None
        self.running = False

    def start(self):
        try:
            from .frida_manager import FridaManager
            self.manager = FridaManager(log_callback=self.log_callback)
            self.running = True
            # FridaManager doesn't have a simple start/stop interface
            # We'll manage it differently
            return True
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"FridaManager proxy error: {e}")
            return False

    def stop(self):
        self.running = False
        if self.manager and hasattr(self.manager, 'stop_frida_server'):
            try:
                self.manager.stop_frida_server()
            except:
                pass

    def get_token_data(self):
        # FridaManager doesn't provide token data directly
        return {
            'token': '',
            'club_id': '',
            'role_id': '',
            'tenant_id': '',
            'timestamp': 0
        }

    def set_token_callback(self, callback):
        # FridaManager doesn't support token callbacks
        pass


# Factory function for easy instantiation
def create_smart_frida_service(target_package="com.dys.shzs", log_callback=None):
    """
    Create a smart Frida service instance with automatic environment detection

    Args:
        target_package: Target APP package name
        log_callback: Optional log callback function

    Returns:
        SmartFridaService instance
    """
    return SmartFridaService(target_package=target_package, log_callback=log_callback)


# Test function
def test_smart_service():
    """Test the smart Frida service"""
    print("🧪 Testing Smart Frida Service...")

    service = SmartFridaService()

    # Print environment info
    env_info = service.get_environment_info()
    print("📊 Environment Information:")
    for key, value in env_info.items():
        print(f"  {key}: {value}")

    # Test diagnosis
    diagnosis = service.diagnose_issues()
    print("🔍 Diagnosis Results:")
    print(f"  Issues: {len(diagnosis['issues'])}")
    for issue in diagnosis['issues']:
        print(f"    - {issue}")
    print(f"  Recommendations: {len(diagnosis['recommendations'])}")
    for rec in diagnosis['recommendations']:
        print(f"    - {rec}")

    print("✅ Smart Frida Service test completed")


if __name__ == '__main__':
    test_smart_service()
