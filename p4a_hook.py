#!/usr/bin/env python3
"""
python-for-android build hook
Fix libffi and other dependency issues before compilation
"""

import os
import subprocess
import sys


def pre_build_hook(ctx):
    """Pre-build hook"""
    print("=" * 70)
    print("Executing custom build hook...")
    print("=" * 70)
    
    # Set environment variables to fix autoconf issues
    os.environ['ACLOCAL_PATH'] = '/usr/share/aclocal'
    os.environ['PKG_CONFIG_PATH'] = '/usr/lib/pkgconfig:/usr/share/pkgconfig'
    
    # Output environment info
    print("Environment variables set:")
    print(f"   ACLOCAL_PATH: {os.environ.get('ACLOCAL_PATH')}")
    print(f"   PKG_CONFIG_PATH: {os.environ.get('PKG_CONFIG_PATH')}")
    
    return True


def post_build_hook(ctx):
    """Post-build hook"""
    print("=" * 70)
    print("Build completed")
    print("=" * 70)
    return True

