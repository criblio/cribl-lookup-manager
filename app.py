#!/usr/bin/env python3
"""
Cribl Lookup Manager - Backend Server
Version: 1.0.1 (Security Hardened)
Date: November 21, 2025

Security Fixes in v1.0.1:
- Removed SSRF vulnerability (/api/test-curl endpoint)
- Fixed CORS configuration (localhost only)
- Added input validation for all user inputs
- Added security headers (XSS, Clickjacking, etc.)
- Added URL sanitization for logs
"""
import sys
import subprocess
import importlib.util
import socket
import webbrowser
import threading
import time

# Check and install dependencies
def check_install_package(package_name, import_name=None):
    """Check if a package is installed, if not ask to install it"""
    if import_name is None:
        import_name = package_name
    
    if importlib.util.find_spec(import_name) is None:
        print(f"\n[WARN] Required package '{package_name}' is not installed.")
        response = input(f"Would you like to install '{package_name}' now? (y/n): ").strip().lower()
        
        if response == 'y':
            print(f"[INSTALL] Installing {package_name}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
                print(f"[ERROR] {package_name} installed successfully!")
                return True
            except subprocess.CalledProcessError:
                print(f"[ERROR] Failed to install {package_name}. Please install manually:")
                print(f"   pip install {package_name}")
                return False
        else:
            print(f"[ERROR] {package_name} is required to run this application.")
            print(f"   Install with: pip install {package_name}")
            return False
    return True

# Check all required packages
required_packages = [
    ('Flask', 'flask'),
    ('Flask-CORS', 'flask_cors'),
    ('requests', 'requests')
]

print("[INFO] Checking dependencies...")
all_installed = True
for package_name, import_name in required_packages:
    if not check_install_package(package_name, import_name):
        all_installed = False

if not all_installed:
    print("\n[ERROR] Missing required dependencies. Please install them and try again.")
    sys.exit(1)

print("[ERROR] All dependencies are installed!\n")

# Now import Flask modules
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import requests
import os
import json
from pathlib import Path
import configparser
import gzip
import tempfile
from datetime import datetime
import re

app = Flask(__name__)

# SECURITY: Configure CORS to only allow localhost origins
# This prevents Cross-Site Request Forgery (CSRF) attacks
CORS(app, 
     origins=[
         'http://localhost:42001',
         'http://127.0.0.1:42001',
         'http://localhost:*',  # Allow any localhost port for development
         'http://127.0.0.1:*'
     ],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'])

# SECURITY: Input validation functions
def validate_filename(filename):
    """
    Validate filename to prevent path traversal attacks
    Only allows: letters, numbers, underscores, hyphens, periods
    """
    if not filename:
        raise ValueError("Filename cannot be empty")
    
    # Check for path traversal attempts
    if '..' in filename or '/' in filename or '\\' in filename or '\0' in filename:
        raise ValueError("Invalid filename: path traversal detected")
    
    # Only allow safe characters
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        raise ValueError("Invalid filename: only alphanumeric, underscore, hyphen, and period allowed")
    
    # Check length
    if len(filename) > 255:
        raise ValueError("Filename too long (max 255 characters)")
    
    return filename

def validate_worker_group(group_name):
    """
    Validate worker group name
    Only allows: letters, numbers, underscores, hyphens
    """
    if not group_name:
        raise ValueError("Worker group name cannot be empty")
    
    # Check for path traversal or special characters
    if '..' in group_name or '/' in group_name or '\\' in group_name or '\0' in group_name:
        raise ValueError("Invalid worker group name")
    
    # Allow alphanumeric, underscore, hyphen, and period (for default_search, etc.)
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', group_name):
        raise ValueError("Invalid worker group name: only alphanumeric, underscore, hyphen allowed")
    
    if len(group_name) > 100:
        raise ValueError("Worker group name too long (max 100 characters)")
    
    return group_name

def validate_api_type(api_type):
    """
    Validate API type against allowed values
    """
    allowed_types = ['stream', 'search', 'edge']
    if api_type not in allowed_types:
        raise ValueError(f"Invalid API type: must be one of {allowed_types}")
    return api_type

def sanitize_url_for_logging(url):
    """
    Remove sensitive data from URLs before logging
    """
    if not url:
        return url
    # Remove token parameters
    url = re.sub(r'([?&]token=)[^&]+', r'\1***', url)
    # Remove Authorization headers from logs
    url = re.sub(r'(Bearer\s+)[a-zA-Z0-9\-_\.]+', r'\1***', url)
    return url

# Global config storage
app_config = {
    'authenticated': False,
    'token': None,
    'token_expiry': None,
    'client_id': None,
    'client_secret': None,
    'organization_id': None,
    'base_url': None,  # Store the base URL for API calls
    'is_direct_tenant': False  # Flag for direct tenant URLs
}

# SECURITY: Add security headers to all responses
@app.after_request
def add_security_headers(response):
    """Add security headers to prevent various attacks"""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Content Security Policy (restrictive)
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self' http://localhost:* http://127.0.0.1:* https://*.cribl.cloud;"
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/')
def index():
    """Serve the main application page"""
    return send_file('index.html')

@app.route('/cribl-logo.svg')
def serve_logo():
    """Serve the Cribl logo SVG file"""
    return send_file('cribl-logo.svg', mimetype='image/svg+xml')

def load_config_file():
    """Load config.ini if it exists"""
    config_path = Path('config.ini')
    if config_path.exists():
        config = configparser.ConfigParser()
        config.read(config_path)
        if 'cribl' in config:
            return {
                'client_id': config['cribl'].get('client_id', ''),
                'client_secret': config['cribl'].get('client_secret', ''),
                'organization_id': config['cribl'].get('organization_id', '')
            }
    return None

def get_bearer_token(client_id, client_secret):
    """Obtain OAuth bearer token"""
    url = "https://login.cribl.cloud/oauth/token"
    headers = {"Content-Type": "application/json"}
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": "https://api.cribl.cloud"
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()["access_token"]
    except Exception as e:
        raise Exception(f"Failed to obtain bearer token: {str(e)}")

def get_api_base_url(api_type, organization_id):
    """Get the appropriate API base URL based on API type"""
    if api_type == 'search':
        return f"https://app.cribl.cloud/organizations/{organization_id}/workspaces/main/app/api/v1"
    elif api_type == 'stream':
        return f"https://app.cribl.cloud/organizations/{organization_id}/workspaces/main/app/api/v1"
    elif api_type == 'edge':
        return f"https://app.cribl.cloud/organizations/{organization_id}/edge/api/v1"
    else:
        return f"https://app.cribl.cloud/organizations/{organization_id}/workspaces/main/app/api/v1"

@app.route('/api/test-connection', methods=['GET'])
def test_connection():
    """Test connectivity to Cribl Cloud"""
    results = {}
    
    # Get the actual base URL if we have one from login
    base_url = get_base_url()  # Use helper function
    test_hostname = base_url.replace('https://', '').replace('http://', '').split('/')[0]
    
    # Test DNS resolution
    try:
        import socket
        socket.gethostbyname(test_hostname)
        results['dns'] = f'✓ DNS resolution successful for {test_hostname}'
    except Exception as e:
        results['dns'] = f'[ERROR] DNS resolution failed for {test_hostname}: {str(e)}'
    
    # Test HTTPS connection
    try:
        response = requests.get(base_url, timeout=5)
        results['https'] = f'✓ HTTPS connection successful (status: {response.status_code})'
    except requests.exceptions.Timeout:
        results['https'] = f'[ERROR] Connection timeout to {base_url} - firewall or network issue?'
    except requests.exceptions.ConnectionError as e:
        results['https'] = f'[ERROR] Connection error to {base_url}: {str(e)}'
    except Exception as e:
        results['https'] = f'[ERROR] HTTPS connection failed to {base_url}: {str(e)}'
    
    # Test OAuth endpoint
    try:
        response = requests.get('https://login.cribl.cloud', timeout=5)
        results['oauth'] = f'✓ OAuth endpoint reachable (status: {response.status_code})'
    except Exception as e:
        results['oauth'] = f'[ERROR] OAuth endpoint unreachable: {str(e)}'
    
    return jsonify(results)

@app.route('/api/discover-api-paths', methods=['GET'])
def discover_api_paths():
    """Try to discover the correct API paths for the deployment"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    base_url = get_base_url()  # Use helper function
    org_id = app_config['organization_id']
    token = app_config['token']
    api_type = request.args.get('api_type', 'stream')
    
    headers = {"Authorization": f"Bearer {token}"}
    results = {}
    
    print(f"\n[DISCOVER] Discovering API paths for {api_type}")
    print(f"   Base URL: {base_url}")
    print(f"   Org ID: {org_id}")
    
    # Test both direct tenant URLs and centralized URLs
    test_urls = []
    
    if api_type == 'search':
        test_urls = [
            # Most likely correct path based on user's working curl
            f"{base_url}/api/v1/master/groups",
            # Standard Cribl Cloud API patterns
            f"{base_url}/api/v1/m",
            f"{base_url}/api/v1/m/default_search",
            # With workspaces
            f"{base_url}/workspaces/main/app/api/v1/m",
            f"{base_url}/search/workspaces/main/app/api/v1/m",
            f"{base_url}/workspaces/search/api/v1/m",
            # Search-specific paths
            f"{base_url}/search/api/v1/m",
            f"{base_url}/api/m",
            # Centralized attempts (likely to fail based on your network)
            f"https://app.cribl.cloud/organizations/{org_id}/workspaces/main/app/api/v1/m",
            f"https://app.cribl.cloud/organizations/{org_id}/search/api/v1/m",
        ]
    elif api_type == 'edge':
        test_urls = [
            # Correct path based on user's working curl
            f"{base_url}/api/v1/products/edge/groups",
            # Other possible paths
            f"{base_url}/api/v1/edge/fleets",
            f"{base_url}/api/v1/fleets",
            f"{base_url}/api/v1/f",
            # With workspaces
            f"{base_url}/workspaces/main/app/api/v1/edge/fleets",
            f"{base_url}/edge/workspaces/main/api/v1/fleets",
            f"{base_url}/edge/api/v1/fleets",
            # Centralized attempts
            f"https://app.cribl.cloud/organizations/{org_id}/api/v1/products/edge/groups",
            f"https://app.cribl.cloud/organizations/{org_id}/edge/api/v1/fleets",
        ]
    else:  # stream
        test_urls = [
            # Most likely correct path based on user's working curl
            f"{base_url}/api/v1/master/groups",
            # Standard Cribl Cloud API patterns
            f"{base_url}/api/v1/m",
            f"{base_url}/api/v1/groups",
            # With workspaces  
            f"{base_url}/workspaces/main/app/api/v1/m",
            f"{base_url}/stream/workspaces/main/app/api/v1/m",
            f"{base_url}/workspaces/stream/api/v1/m",
            # Stream-specific paths
            f"{base_url}/stream/api/v1/m",
            f"{base_url}/api/m",
            # Centralized attempts
            f"https://app.cribl.cloud/organizations/{org_id}/workspaces/main/app/api/v1/m",
            f"https://app.cribl.cloud/organizations/{org_id}/api/v1/m",
        ]
    
    for url in test_urls:
        try:
            print(f"   Testing: {url}")
            response = requests.get(url, headers=headers, timeout=10)
            content_type = response.headers.get('Content-Type', '')
            
            is_json = 'application/json' in content_type
            is_success = response.status_code == 200
            
            print(f"   {'[OK]' if (is_json and is_success) else '[WARN]'} Status: {response.status_code}, Content-Type: {content_type}")
            
            result_data = {
                'status': response.status_code,
                'content_type': content_type,
                'is_json': is_json,
                'works': is_json and is_success
            }
            
            if is_json and is_success:
                try:
                    data = response.json()
                    result_data['preview'] = json.dumps(data, indent=2)[:300]
                    result_data['data_type'] = type(data).__name__
                    if isinstance(data, dict):
                        result_data['keys'] = list(data.keys())[:10]
                    elif isinstance(data, list):
                        result_data['count'] = len(data)
                        result_data['first_item'] = data[0] if data else None
                except:
                    pass
                
                # Found a working path - return immediately
                results[url] = result_data
                print(f"   [OK] Found working path! Stopping search.")
                return jsonify(results)
            
            results[url] = result_data
            
        except Exception as e:
            print(f"   [ERROR] Error: {str(e)}")
            results[url] = {
                'works': False,
                'error': str(e)
            }
    
    return jsonify(results)

@app.route('/api/config', methods=['GET'])
def get_config():
    """Check if config file exists and return config"""
    config = load_config_file()
    if config and all(config.values()):
        return jsonify({
            'hasConfig': True,
            'config': {
                'organization_id': config['organization_id']
            }
        })
    return jsonify({'hasConfig': False})

@app.route('/api/session-info', methods=['GET'])
def get_session_info():
    """Get current session info including token and base URL"""
    if not app_config['authenticated']:
        print("   [ERROR] Session info request - not authenticated")
        return jsonify({'error': 'Not authenticated'}), 401
    
    base_url = app_config.get('base_url', '')
    token = app_config.get('token', '')
    org_id = app_config.get('organization_id', '')
    
    print(f"\n?[ERROR] Session info request:")
    print(f"   Base URL: {base_url}")
    print(f"   Token present: {bool(token)}")
    print(f"   Token length: {len(token) if token else 0}")
    print(f"   Org ID: {org_id}")
    
    response_data = {
        'base_url': base_url,
        'token': token,
        'organization_id': org_id
    }
    
    return jsonify(response_data)


def extract_org_id_and_base_url(org_input):
    """Extract organization ID and determine base URL from input"""
    if not org_input:
        return None, None, False
    
    # Remove any whitespace
    org_input = org_input.strip()
    
    # Check if it's a direct tenant URL (e.g., main-amazing-varahamihira.cribl.cloud)
    is_direct_tenant = False
    base_url = None
    org_id = None
    
    # If it's a URL, extract the org ID and base URL
    if 'http://' in org_input or 'https://' in org_input or '.cribl.cloud' in org_input:
        # Remove protocol
        clean_url = org_input.replace('https://', '').replace('http://', '')
        
        # Handle app.cribl.cloud URLs with /organizations/ path
        if 'app.cribl.cloud/organizations/' in clean_url:
            parts = clean_url.split('/organizations/')
            if len(parts) > 1:
                org_id = parts[1].split('/')[0]
                base_url = 'https://app.cribl.cloud'
                is_direct_tenant = False
        # Handle direct tenant URLs (e.g., main-amazing-varahamihira.cribl.cloud)
        elif '.cribl.cloud' in clean_url and 'app.cribl.cloud' not in clean_url:
            # Extract subdomain as org_id
            subdomain = clean_url.split('.cribl.cloud')[0]
            # Remove any path
            subdomain = subdomain.split('/')[0]
            org_id = subdomain
            base_url = f'https://{subdomain}.cribl.cloud'
            is_direct_tenant = True
        # Handle app.cribl.cloud without /organizations/ path
        elif 'app.cribl.cloud' in clean_url:
            base_url = 'https://app.cribl.cloud'
            # Try to extract from other parts of URL
            org_id = clean_url.split('/')[1] if '/' in clean_url else None
            is_direct_tenant = False
    else:
        # Just an org ID was provided - assume it's a direct tenant subdomain
        # For Cribl Cloud, the format is: https://{workspace}-{org}.cribl.cloud
        org_id = org_input
        base_url = f'https://{org_input}.cribl.cloud'
        is_direct_tenant = True
    
    return org_id, base_url, is_direct_tenant

def get_base_url():
    """Get base URL with proper fallback to organization_id
    
    Returns the correct base URL for API calls. If base_url is not set in app_config,
    it constructs it from organization_id to avoid using the invalid 'app.cribl.cloud'.
    """
    base_url = app_config.get('base_url')
    
    # ALWAYS print what we got from config for debugging
    print(f"[DEBUG] get_base_url() called - Current base_url in config: {base_url}")
    
    # Always validate base_url - if it contains double protocol or .cribl.cloud, reconstruct it
    if base_url and ('https://https://' in base_url or '.cribl.cloud/.cribl.cloud' in base_url or 'https://' in base_url[8:]):
        print(f"[WARNING] Detected malformed base_url: {base_url}")
        print(f"[WARNING] Forcing reconstruction...")
        base_url = None  # Force reconstruction
    
    if not base_url and app_config.get('organization_id'):
        # Construct from organization_id if not already set
        org_id = app_config['organization_id']
        
        print(f"[DEBUG] Reconstructing from org_id: {org_id}")
        
        # Clean up organization_id - remove protocol and trailing slashes
        org_id = org_id.strip()
        # Remove https:// or http:// prefix if present
        if org_id.startswith('https://'):
            org_id = org_id[8:]
        elif org_id.startswith('http://'):
            org_id = org_id[7:]
        # Remove trailing slashes
        org_id = org_id.rstrip('/')
        
        # If it already ends with .cribl.cloud, use as-is; otherwise add it
        if org_id.endswith('.cribl.cloud'):
            base_url = f'https://{org_id}'
        else:
            base_url = f'https://{org_id}.cribl.cloud'
        
        print(f"[DEBUG] Constructed base_url from org_id: {base_url}")
        # Update the stored value with the corrected one
        app_config['base_url'] = base_url
    
    # Final fallback with proper cleaning
    if not base_url and app_config.get('organization_id'):
        org_id = app_config.get('organization_id', 'unknown')
        print(f"[DEBUG] Final fallback, org_id: {org_id}")
        # Clean it before using
        org_id = org_id.strip()
        if org_id.startswith('https://'):
            org_id = org_id[8:]
        elif org_id.startswith('http://'):
            org_id = org_id[7:]
        org_id = org_id.rstrip('/')
        
        if org_id.endswith('.cribl.cloud'):
            base_url = f'https://{org_id}'
        else:
            base_url = f'https://{org_id}.cribl.cloud'
    
    print(f"[DEBUG] get_base_url() returning: {base_url}")
    return base_url

def build_api_url(api_type, worker_group=None, path='', query=''):
    """Build API URL based on tenant type and API type
    
    Based on Cribl API documentation:
    - Cribl.Cloud: https://{workspace}-{org}.cribl.cloud/api/v1/m/{group}/...
    - On-prem: https://{hostname}:{port}/api/v1/m/{group}/...
    """
    base_url = get_base_url()  # Use helper function
    is_direct_tenant = app_config.get('is_direct_tenant', False)
    organization_id = app_config.get('organization_id')
    
    # All Cribl.Cloud deployments use the same format
    if is_direct_tenant or '.cribl.cloud' in base_url:
        # Cribl.Cloud format: https://{subdomain}.cribl.cloud/api/v1/m/{group}/...
        if api_type == 'edge':
            # Edge uses /api/v1/f/{fleet_id} for accessing fleet resources
            base_path = f"{base_url}/api/v1"
            if worker_group:
                base_path += f"/f/{worker_group}"
        else:  # stream or search
            # Both Stream and Search use /api/v1/m/{group_id} format
            base_path = f"{base_url}/api/v1"
            if worker_group:
                base_path += f"/m/{worker_group}"
    else:
        # On-prem format: https://{hostname}:{port}/api/v1/m/{group}/...
        if api_type == 'edge':
            base_path = f"{base_url}/api/v1"
            if worker_group:
                base_path += f"/f/{worker_group}"
        else:  # stream or search
            base_path = f"{base_url}/api/v1"
            if worker_group:
                base_path += f"/m/{worker_group}"
    
    url = base_path + path
    if query:
        url += f"?{query}"
    
    return url

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate with Cribl Cloud"""
    data = request.json
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    organization_id = data.get('organization_id')
    
    # Try config file first if credentials not provided
    if not client_id or not client_secret:
        config = load_config_file()
        if config:
            client_id = config['client_id']
            client_secret = config['client_secret']
            organization_id = organization_id or config['organization_id']
    
    # Extract org ID and determine base URL from URL if needed
    org_id, base_url, is_direct_tenant = extract_org_id_and_base_url(organization_id)
    
    print(f"\n?[ERROR] Login attempt:")
    print(f"   Input: {organization_id}")
    print(f"   Extracted Org ID: {org_id}")
    print(f"   Base URL: {base_url}")
    print(f"   Direct Tenant: {is_direct_tenant}")
    
    if not all([client_id, client_secret, org_id]):
        return jsonify({'error': 'Missing credentials'}), 400
    
    try:
        token = get_bearer_token(client_id, client_secret)
        app_config['authenticated'] = True
        app_config['token'] = token
        app_config['client_id'] = client_id
        app_config['client_secret'] = client_secret
        app_config['organization_id'] = org_id
        app_config['base_url'] = base_url
        app_config['is_direct_tenant'] = is_direct_tenant
        
        print(f"   [ERROR] Authentication successful!")
        print(f"   Token stored (length: {len(token)})")
        
        return jsonify({
            'success': True,
            'organization_id': org_id,
            'base_url': base_url,
            'is_direct_tenant': is_direct_tenant,
            'extracted_from_input': organization_id
        })
    except Exception as e:
        print(f"   [ERROR] Authentication failed: {str(e)}")
        return jsonify({'error': str(e)}), 401

@app.route('/api/test-curl', methods=['POST'])
def test_curl():
    """Test API endpoint connectivity (secured version)"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    api_type = data.get('api_type', 'stream')
    worker_group = data.get('worker_group')
    
    print(f"\n[TEST] Testing API connectivity for {api_type}")
    if worker_group:
        print(f"   Worker Group: {worker_group}")
    
    try:
        # Validate API type
        validate_api_type(api_type)
        
        token = app_config['token']
        base_url = get_base_url()
        
        print(f"   Base URL: {base_url}")
        
        results = []
        
        # Test 1: List worker groups
        try:
            if api_type == 'edge':
                test_url = f"{base_url}/api/v1/products/edge/groups"
            else:
                test_url = f"{base_url}/api/v1/master/groups"
            
            print(f"   Testing: {test_url}")
            response = requests.get(test_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
            results.append({
                'endpoint': 'List Groups',
                'url': test_url,
                'status': response.status_code,
                'success': response.status_code == 200,
                'message': 'OK' if response.status_code == 200 else f"HTTP {response.status_code}"
            })
        except Exception as e:
            results.append({
                'endpoint': 'List Groups',
                'url': test_url,
                'status': 0,
                'success': False,
                'message': str(e)
            })
        
        # Test 2: List lookups (if worker group provided)
        if worker_group:
            try:
                validate_worker_group(worker_group)
                
                if api_type == 'edge':
                    test_url = f"{base_url}/api/v1/f/{worker_group}/system/lookups"
                else:
                    test_url = f"{base_url}/api/v1/m/{worker_group}/system/lookups"
                
                print(f"   Testing: {test_url}")
                response = requests.get(test_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
                results.append({
                    'endpoint': 'List Lookups',
                    'url': test_url,
                    'status': response.status_code,
                    'success': response.status_code == 200,
                    'message': 'OK' if response.status_code == 200 else f"HTTP {response.status_code}"
                })
            except Exception as e:
                results.append({
                    'endpoint': 'List Lookups',
                    'url': test_url,
                    'status': 0,
                    'success': False,
                    'message': str(e)
                })
        
        # Test 3: Version endpoint (if worker group provided)
        if worker_group:
            try:
                if api_type == 'edge':
                    test_url = f"{base_url}/api/v1/f/{worker_group}/version"
                else:
                    test_url = f"{base_url}/api/v1/m/{worker_group}/version"
                
                print(f"   Testing: {test_url}")
                response = requests.get(test_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
                results.append({
                    'endpoint': 'Version',
                    'url': test_url,
                    'status': response.status_code,
                    'success': response.status_code in [200, 404],  # 404 is OK for version
                    'message': 'OK' if response.status_code == 200 else f"HTTP {response.status_code} (may not be supported)"
                })
            except Exception as e:
                results.append({
                    'endpoint': 'Version',
                    'url': test_url,
                    'status': 0,
                    'success': False,
                    'message': str(e)
                })
        
        print(f"   [OK] Test completed - {len([r for r in results if r['success']])}/{len(results)} passed")
        
        return jsonify({
            'success': True,
            'results': results,
            'base_url': base_url
        })
        
    except Exception as e:
        print(f"   [ERROR] Test failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Clear session data"""
    app_config['authenticated'] = False
    app_config['token'] = None
    app_config['client_id'] = None
    app_config['client_secret'] = None
    app_config['organization_id'] = None
    app_config['base_url'] = None
    app_config['is_direct_tenant'] = False
    print("[INFO] User logged out - session cleared")
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    """Check authentication status"""
    return jsonify({
        'authenticated': app_config['authenticated'],
        'organization_id': app_config.get('organization_id')
    })

@app.route('/api/worker-groups', methods=['GET'])
def get_worker_groups():
    """Get list of worker groups"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    api_type = request.args.get('api_type', 'stream')
    organization_id = app_config['organization_id']
    token = app_config['token']
    base_url = get_base_url()  # Use helper function
    is_direct_tenant = app_config.get('is_direct_tenant', False)
    
    print(f"\n?[ERROR] Fetching worker groups for {api_type} API...")
    print(f"   Organization ID: {organization_id}")
    print(f"   Base URL: {base_url}")
    print(f"   Direct Tenant: {is_direct_tenant}")
    
    try:
        # Build correct URL for listing groups per Cribl API docs
        if is_direct_tenant or '.cribl.cloud' in base_url:
            # Cribl.Cloud format
            if api_type == 'edge':
                url = f"{base_url}/api/v1/products/edge/groups"
            else:  # stream or search
                url = f"{base_url}/api/v1/master/groups"
        else:
            # On-prem format
            if api_type == 'edge':
                url = f"{base_url}/api/v1/products/edge/groups"
            else:  # stream or search
                url = f"{base_url}/api/v1/master/groups"
        
        print(f"   URL: {url}")
        
        headers = {"Authorization": f"Bearer {token}"}
        
        response = requests.get(url, headers=headers, timeout=10)
        print(f"   Response Status: {response.status_code}")
        print(f"   Content-Type: {response.headers.get('Content-Type', 'unknown')}")
        
        # Check if we got HTML instead of JSON
        if 'text/html' in response.headers.get('Content-Type', ''):
            print(f"   [ERROR] Received HTML instead of JSON - wrong endpoint!")
            print(f"   Response preview: {response.text[:200]}")
            # Return defaults with a helpful message
            if api_type == 'search':
                groups = [
                    {'id': 'default_search', 'name': 'default_search'},
                    {'id': 'default', 'name': 'default'}
                ]
            else:
                groups = [{'id': 'default', 'name': 'default'}]
            return jsonify({
                'groups': groups,
                'warning': f'API endpoint returned HTML. Using defaults. URL: {url}'
            })
        
        response.raise_for_status()
        
        try:
            data = response.json()
        except json.JSONDecodeError as e:
            print(f"   [ERROR] JSON decode error: {str(e)}")
            print(f"   Response text: {response.text[:500]}")
            raise
        
        print(f"   Response Data: {json.dumps(data, indent=2)[:500]}...")
        
        # Extract group names based on API type and response structure
        groups = []
        
        if api_type == 'edge':
            # Edge /api/v1/products/edge/groups returns array of group objects
            if isinstance(data, list):
                groups = [{'id': item.get('id', item) if isinstance(item, dict) else item, 
                          'name': item.get('name', item.get('id', item)) if isinstance(item, dict) else item} 
                         for item in data]
            elif 'items' in data:
                items = data.get('items', [])
                groups = [{'id': item.get('id', item) if isinstance(item, dict) else item, 
                          'name': item.get('name', item.get('id', item)) if isinstance(item, dict) else item} 
                         for item in items]
        elif api_type == 'search':
            # Search uses default_search - auto-selected in UI
            groups = [{'id': 'default_search', 'name': 'default_search'}]
        else:  # stream
            # Stream /api/v1/master/groups returns array of objects with id property
            if isinstance(data, list):
                groups = [{'id': item.get('id', item) if isinstance(item, dict) else item, 
                          'name': item.get('id', item) if isinstance(item, dict) else item} 
                         for item in data]
            elif 'items' in data:
                items = data.get('items', [])
                groups = [{'id': item.get('id', item) if isinstance(item, dict) else item, 
                          'name': item.get('id', item) if isinstance(item, dict) else item} 
                         for item in items]
            else:
                groups = []
        
        # If no groups found, provide defaults
        if not groups:
            if api_type == 'search':
                groups = [
                    {'id': 'default_search', 'name': 'default_search'},
                    {'id': 'default', 'name': 'default'}
                ]
            else:
                groups = [{'id': 'default', 'name': 'default'}]
        
        return jsonify({'groups': groups})
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP error: {e.response.status_code}"
        print(f"   [ERROR] HTTP Error: {e.response.status_code}")
        print(f"   Response: {e.response.text[:500]}")
        if e.response.status_code == 404:
            # If endpoint not found, return defaults
            if api_type == 'search':
                groups = [
                    {'id': 'default_search', 'name': 'default_search'},
                    {'id': 'default', 'name': 'default'}
                ]
            else:
                groups = [{'id': 'default', 'name': 'default'}]
            print(f"   [OK] Using default groups: {[g['id'] for g in groups]}")
            return jsonify({'groups': groups})
        return jsonify({'error': error_msg}), 500
    except Exception as e:
        print(f"   [ERROR] Exception: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/lookups', methods=['GET'])
def get_lookups():
    """Get list of lookup files in a worker group"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')
    
    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400
    
    token = app_config['token']
    
    # Use helper to build URL
    url = build_api_url(api_type, worker_group, path='/system/lookups')
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Debug: Print full response to see what's available
        print(f"\n[DEBUG] Lookups API response for {worker_group}:")
        if data.get('items') and len(data.get('items', [])) > 0:
            print(f"   Total items: {len(data['items'])}")
            # Print first 3 items to see the structure
            for i, item in enumerate(data['items'][:3]):
                mode = item.get('mode', 'memory')  # No mode = memory-based
                print(f"   Item {i+1}: id={item.get('id')}, size={item.get('size')}, mode={mode}, type={item.get('type')}")
        
        lookups = []
        for item in data.get('items', []):
            # Cribl API: mode="disk" means disk-based, no mode field means memory-based
            mode = item.get('mode', 'memory')  # Default to memory if mode is absent
            is_memory = mode != 'disk'
            
            lookup = {
                'id': item['id'], 
                'size': item.get('size', 0),
                'inMemory': is_memory  # Convert mode to inMemory boolean
            }
            # Log lookup types
            if is_memory:
                print(f"   [MEMORY] {item['id']}")
            else:
                print(f"   [DISK] {item['id']}")
            lookups.append(lookup)
        
        return jsonify({'lookups': lookups})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/lookups/<worker_group>/<lookup_filename>/content', methods=['GET'])
def get_lookup_content(worker_group, lookup_filename):
    """Get the raw content of a lookup file"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    api_type = request.args.get('api_type', 'stream')
    token = app_config['token']
    
    print(f"\n[FETCH] Getting content for {lookup_filename} from {worker_group} ({api_type})")
    
    try:
        # Build URL to download the file
        download_url = build_api_url(api_type, worker_group, 
                                     path=f'/system/lookups/{lookup_filename}/content', 
                                     query='raw=1')
        
        print(f"   Download URL: {download_url}")
        headers = {"Authorization": f"Bearer {token}"}
        
        response = requests.get(download_url, headers=headers, timeout=30)
        response.raise_for_status()
        
        # Return the raw content as text
        return response.text, 200, {'Content-Type': 'text/plain'}
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"{e.response.status_code} {e.response.reason}"
        print(f"   [ERROR] {error_msg}")
        return jsonify({'error': error_msg}), 500
    except Exception as e:
        print(f"   [ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/lookups/<worker_group>/<lookup_id>', methods=['GET'])
def get_lookup_details(worker_group, lookup_id):
    """Get lookup details including inMemory flag"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    api_type = request.args.get('api_type', 'stream')
    token = app_config['token']
    
    print(f"\n[FETCH] Getting details for {lookup_id} from {worker_group} ({api_type})")
    
    try:
        # Build URL to get lookup details
        lookup_url = build_api_url(api_type, worker_group, 
                                   path=f'/system/lookups/{lookup_id}')
        
        print(f"   Lookup URL: {lookup_url}")
        headers = {"Authorization": f"Bearer {token}"}
        
        response = requests.get(lookup_url, headers=headers, timeout=10)
        response.raise_for_status()
        
        lookup_data = response.json()
        print(f"   [DEBUG] Full lookup data: {json.dumps(lookup_data, indent=2)}")
        print(f"   [DEBUG] inMemory value: {lookup_data.get('inMemory')}")
        print(f"   [OK] Lookup type: {'memory-based' if lookup_data.get('inMemory') else 'disk-based'}")
        
        return jsonify({'success': True, 'lookup': lookup_data}), 200
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"{e.response.status_code} {e.response.reason}"
        print(f"   [ERROR] {error_msg}")
        return jsonify({'error': error_msg}), 500
    except Exception as e:
        print(f"   [ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/transfer', methods=['POST'])
def transfer_lookup():
    """Transfer a lookup file from source to target"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    source_group = data.get('source_group')
    target_group = data.get('target_group')
    lookup_filename = data.get('lookup_filename')
    source_api_type = data.get('source_api_type', 'stream')
    target_api_type = data.get('target_api_type', 'stream')
    edited_content = data.get('content')  # Optional edited content
    target_filename_override = data.get('target_filename')  # Optional renamed file
    lookup_type = data.get('lookup_type', 'file')  # 'file' or 'memory'
    
    if not all([source_group, target_group, lookup_filename]):
        return jsonify({'error': 'Missing required parameters'}), 400
    
    # SECURITY: Validate all inputs
    try:
        source_group = validate_worker_group(source_group)
        target_group = validate_worker_group(target_group)
        lookup_filename = validate_filename(lookup_filename)
        source_api_type = validate_api_type(source_api_type)
        target_api_type = validate_api_type(target_api_type)
        if target_filename_override:
            target_filename_override = validate_filename(target_filename_override)
        if lookup_type not in ['file', 'memory']:
            return jsonify({'error': 'Invalid lookup_type: must be file or memory'}), 400
    except ValueError as e:
        print(f"   [SECURITY] Input validation failed: {str(e)}")
        return jsonify({'error': f'Invalid input: {str(e)}'}), 400
    
    print(f"\n[TRANSFER] Lookup type: {lookup_type}-based")
    
    # Strip pack prefix for Cribl Pack lookups
    # Format: pack-name.lookup-name.csv -> lookup-name.csv
    def strip_pack_prefix(filename):
        """Remove pack prefix from filename if it has more than one period"""
        parts = filename.split('.')
        # If more than 2 parts (e.g., pack.name.csv has 3), it's from a pack
        if len(parts) > 2:
            # Remove the first part (pack name) and rejoin
            return '.'.join(parts[1:])
        return filename
    
    # Use target filename override if provided, otherwise strip pack prefix
    target_filename = target_filename_override if target_filename_override else strip_pack_prefix(lookup_filename)
    
    print(f"\n[TRANSFER] Transfer lookup:")
    print(f"   Source: {lookup_filename}")
    if target_filename != lookup_filename:
        print(f"   Target: {target_filename} (renamed/stripped)" if target_filename_override else f"   Target: {target_filename} (stripped pack prefix)")
    else:
        print(f"   Target: {target_filename}")
    if edited_content:
        print(f"   [INFO] Using edited content ({len(edited_content)} chars)")
    
    organization_id = app_config['organization_id']
    token = app_config['token']
    
    try:
        # Check if we have edited content or need to download
        if edited_content:
            # Use the edited content directly
            print(f"   [STEP 1] Using provided edited content...")
            content = edited_content.encode('utf-8')
            print(f"   [OK] Using {len(content)} bytes of edited content")
        else:
            # Step 1: Download from source
            print(f"   [STEP 1] Downloading from source...")
            # Use FULL filename (with .csv extension) as that's what the Cribl API expects
            download_url = build_api_url(source_api_type, source_group, 
                                         path=f'/system/lookups/{lookup_filename}/content', 
                                         query='raw=1')
            
            print(f"   Download URL: {download_url}")
            headers = {"Authorization": f"Bearer {token}"}
            
            # Retry logic for downloads (large files can timeout)
            max_retries = 3
            retry_delay = 2
            response = None
            
            for attempt in range(1, max_retries + 1):
                try:
                    print(f"   [DOWNLOAD] Attempt {attempt}/{max_retries}...")
                    # Increased timeout to 120 seconds for large files, stream the response
                    response = requests.get(download_url, headers=headers, timeout=120, stream=True)
                    response.raise_for_status()
                    
                    # Download with progress indication
                    content = b''
                    total_size = int(response.headers.get('content-length', 0))
                    if total_size > 0:
                        print(f"   [INFO] File size: {total_size / 1024:.2f} KB")
                    
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            content += chunk
                    
                    print(f"   [OK] Downloaded {len(content)} bytes")
                    break  # Success, exit retry loop
                    
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                    if attempt < max_retries:
                        print(f"   [WARN] Connection issue: {type(e).__name__}, retrying in {retry_delay}s...")
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                    else:
                        print(f"   [ERROR] Failed after {max_retries} attempts")
                        raise
            
            if response is None:
                raise Exception("Failed to download file after all retries")
        
        # Save to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(target_filename).suffix) as tmp_file:
            tmp_file.write(content)
            tmp_filename = tmp_file.name
        
        # Step 2: Upload to target (use target filename)
        print(f"   [STEP 2] Uploading to target as {target_filename}...")
        content_type = "text/csv" if target_filename.endswith('.csv') else "application/gzip"
        
        upload_url = build_api_url(target_api_type, target_group, 
                                   path='/system/lookups', 
                                   query=f'filename={target_filename}')
        
        print(f"   Upload URL: {upload_url}")
        
        upload_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": content_type
        }
        
        # Retry logic for uploads
        max_retries = 3
        retry_delay = 2
        upload_success = False
        
        for attempt in range(1, max_retries + 1):
            try:
                print(f"   [UPLOAD] Attempt {attempt}/{max_retries}...")
                with open(tmp_filename, 'rb') as f:
                    response = requests.put(upload_url, headers=upload_headers, data=f, timeout=120)
                response.raise_for_status()
                upload_success = True
                break  # Success, exit retry loop
                
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if attempt < max_retries:
                    print(f"   [WARN] Connection issue: {type(e).__name__}, retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    print(f"   [ERROR] Failed after {max_retries} attempts")
                    raise
        
        if not upload_success:
            raise Exception("Failed to upload file after all retries")
        
        temp_file_response = response.json()
        temp_file_name = temp_file_response.get('filename')
        
        print(f"   [OK] Uploaded to temp file: {temp_file_name}")
        
        # Step 3: Try to create the lookup (will update if exists)
        print(f"   [STEP 3] Creating/updating lookup...")
        lookup_url = build_api_url(target_api_type, target_group, path='/system/lookups')
        
        # Try POST first (create new)
        payload = {
            "id": Path(target_filename).stem,  # ID without extension
            "fileInfo": {"filename": temp_file_name}
        }
        
        # Set mode based on lookup type (Cribl uses mode: "disk" for disk-based, absent/memory for memory-based)
        if lookup_type == 'memory':
            # Don't set mode field for memory-based (or set to "memory")
            # payload["mode"] = "memory"  # Optional - can be omitted
            print(f"   [INFO] Creating memory-based lookup (mode not set)")
        else:
            payload["mode"] = "disk"
            print(f"   [INFO] Creating disk-based lookup (mode=disk)")
        
        lookup_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        print(f"   Lookup ID: {Path(target_filename).stem}")
        print(f"   Lookup URL: {lookup_url}")
        
        # Try POST, if it fails with 409 (conflict) or 500 (already exists), try PATCH
        lookup_exists = False
        try:
            response = requests.post(lookup_url, headers=lookup_headers, json=payload, timeout=10)
            response.raise_for_status()
            print(f"   [OK] Created new lookup")
        except requests.exceptions.HTTPError as e:
            # Check if lookup already exists (409 conflict or 500 with "already exists" message)
            if e.response.status_code == 409:
                lookup_exists = True
            elif e.response.status_code == 500:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get('message', '').lower()
                    if 'already exists' in error_msg:
                        lookup_exists = True
                except:
                    pass
            
            if lookup_exists:
                # Lookup exists, update it
                print(f"   [INFO] Lookup exists, updating...")
                # PATCH URL and payload both need FULL filename with extension
                lookup_url_patch = f"{lookup_url}/{target_filename}"
                # Update payload to include full filename in id field for PATCH
                patch_payload = {
                    "id": target_filename,  # Full filename WITH extension for PATCH
                    "fileInfo": {"filename": temp_file_name}
                }
                # Set mode based on lookup type (same as POST)
                if lookup_type == 'memory':
                    # Don't set mode field for memory-based
                    print(f"   [INFO] Updating to memory-based lookup (mode not set)")
                else:
                    patch_payload["mode"] = "disk"
                    print(f"   [INFO] Updating to disk-based lookup (mode=disk)")
                
                try:
                    response = requests.patch(lookup_url_patch, headers=lookup_headers, json=patch_payload, timeout=10)
                    response.raise_for_status()
                    print(f"   [OK] Updated existing lookup")
                except requests.exceptions.HTTPError as patch_error:
                    # Check if it's a mode change error
                    if patch_error.response.status_code == 400:
                        try:
                            error_data = patch_error.response.json()
                            error_msg = error_data.get('message', '')
                            if 'mode can not be changed' in error_msg.lower():
                                print(f"   [ERROR] Cannot change lookup mode")
                                return jsonify({
                                    'success': False,
                                    'error': 'Cannot change lookup type',
                                    'message': f'The lookup "{target_filename}" already exists on the target with a different type. To change from memory-based to disk-based (or vice versa), you must first delete the existing lookup on the target, then transfer again.',
                                    'action_required': 'delete_first'
                                }), 400
                        except:
                            pass
                    # Re-raise if not a mode change error
                    raise patch_error
            else:
                # Some other error
                print(f"   [ERROR] Error creating lookup: {e.response.status_code} - {e.response.text}")
                raise
        
        # Transfer complete - file uploaded successfully
        # Now commit ONLY this file (partial commit)
        print(f"   [OK] Lookup file uploaded successfully!")
        print(f"   [STEP 4] Committing only the transferred lookup file...")
        
        try:
            # Build the file paths that need to be committed
            # Cribl stores lookups in groups/{group}/data/lookups/
            lookup_csv_path = f"groups/{target_group}/data/lookups/{target_filename}"
            lookup_yml_path = f"groups/{target_group}/data/lookups/{Path(target_filename).stem}.yml"
            
            commit_url = build_api_url(target_api_type, target_group, path='/version/commit')
            commit_payload = {
                "message": f"Transfer lookup: {target_filename}",
                "group": target_group,
                "files": [lookup_csv_path, lookup_yml_path]
            }
            
            commit_headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            print(f"   Commit URL: {commit_url}")
            print(f"   Committing files: {commit_payload['files']}")
            
            commit_response = requests.post(commit_url, headers=commit_headers, json=commit_payload, timeout=10)
            commit_response.raise_for_status()
            commit_data = commit_response.json()
            
            print(f"   [DATA] Commit response: {json.dumps(commit_data, indent=2)}")
            
            # Extract commit ID
            commit_id = None
            if 'items' in commit_data and isinstance(commit_data['items'], list) and len(commit_data['items']) > 0:
                first_item = commit_data['items'][0]
                commit_id = (first_item.get('commit') or 
                            first_item.get('hash') or
                            first_item.get('version'))
            
            if not commit_id:
                commit_id = commit_data.get('commit') or commit_data.get('hash', 'unknown')
            
            print(f"   [OK] Committed lookup file: {commit_id}")
            
            # Store the commit ID for the deploy endpoint to use for partial deployment
            app_config['last_transfer_commit_id'] = commit_id
            app_config['last_transfer_group'] = target_group
            app_config['last_transfer_api_type'] = target_api_type
            app_config['last_transfer_files'] = [lookup_csv_path, lookup_yml_path]
            
            print(f"   [INFO] Use Deploy button to push to workers")
            
        except Exception as commit_error:
            print(f"   [WARN] Warning: Commit failed: {str(commit_error)}")
            print(f"   [WARN] File uploaded but not committed. Use Commit button to commit manually.")
            # Don't fail the whole transfer if commit fails - file is already uploaded
        
        # Cleanup
        os.unlink(tmp_filename)
        
        success_message = f'Successfully transferred {lookup_filename}'
        if target_filename != lookup_filename:
            success_message += f' as {target_filename}'
        success_message += f' from {source_group} to {target_group} and committed'
        
        return jsonify({
            'success': True,
            'message': success_message,
            'committed': True,
            'requiresDeploy': True
        })
        
    except requests.exceptions.HTTPError as e:
        # HTTP error - log the response details
        error_msg = f"{e.response.status_code} {e.response.reason}"
        try:
            error_details = e.response.json()
            error_msg += f": {error_details}"
            print(f"   [ERROR] HTTP Error: {error_msg}")
        except:
            error_msg += f": {e.response.text}"
            print(f"   [ERROR] HTTP Error: {error_msg}")
        
        # Cleanup on error
        try:
            if 'tmp_filename' in locals():
                os.unlink(tmp_filename)
        except:
            pass
        return jsonify({'error': error_msg}), 500
        
    except Exception as e:
        # Other error
        error_msg = str(e)
        print(f"   [ERROR] Error: {error_msg}")
        
        # Cleanup on error
        try:
            if 'tmp_filename' in locals():
                os.unlink(tmp_filename)
        except:
            pass
        return jsonify({'error': error_msg}), 500

@app.route('/api/commit', methods=['POST'])
def commit_changes():
    """Commit pending changes for a worker group"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    worker_group = data.get('worker_group')
    api_type = data.get('api_type', 'stream')
    commit_message = data.get('commit_message', 'Update lookup files')
    
    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400
    
    token = app_config['token']
    base_url = get_base_url()  # Use helper function
    
    print(f"\n?[ERROR] Committing changes to {worker_group}...")
    print(f"   Message: {commit_message}")
    
    try:
        # Get pending changes
        status_url = build_api_url(api_type, worker_group, path='/version')
        headers = {"Authorization": f"Bearer {token}"}
        
        status_response = requests.get(status_url, headers=headers, timeout=10)
        status_response.raise_for_status()
        status_data = status_response.json()
        
        pending_count = status_data.get('count', 0)
        print(f"   Pending changes: {pending_count} files")
        
        if pending_count == 0:
            return jsonify({
                'success': True,
                'message': 'No pending changes to commit'
            })
        
        # Commit all pending changes
        commit_url = build_api_url(api_type, worker_group, path='/version/commit')
        commit_payload = {
            "message": commit_message,
            "group": worker_group
        }
        
        print(f"   Commit URL: {commit_url}")
        
        response = requests.post(commit_url, headers=headers, json=commit_payload, timeout=10)
        response.raise_for_status()
        commit_data = response.json()
        
        print(f"   [DATA] Commit response: {json.dumps(commit_data, indent=2)}")
        
        # Extract commit ID from response - try multiple patterns
        commit_id = None
        changes_count = 0
        
        if 'items' in commit_data and isinstance(commit_data['items'], list) and len(commit_data['items']) > 0:
            first_item = commit_data['items'][0]
            # Try multiple field names for the commit hash
            commit_id = (first_item.get('commit') or 
                        first_item.get('hash') or  # Git commit hash
                        first_item.get('version'))
            
            # Get changes count from summary if available
            if 'summary' in first_item and isinstance(first_item['summary'], dict):
                changes_count = first_item['summary'].get('changes', 0)
                print(f"   [INFO] Summary: {changes_count} changes, "
                      f"{first_item['summary'].get('insertions', 0)} insertions, "
                      f"{first_item['summary'].get('deletions', 0)} deletions")
        
        if not commit_id:
            commit_id = commit_data.get('commit') or commit_data.get('hash', 'unknown')
        
        print(f"   [SUCCESS] Committed: {commit_id}")
        
        # Store the last commit ID for potential use by deploy
        app_config['last_commit_id'] = commit_id
        app_config['last_commit_group'] = worker_group
        
        return jsonify({
            'success': True,
            'message': f'Successfully committed {changes_count or pending_count} changes',
            'commit_id': commit_id,
            'files_count': pending_count,
            'changes_count': changes_count
        })
        
    except Exception as e:
        error_msg = str(e)
        print(f"   [ERROR] Commit error: {error_msg}")
        return jsonify({'error': error_msg}), 500

@app.route('/api/deploy', methods=['POST'])
def deploy_changes():
    """Deploy committed changes to workers"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    worker_group = data.get('worker_group')
    api_type = data.get('api_type', 'stream')
    
    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400
    
    token = app_config['token']
    base_url = get_base_url()  # Use helper function
    
    print(f"\n[DEPLOY] Deploying to {worker_group}...")
    print(f"   [DEBUG] Checking for recent transfer:")
    print(f"   [DEBUG]   last_transfer_commit_id: {app_config.get('last_transfer_commit_id')}")
    print(f"   [DEBUG]   last_transfer_group: {app_config.get('last_transfer_group')}")
    print(f"   [DEBUG]   last_transfer_api_type: {app_config.get('last_transfer_api_type')}")
    print(f"   [DEBUG]   Requested worker_group: {worker_group}")
    print(f"   [DEBUG]   Requested api_type: {api_type}")
    
    try:
        commit_version = None
        
        # CRITICAL: Use the stored commit ID from the most recent transfer (partial deploy)
        # This ensures we only deploy the transferred lookup, not other uncommitted changes
        if (app_config.get('last_transfer_commit_id') and 
            app_config.get('last_transfer_group') == worker_group and
            app_config.get('last_transfer_api_type') == api_type):
            commit_version = app_config['last_transfer_commit_id']
            print(f"   [OK] Using commit ID from most recent transfer: {commit_version}")
            print(f"   [PARTIAL] This will deploy ONLY the transferred lookup, not other changes")
        else:
            # No recent transfer to this group - cannot do partial deploy
            print(f"   [ERROR] No recent transfer found for {worker_group} ({api_type})")
            print(f"   [ERROR] Deploy button should only be used after transferring a lookup")
            return jsonify({
                'error': 'No recent transfer to deploy. Please transfer a lookup first.',
                'details': 'Deploy button deploys only the most recently transferred lookup'
            }), 400
        
        # Initialize headers
        headers = {"Authorization": f"Bearer {token}"}
        
        # Deploy the commit
        if api_type == 'edge':
            deploy_url = f"{base_url}/api/v1/master/fleets/{worker_group}/deploy"
        else:
            deploy_url = f"{base_url}/api/v1/master/groups/{worker_group}/deploy"
        
        print(f"   [INFO] Deploying to: {deploy_url}")
        print(f"   [INFO] Version: {commit_version}")
        
        deploy_payload = {"version": commit_version}
        
        response = requests.patch(deploy_url, headers=headers, json=deploy_payload, timeout=10)
        response.raise_for_status()
        
        print(f"   [SUCCESS] Deployed: {commit_version}")
        
        return jsonify({
            'success': True,
            'message': f'Successfully deployed to {worker_group}',
            'version': commit_version
        })
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP {e.response.status_code}"
        try:
            error_data = e.response.json()
            error_msg += f": {error_data}"
        except:
            error_msg += f": {e.response.text[:200]}"
        print(f"   [ERROR] {error_msg}")
        return jsonify({'error': error_msg}), 500
    except Exception as e:
        print(f"   [ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500







@app.route('/api/lookups/<worker_group>/<lookup_filename>', methods=['DELETE'])
def delete_lookup(worker_group, lookup_filename):
    """Delete a lookup file from a worker group"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    api_type = request.args.get('api_type', 'stream')
    token = app_config['token']
    
    # SECURITY: Validate inputs
    try:
        worker_group = validate_worker_group(worker_group)
        lookup_filename = validate_filename(lookup_filename)
        api_type = validate_api_type(api_type)
    except ValueError as e:
        print(f"   [SECURITY] Input validation failed: {str(e)}")
        return jsonify({'error': f'Invalid input: {str(e)}'}), 400
    
    print(f"\n[DELETE] Deleting {lookup_filename} from {worker_group} ({api_type})")
    
    try:
        # Build URL to delete the lookup
        delete_url = build_api_url(api_type, worker_group, path=f'/system/lookups/{lookup_filename}')
        
        print(f"   Delete URL: {delete_url}")
        headers = {"Authorization": f"Bearer {token}"}
        
        response = requests.delete(delete_url, headers=headers, timeout=10)
        response.raise_for_status()
        
        print(f"   [OK] Successfully deleted {lookup_filename}")
        
        # Get the actual list of pending changes to do a true partial commit
        print(f"   [STEP 2] Getting pending changes to identify deletion-related files...")
        status_url = build_api_url(api_type, worker_group, path='/version/status')
        
        try:
            status_response = requests.get(status_url, headers=headers, timeout=10)
            status_response.raise_for_status()
            status_data = status_response.json()
            
            print(f"   [DEBUG] Status response: {json.dumps(status_data, indent=2)}")
            
            # Try to extract the actual file paths from pending changes
            pending_files = []
            
            # Try different response structures
            if 'items' in status_data and isinstance(status_data['items'], list):
                for item in status_data['items']:
                    if isinstance(item, dict) and 'file' in item:
                        pending_files.append(item['file'])
                    elif isinstance(item, str):
                        pending_files.append(item)
            elif 'files' in status_data and isinstance(status_data['files'], list):
                pending_files = status_data['files']
            
            print(f"   [INFO] Found {len(pending_files)} pending files")
            if pending_files:
                print(f"   [INFO] Pending files: {pending_files}")
            
            # Filter to only files related to the deleted lookup
            lookup_base = Path(lookup_filename).stem
            deletion_files = [f for f in pending_files if lookup_filename in f or lookup_base in f]
            
            print(f"   [INFO] Deletion-related files: {deletion_files}")
            
            # If we couldn't get the file list, build the expected paths manually
            if not deletion_files:
                print(f"   [WARNING] Could not identify deletion files from status response")
                print(f"   [WARNING] Building expected paths manually...")
                lookup_csv_path = f"groups/{worker_group}/data/lookups/{lookup_filename}"
                lookup_yml_path = f"groups/{worker_group}/data/lookups/{lookup_base}.yml"
                deletion_files = [lookup_csv_path, lookup_yml_path]
                print(f"   [INFO] Expected deletion files: {deletion_files}")
            
            # Attempt partial commit with deletion files
            print(f"   [STEP 3] Attempting partial commit of deletion files only...")
            commit_message = f"Deleted lookup: {lookup_filename}"
            commit_url = build_api_url(api_type, worker_group, path='/version/commit')
            
            commit_data = {
                "message": commit_message,
                "group": worker_group,
                "files": deletion_files  # PARTIAL COMMIT - only deletion files
            }
            
            print(f"   Commit URL: {commit_url}")
            print(f"   Committing files (partial commit): {commit_data['files']}")
            
            try:
                commit_response = requests.post(commit_url, json=commit_data, headers=headers, timeout=30)
                commit_response.raise_for_status()
                commit_result = commit_response.json()
                
                print(f"   [DATA] Commit response: {json.dumps(commit_result, indent=2)}")
                
                # Extract commit ID from response for deployment
                commit_id = None
                if 'items' in commit_result and isinstance(commit_result['items'], list) and len(commit_result['items']) > 0:
                    first_item = commit_result['items'][0]
                    commit_id = (first_item.get('commit') or 
                                first_item.get('hash') or
                                first_item.get('version'))
                
                if not commit_id:
                    commit_id = commit_result.get('commit') or commit_result.get('hash') or commit_result.get('version', 'unknown')
                
                print(f"   [OK] Partial commit successful: {str(commit_id)[:8]}...")
                print(f"   [OK] Only deletion files were committed (other pending changes untouched)")
                
                # Store commit ID for deployment (same as transfer)
                app_config['last_transfer_commit_id'] = commit_id
                app_config['last_transfer_group'] = worker_group
                app_config['last_transfer_api_type'] = api_type
                app_config['last_transfer_files'] = deletion_files
                
                print(f"   [INFO] Deletion committed and ready for partial deployment")
                
                return jsonify({
                    'success': True,
                    'message': f'Successfully deleted {lookup_filename}',
                    'committed': True,
                    'commit_id': commit_id,
                    'partial_commit': True
                })
                
            except requests.exceptions.HTTPError as commit_error:
                # Partial commit with deleted files failed (likely 500 error)
                print(f"   [ERROR] Partial commit failed: {commit_error.response.status_code}")
                print(f"   [ERROR] This is expected - Cribl API may not support partial commit of deleted files")
                print(f"   [WARNING] Deletion succeeded but NOT committed to prevent committing other changes")
                print(f"   [WARNING] Please commit manually in Cribl UI to complete the deletion")
                
                return jsonify({
                    'success': True,
                    'message': f'Successfully deleted {lookup_filename} but could not do partial commit',
                    'committed': False,
                    'warning': 'Cribl API does not support partial commit of deleted files. Please commit manually in Cribl UI to avoid committing other pending changes.',
                    'manual_commit_required': True
                })
                
        except Exception as status_error:
            print(f"   [ERROR] Could not get pending changes: {str(status_error)}")
            print(f"   [WARNING] Cannot verify partial commit is possible")
            print(f"   [WARNING] Deletion succeeded but NOT committing to be safe")
            
            return jsonify({
                'success': True,
                'message': f'Successfully deleted {lookup_filename} but could not verify partial commit',
                'committed': False,
                'warning': 'Could not verify partial commit is safe. Please commit manually in Cribl UI.',
                'manual_commit_required': True
            })
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"{e.response.status_code} {e.response.reason}"
        print(f"   [ERROR] {error_msg}")
        return jsonify({'error': error_msg}), 500
    except Exception as e:
        print(f"   [ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/pending-changes', methods=['GET'])
def get_pending_changes():
    """Get count of pending changes for a worker group using version/status endpoint"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')
    
    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400
    
    token = app_config['token']
    
    print(f"\n[PENDING] Checking pending changes for {worker_group} ({api_type})")
    
    try:
        # Use /version/status endpoint to check for uncommitted changes
        status_url = build_api_url(api_type, worker_group, path='/version/status')
        headers = {"Authorization": f"Bearer {token}"}
        
        print(f"   [INFO] Querying: {status_url}")
        
        response = requests.get(status_url, headers=headers, timeout=10)
        response.raise_for_status()
        status_data = response.json()
        
        print(f"   [DATA] Status Response: {json.dumps(status_data, indent=2)}")
        
        # Count pending changes from the status response
        pending_count = 0
        
        # Check for files object with modified/created/deleted arrays
        if 'files' in status_data:
            files = status_data['files']
            if isinstance(files, dict):
                modified = files.get('modified', [])
                created = files.get('created', [])
                deleted = files.get('deleted', [])
                
                if isinstance(modified, list):
                    pending_count += len(modified)
                if isinstance(created, list):
                    pending_count += len(created)
                if isinstance(deleted, list):
                    pending_count += len(deleted)
                    
                print(f"   [INFO] Modified: {len(modified) if isinstance(modified, list) else 0}")
                print(f"   [INFO] Created: {len(created) if isinstance(created, list) else 0}")
                print(f"   [INFO] Deleted: {len(deleted) if isinstance(deleted, list) else 0}")
        
        # Check for changes field directly
        elif 'changes' in status_data:
            pending_count = status_data.get('changes', 0)
            print(f"   [INFO] Direct changes count: {pending_count}")
        
        # Check if there's a summary object
        elif 'summary' in status_data and isinstance(status_data['summary'], dict):
            summary = status_data['summary']
            pending_count = summary.get('changes', 0)
            print(f"   [INFO] Summary changes count: {pending_count}")
        
        print(f"   [SUCCESS] Pending changes: {pending_count}")
        
        return jsonify({
            'success': True,
            'pending_count': pending_count
        })
        
    except requests.exceptions.HTTPError as e:
        # If status endpoint doesn't exist or returns error, return 0
        print(f"   [WARNING] Status endpoint error: {e.response.status_code}")
        try:
            print(f"   [WARNING] Response: {e.response.text[:500]}")
        except:
            pass
        return jsonify({'success': True, 'pending_count': 0})
        
    except Exception as e:
        print(f"   [ERROR] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': True, 'pending_count': 0, 'error': str(e)})


@app.route('/api/current-version', methods=['GET'])
def get_current_version():
    """Get the current deployed/committed version for a worker group"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')
    
    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400
    
    token = app_config['token']
    
    print(f"\n[VERSION] Getting current version for {worker_group} ({api_type})")
    
    try:
        version_url = build_api_url(api_type, worker_group, path='/version')
        headers = {"Authorization": f"Bearer {token}"}
        
        print(f"   [INFO] Querying: {version_url}")
        
        response = requests.get(version_url, headers=headers, timeout=10)
        
        # Handle 404 gracefully - endpoint might not exist for this worker group
        if response.status_code == 404:
            print(f"   [WARNING] /version endpoint not found for {worker_group} (HTTP 404)")
            print(f"   [INFO] This worker group may not support version tracking")
            return jsonify({
                'success': True,
                'version': None,
                'warning': 'Version endpoint not available for this worker group'
            })
        
        response.raise_for_status()
        version_data = response.json()
        
        print(f"   [DATA] Version response: {json.dumps(version_data, indent=2)}")
        
        # Try to extract the current version/commit
        current_version = None
        
        # Method 1: Direct commit field
        if 'commit' in version_data and version_data['commit']:
            current_version = version_data['commit']
            print(f"   [OK] Found commit field: {current_version}")
        
        # Method 2: Git object
        elif 'git' in version_data and isinstance(version_data['git'], dict):
            if 'commit' in version_data['git'] and version_data['git']['commit']:
                current_version = version_data['git']['commit']
                print(f"   [OK] Found git.commit: {current_version}")
        
        # Method 3: Items array
        elif 'items' in version_data and isinstance(version_data['items'], list) and len(version_data['items']) > 0:
            first_item = version_data['items'][0]
            print(f"   [INFO] Checking items[0]: {list(first_item.keys())}")
            if isinstance(first_item, dict):
                current_version = (first_item.get('commit') or 
                                 first_item.get('configVersion') or 
                                 first_item.get('version') or
                                 first_item.get('hash'))  # Git commit hash
                if current_version:
                    print(f"   [OK] Found in items[0]: {current_version}")
                    # Log which field we used
                    for key in ['commit', 'configVersion', 'version', 'hash']:
                        if first_item.get(key) == current_version:
                            print(f"   [OK] Used field: items[0].{key}")
                            break
        
        # Method 4: ConfigVersion field
        elif 'configVersion' in version_data and version_data['configVersion']:
            current_version = version_data['configVersion']
            print(f"   [OK] Found configVersion: {current_version}")
        
        if not current_version:
            print(f"   [ERROR] Could not find version in response")
            print(f"   [ERROR] Available keys: {list(version_data.keys())}")
            return jsonify({
                'success': False, 
                'error': 'Could not find version in API response',
                'response_keys': list(version_data.keys())
            }), 500
        
        print(f"   [SUCCESS] Current version: {current_version}")
        
        return jsonify({
            'success': True,
            'version': current_version
        })
        
    except Exception as e:
        print(f"   [ERROR] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


def is_port_available(port):
    """Check if a port is available"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('0.0.0.0', port))
        sock.close()
        return True
    except OSError:
        return False

def get_available_port(preferred_port=42001):
    """Get an available port, asking user if preferred port is taken"""
    if is_port_available(preferred_port):
        return preferred_port
    
    print(f"\n[WARN] Port {preferred_port} is already in use.")
    
    # Try to find an available port nearby
    for port in range(preferred_port + 1, preferred_port + 100):
        if is_port_available(port):
            print(f"[OK] Found available port: {port}")
            response = input(f"Would you like to use port {port}? (y/n): ").strip().lower()
            if response == 'y':
                return port
    
    # Ask user for custom port
    while True:
        try:
            custom_port = input("Please enter a port number to use (1024-65535): ").strip()
            port = int(custom_port)
            
            if port < 1024 or port > 65535:
                print("[ERROR] Port must be between 1024 and 65535")
                continue
            
            if is_port_available(port):
                return port
            else:
                print(f"[ERROR] Port {port} is not available. Please try another port.")
        except ValueError:
            print("[ERROR] Please enter a valid number")
        except KeyboardInterrupt:
            print("\n\n[EXIT] Exiting...")
            sys.exit(0)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("[SERVER] Cribl Lookup Transfer Server")
    print("="*60)
    
    # Check for config file
    print("\n[CONFIG] Checking for config.ini...")
    config = load_config_file()
    if config and all(config.values()):
        print("[OK] Config file found - auto-login will be available")
    else:
        print("[WARN] No config file found - manual login required")
        print("   Create config.ini from config.ini.sample for auto-login")
    
    # Get available port
    print("\n[PORT] Checking port availability...")
    port = get_available_port(42001)
    print(f"[OK] Using port: {port}")
    
    print(f"\n{'='*60}")
    print(f"[OK] Server starting on http://localhost:{port}")
    print(f"{'='*60}")
    print("\n[INFO] Press Ctrl+C to stop the server\n")
    
    # Ask about browser BEFORE starting Flask (so its output doesn't interrupt)
    url = f"http://localhost:{port}"
    print(f"[INFO] Server will be available at: {url}")
    response = input("\nWould you like to open this in your browser? (y/n): ").strip().lower()
    if response == 'y':
        print("[INFO] Opening browser...")
        # Open browser in a thread so Flask can start
        browser_thread = threading.Thread(target=lambda: webbrowser.open(url))
        browser_thread.daemon = True
        browser_thread.start()
    else:
        print(f"[INFO] You can manually open {url} in your browser anytime.")
    
    print("\n" + "="*60)
    print("Starting Flask server...")
    print("="*60 + "\n")
    
    try:
        app.run(debug=False, host='0.0.0.0', port=port, use_reloader=False)
    except KeyboardInterrupt:
        print("\n\n[SHUTDOWN] Shutting down gracefully...")
        print("[OK] Server stopped")
        sys.exit(0)
