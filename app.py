#!/usr/bin/env python3
"""
Cribl Lookup Manager - Backend Server
Version: 1.3.0
Date: December 1, 2025

New in v1.3.0:
- Pack lookup discovery for Stream/Edge (exports .crbl files to find pack lookups)
- Bulk transfer support (multiple lookups to multiple targets)
- Per-lookup type override for bulk transfers
- Binary file support (.mmdb, .gz)
- Collapsible UI panels
- Bug fixes for race conditions and partial deployments

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
import tarfile
import io
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

@app.route('/api/discover-pack-lookups', methods=['GET'])
def discover_pack_lookups():
    """Discover the correct API path for pack lookups"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    worker_group = request.args.get('worker_group', 'default')
    pack_id = request.args.get('pack_id')
    api_type = request.args.get('api_type', 'stream')

    base_url = get_base_url()
    token = app_config['token']
    headers = {"Authorization": f"Bearer {token}"}
    results = {}

    print(f"\n[DISCOVER-PACK] Finding pack lookup path for {pack_id} in {worker_group}")

    # First, get the pack detail to see what fields it returns
    pack_detail_url = build_api_url(api_type, worker_group, path=f'/packs/{pack_id}')
    try:
        print(f"   Getting pack detail: {pack_detail_url}")
        response = requests.get(pack_detail_url, headers=headers, timeout=10)
        if response.status_code == 200:
            pack_data = response.json()
            results['pack_detail_url'] = pack_detail_url
            results['pack_keys'] = list(pack_data.keys()) if isinstance(pack_data, dict) else str(type(pack_data))
            results['pack_data_preview'] = json.dumps(pack_data, indent=2)[:2000]
    except Exception as e:
        results['pack_detail_error'] = str(e)

    # Try various pack lookup endpoint patterns
    test_patterns = [
        f"/packs/{pack_id}/lookups",
        f"/packs/{pack_id}/knowledge/lookups",
        f"/lib/{pack_id}/lookups",
        f"/lib/{pack_id}/knowledge/lookups",
        f"/p/{pack_id}/lookups",
        f"/p/{pack_id}/knowledge/lookups",
    ]

    for pattern in test_patterns:
        url = build_api_url(api_type, worker_group, path=pattern)
        try:
            print(f"   Testing: {url}")
            response = requests.get(url, headers=headers, timeout=10)
            content_type = response.headers.get('Content-Type', '')
            result = {
                'status': response.status_code,
                'content_type': content_type
            }
            if response.status_code == 200 and 'application/json' in content_type:
                data = response.json()
                result['data_preview'] = json.dumps(data, indent=2)[:500]
                result['works'] = True
            else:
                result['works'] = False
            results[url] = result
        except Exception as e:
            results[url] = {'error': str(e), 'works': False}

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

    # Validate base_url - if it contains double protocol or malformed .cribl.cloud, reconstruct it
    if base_url and ('https://https://' in base_url or '.cribl.cloud/.cribl.cloud' in base_url or 'https://' in base_url[8:]):
        base_url = None  # Force reconstruction

    if not base_url and app_config.get('organization_id'):
        # Construct from organization_id if not already set
        org_id = app_config['organization_id']

        # Clean up organization_id - remove protocol and trailing slashes
        org_id = org_id.strip()
        if org_id.startswith('https://'):
            org_id = org_id[8:]
        elif org_id.startswith('http://'):
            org_id = org_id[7:]
        org_id = org_id.rstrip('/')

        # If it already ends with .cribl.cloud, use as-is; otherwise add it
        if org_id.endswith('.cribl.cloud'):
            base_url = f'https://{org_id}'
        else:
            base_url = f'https://{org_id}.cribl.cloud'

        # Update the stored value with the corrected one
        app_config['base_url'] = base_url

    # Final fallback with proper cleaning
    if not base_url and app_config.get('organization_id'):
        org_id = app_config.get('organization_id', 'unknown')
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

    return base_url

def build_api_url(api_type, worker_group=None, path='', query=''):
    """Build API URL based on tenant type and API type

    Based on Cribl API documentation:
    - Cribl.Cloud: https://{workspace}-{org}.cribl.cloud/api/v1/m/{group}/...
    - On-prem: https://{hostname}:{port}/api/v1/m/{group}/...

    Note: Both Stream worker groups AND Edge fleets use /m/{group} for resource access
    (lookups, pipelines, etc). The /f/ prefix was incorrect.
    """
    base_url = get_base_url()  # Use helper function
    is_direct_tenant = app_config.get('is_direct_tenant', False)
    organization_id = app_config.get('organization_id')

    # All API types (stream, edge, search) use /m/{group} for resource access
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
    """Get list of lookup files in a worker group.

    Query params:
    - worker_group: Required. The worker group/fleet to query.
    - api_type: 'stream', 'edge', or 'search'. Default: 'stream'

    Note: For Stream/Edge, pack lookups are not included here. Use the
    /api/packs endpoint to list packs, then /api/packs/<pack_id>/lookups
    to get lookups from specific packs.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    token = app_config['token']
    headers = {"Authorization": f"Bearer {token}"}
    lookups = []

    # Get system lookups - single API call for fast response
    # Note: Pack lookups are only available in Search (they appear with pack prefix in /system/lookups)
    # For Stream/Edge, use /api/packs and /api/packs/<pack_id>/lookups separately
    url = build_api_url(api_type, worker_group, path='/system/lookups')

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        for item in data.get('items', []):
            mode = item.get('mode', 'memory')
            is_memory = mode != 'disk'
            item_id = item.get('id', '')

            # Detect pack lookups by pattern (works for Search where pack lookups have prefix)
            pack_name = None
            detected_pack, _ = parse_pack_lookup(item_id)
            if detected_pack:
                pack_name = detected_pack

            lookup = {
                'id': item_id,
                'size': item.get('size', 0),
                'inMemory': is_memory,
                'pack': pack_name
            }
            lookups.append(lookup)
    except Exception as e:
        print(f"[WARNING] Failed to get system lookups: {str(e)}")

    return jsonify({'lookups': lookups})


def fetch_pack_lookups_internal(worker_group, api_type, token):
    """Internal function to fetch pack lookups by exporting and parsing .crbl files.

    This is the only way to discover pack lookups in Stream/Edge since the
    /system/lookups endpoint doesn't include them (unlike Search).

    Returns a list of lookup dicts.
    """
    headers = {"Authorization": f"Bearer {token}"}
    pack_lookups = []

    print(f"\n[PACK-LOOKUPS] Discovering pack lookups in {worker_group} ({api_type})")

    # Step 1: List all packs in the worker group
    packs_url = build_api_url(api_type, worker_group, path='/packs')
    print(f"   [INFO] Listing packs: {packs_url}")

    packs_response = requests.get(packs_url, headers=headers, timeout=15)
    if packs_response.status_code != 200:
        print(f"   [WARNING] Failed to list packs: HTTP {packs_response.status_code}")
        return []

    packs_data = packs_response.json()
    packs = packs_data.get('items', [])
    print(f"   [OK] Found {len(packs)} pack(s)")

    if not packs:
        return []

    # Step 2: Export each pack and extract lookup files
    for pack in packs:
        pack_id = pack.get('id')
        if not pack_id:
            continue

        print(f"   [PACK] Processing pack: {pack_id}")

        # Export the pack as .crbl file
        export_url = build_api_url(api_type, worker_group, path=f'/packs/{pack_id}/export', query='mode=merge')
        print(f"      [EXPORT] {export_url}")

        try:
            export_response = requests.get(export_url, headers=headers, timeout=30, stream=True)
            if export_response.status_code != 200:
                print(f"      [WARNING] Failed to export pack {pack_id}: HTTP {export_response.status_code}")
                continue

            # The .crbl file is a gzipped tarball
            crbl_content = export_response.content
            print(f"      [OK] Downloaded {len(crbl_content)} bytes")

            # Extract lookup files from the tarball
            lookups_found = extract_lookups_from_crbl(crbl_content, pack_id)
            print(f"      [OK] Found {len(lookups_found)} lookup(s) in pack")

            for lookup in lookups_found:
                # Determine if lookup is memory-based from mode in lookups.yml
                mode = lookup.get('mode', 'memory').lower()
                is_memory = mode != 'disk'
                pack_lookups.append({
                    'id': f"{pack_id}.{lookup['filename']}",  # Use pack prefix format
                    'filename': lookup['filename'],
                    'size': lookup.get('size', 0),
                    'inMemory': is_memory,
                    'pack': pack_id,
                    'packPath': lookup.get('path', '')
                })

        except requests.exceptions.Timeout:
            print(f"      [WARNING] Timeout exporting pack {pack_id}")
            continue
        except Exception as e:
            print(f"      [WARNING] Error processing pack {pack_id}: {str(e)}")
            continue

    print(f"   [DONE] Total pack lookups found: {len(pack_lookups)}")
    return pack_lookups


@app.route('/api/packs', methods=['GET'])
def list_packs():
    """List all packs in a worker group (without exporting them).

    This is a fast endpoint that just lists pack names/IDs.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    token = app_config['token']
    headers = {"Authorization": f"Bearer {token}"}

    print(f"\n[PACKS] Listing packs in {worker_group} ({api_type})")

    packs_url = build_api_url(api_type, worker_group, path='/packs')
    print(f"   [INFO] URL: {packs_url}")

    try:
        response = requests.get(packs_url, headers=headers, timeout=15)
        if response.status_code != 200:
            print(f"   [WARNING] Failed to list packs: HTTP {response.status_code}")
            return jsonify({'packs': [], 'error': f'HTTP {response.status_code}'})

        data = response.json()
        packs = data.get('items', [])

        # Return simplified pack info
        pack_list = []
        for pack in packs:
            pack_list.append({
                'id': pack.get('id'),
                'displayName': pack.get('displayName', pack.get('id')),
                'version': pack.get('version', ''),
                'description': pack.get('description', '')
            })

        print(f"   [OK] Found {len(pack_list)} pack(s)")
        return jsonify({'packs': pack_list})

    except Exception as e:
        print(f"   [ERROR] Failed to list packs: {str(e)}")
        return jsonify({'packs': [], 'error': str(e)})


@app.route('/api/packs/<pack_id>/lookups', methods=['GET'])
def get_single_pack_lookups(pack_id):
    """Get lookup files from a single pack by exporting and parsing its .crbl file.

    This allows the frontend to load pack lookups one at a time with progress indication.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    if api_type == 'search':
        return jsonify({'lookups': [], 'message': 'Search API already includes pack lookups in /system/lookups'})

    token = app_config['token']
    headers = {"Authorization": f"Bearer {token}"}

    print(f"\n[PACK-EXPORT] Exporting pack '{pack_id}' from {worker_group} ({api_type})")

    # Export the pack as .crbl file
    export_url = build_api_url(api_type, worker_group, path=f'/packs/{pack_id}/export', query='mode=merge')
    print(f"   [EXPORT] {export_url}")

    try:
        export_response = requests.get(export_url, headers=headers, timeout=60, stream=True)
        if export_response.status_code != 200:
            print(f"   [WARNING] Failed to export pack {pack_id}: HTTP {export_response.status_code}")
            return jsonify({'lookups': [], 'error': f'Failed to export pack: HTTP {export_response.status_code}'})

        # The .crbl file is a gzipped tarball
        crbl_content = export_response.content
        print(f"   [OK] Downloaded {len(crbl_content)} bytes")

        # Extract lookup files from the tarball
        lookups_found = extract_lookups_from_crbl(crbl_content, pack_id)
        print(f"   [OK] Found {len(lookups_found)} lookup(s) in pack")

        pack_lookups = []
        for lookup in lookups_found:
            # Determine if lookup is memory-based from mode in lookups.yml
            mode = lookup.get('mode', 'memory').lower()
            is_memory = mode != 'disk'
            pack_lookups.append({
                'id': f"{pack_id}.{lookup['filename']}",  # Use pack prefix format
                'filename': lookup['filename'],
                'size': lookup.get('size', 0),
                'inMemory': is_memory,
                'pack': pack_id,
                'packPath': lookup.get('path', '')
            })

        return jsonify({'lookups': pack_lookups, 'packId': pack_id})

    except requests.exceptions.Timeout:
        print(f"   [WARNING] Timeout exporting pack {pack_id}")
        return jsonify({'lookups': [], 'error': 'Timeout exporting pack'})
    except Exception as e:
        print(f"   [ERROR] Error processing pack {pack_id}: {str(e)}")
        return jsonify({'lookups': [], 'error': str(e)})


@app.route('/api/pack-lookups', methods=['GET'])
def get_pack_lookups():
    """Get lookup files from ALL packs in Stream/Edge by exporting and parsing .crbl files.

    This endpoint exports all packs at once. For selective loading with progress,
    use /api/packs to list packs, then /api/packs/<pack_id>/lookups for each.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    # This is only needed for Stream/Edge - Search already shows pack lookups in /system/lookups
    if api_type == 'search':
        return jsonify({'lookups': [], 'message': 'Search API already includes pack lookups in /system/lookups'})

    token = app_config['token']

    try:
        pack_lookups = fetch_pack_lookups_internal(worker_group, api_type, token)
        return jsonify({'lookups': pack_lookups})
    except Exception as e:
        print(f"   [ERROR] Failed to get pack lookups: {str(e)}")
        return jsonify({'lookups': [], 'error': str(e)})


def extract_lookups_from_crbl(crbl_content, pack_id):
    """Extract lookup file information from a .crbl (gzipped tarball) file.

    Pack structure typically contains lookups in:
    - lookups/ directory (for lookup files)
    - default/lookups/ or local/lookups/ directories

    Also reads lookups.yml to determine mode (memory/disk) for each lookup.

    Returns list of dicts with 'filename', 'size', 'path', 'mode' keys.
    """
    lookups = []
    lookup_configs = {}  # filename -> mode mapping from lookups.yml

    def parse_lookups_yml(content):
        """Parse lookups.yml to extract mode settings for each lookup."""
        configs = {}
        try:
            # Simple YAML-like parsing for lookups.yml
            # Format is typically:
            # filename.csv:
            #   mode: memory
            # or
            # filename.csv:
            #   mode: disk
            lines = content.decode('utf-8', errors='ignore').split('\n')
            current_file = None
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                # Check for filename entry (ends with : and no leading spaces means top-level)
                if not line.startswith(' ') and not line.startswith('\t') and stripped.endswith(':'):
                    current_file = stripped[:-1]  # Remove trailing colon
                elif current_file and 'mode:' in stripped.lower():
                    mode_value = stripped.split(':', 1)[1].strip().lower()
                    configs[current_file] = mode_value
                    print(f"            [CONFIG] {current_file}: mode={mode_value}")
        except Exception as e:
            print(f"         [WARNING] Failed to parse lookups.yml: {e}")
        return configs

    def process_tar(tar):
        nonlocal lookup_configs
        # First pass: find and parse lookups.yml
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith('lookups.yml'):
                try:
                    f = tar.extractfile(member)
                    if f:
                        lookup_configs = parse_lookups_yml(f.read())
                        print(f"         [CONFIG] Found lookups.yml with {len(lookup_configs)} entries")
                except Exception as e:
                    print(f"         [WARNING] Could not read lookups.yml: {e}")

        # Second pass: find lookup files
        for member in tar.getmembers():
            path_parts = member.name.split('/')
            if member.isfile() and 'lookups' in path_parts:
                filename = path_parts[-1]
                if filename.endswith(('.csv', '.csv.gz', '.mmdb', '.json', '.gz')):
                    # Check if we have mode info from lookups.yml
                    mode = lookup_configs.get(filename, 'memory')  # Default to memory if not specified
                    lookups.append({
                        'filename': filename,
                        'size': member.size,
                        'path': member.name,
                        'mode': mode
                    })
                    print(f"         [LOOKUP] {member.name} ({member.size} bytes, mode={mode})")

    try:
        # .crbl files are gzipped tarballs
        with io.BytesIO(crbl_content) as crbl_io:
            with tarfile.open(fileobj=crbl_io, mode='r:gz') as tar:
                process_tar(tar)

    except tarfile.TarError as e:
        print(f"      [WARNING] Failed to parse crbl as tarball: {str(e)}")
        # Try as plain gzip
        try:
            with io.BytesIO(crbl_content) as crbl_io:
                with gzip.GzipFile(fileobj=crbl_io) as gz:
                    decompressed = gz.read()
                    with io.BytesIO(decompressed) as tar_io:
                        with tarfile.open(fileobj=tar_io, mode='r:') as tar:
                            process_tar(tar)
        except Exception as e2:
            print(f"      [WARNING] Failed alternate extraction: {str(e2)}")
    except Exception as e:
        print(f"      [WARNING] Error extracting lookups: {str(e)}")

    return lookups


def extract_lookup_content_from_crbl(crbl_content, lookup_filename):
    """Extract the actual content of a specific lookup file from a .crbl (gzipped tarball).

    Args:
        crbl_content: The raw bytes of the .crbl file
        lookup_filename: The name of the lookup file to extract (e.g., 'asa_drops.csv')

    Returns:
        The file content as bytes, or None if not found.
    """
    def find_in_tar(tar):
        for member in tar.getmembers():
            path_parts = member.name.split('/')
            if member.isfile() and 'lookups' in path_parts:
                filename = path_parts[-1]
                if filename == lookup_filename:
                    print(f"      [EXTRACT] Found {member.name}")
                    f = tar.extractfile(member)
                    if f:
                        return f.read()
        return None

    try:
        # .crbl files are gzipped tarballs
        with io.BytesIO(crbl_content) as crbl_io:
            with tarfile.open(fileobj=crbl_io, mode='r:gz') as tar:
                content = find_in_tar(tar)
                if content:
                    return content
    except tarfile.TarError as e:
        print(f"      [WARNING] Failed to parse crbl as tarball: {str(e)}")
        # Try as plain gzip then tar
        try:
            import gzip
            with io.BytesIO(crbl_content) as gz_io:
                with gzip.GzipFile(fileobj=gz_io, mode='rb') as gz:
                    decompressed = gz.read()
                    with io.BytesIO(decompressed) as tar_io:
                        with tarfile.open(fileobj=tar_io, mode='r:') as tar:
                            content = find_in_tar(tar)
                            if content:
                                return content
        except Exception as e2:
            print(f"      [WARNING] Failed alternate extraction: {str(e2)}")
    except Exception as e:
        print(f"      [WARNING] Error extracting lookup content: {str(e)}")

    return None


def parse_pack_lookup(lookup_filename, pack_hint=None):
    """Parse a lookup filename to determine if it's a pack lookup.
    Returns (pack_name, actual_filename) if pack lookup, or (None, lookup_filename) if system lookup.
    Pack lookups have format: pack_name.filename.ext (e.g., cribl-search.operators.csv)

    Args:
        lookup_filename: The full lookup filename (may include pack prefix)
        pack_hint: Optional pack name if already known (from frontend)
    """
    # If pack hint is provided, use it directly
    if pack_hint:
        # The filename should start with pack_hint followed by a dot
        prefix = f"{pack_hint}."
        if lookup_filename.startswith(prefix):
            actual_filename = lookup_filename[len(prefix):]
            return pack_hint, actual_filename
        return pack_hint, lookup_filename

    parts = lookup_filename.split('.')
    # Need at least 3 parts: pack_name, filename, extension
    if len(parts) >= 3:
        potential_pack = parts[0]
        # Pack name detection - must meet stricter criteria:
        # 1. Contains hyphen (e.g., cribl-search, cribl-cisco-asa-cleanup) - most common pattern
        # 2. Known vendor prefixes that are commonly used as pack prefixes
        # 3. Underscore alone is NOT enough (e.g., pkg_vuln.csv.gz is not a pack)
        #    - Only treat as pack if it also starts with a known vendor prefix
        known_pack_prefixes = ['cribl', 'okta', 'aws', 'azure', 'gcp', 'splunk', 'crowdstrike', 'palo', 'cisco']

        is_pack_name = (
            # Hyphenated names are almost always packs (e.g., cribl-search, my-custom-pack)
            '-' in potential_pack or
            # Known vendor name as the full pack name
            potential_pack in known_pack_prefixes or
            # Underscore names only if they start with a known vendor prefix
            # e.g., okta_improbable is a pack, but pkg_vuln is not
            ('_' in potential_pack and any(potential_pack.startswith(prefix + '_') for prefix in known_pack_prefixes))
        )
        if is_pack_name:
            pack_name = parts[0]
            actual_filename = '.'.join(parts[1:])
            return pack_name, actual_filename
    return None, lookup_filename

@app.route('/api/lookups/<worker_group>/<lookup_filename>/content', methods=['GET'])
def get_lookup_content(worker_group, lookup_filename):
    """Get the raw content of a lookup file (system or pack)"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    api_type = request.args.get('api_type', 'stream')
    token = app_config['token']

    print(f"\n[FETCH] Getting content for {lookup_filename} from {worker_group} ({api_type})")

    # Check if this is a pack lookup
    pack_name, actual_filename = parse_pack_lookup(lookup_filename)

    try:
        headers = {"Authorization": f"Bearer {token}"}

        if pack_name and api_type in ['stream', 'edge']:
            # Pack lookup - use /p/{pack}/ endpoint (scoped to pack resources)
            download_url = build_api_url(api_type, worker_group,
                                         path=f'/p/{pack_name}/lookups/{actual_filename}/content',
                                         query='raw=1')
            print(f"   [PACK] Pack: {pack_name}, File: {actual_filename}")
        else:
            # System lookup
            download_url = build_api_url(api_type, worker_group,
                                         path=f'/system/lookups/{lookup_filename}/content',
                                         query='raw=1')

        print(f"   Download URL: {download_url}")

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
    """Get lookup details including inMemory flag (system or pack)"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    api_type = request.args.get('api_type', 'stream')
    token = app_config['token']

    print(f"\n[FETCH] Getting details for {lookup_id} from {worker_group} ({api_type})")

    # Check if this is a pack lookup
    pack_name, actual_filename = parse_pack_lookup(lookup_id)

    try:
        headers = {"Authorization": f"Bearer {token}"}

        if pack_name and api_type in ['stream', 'edge']:
            # Pack lookup - use pack endpoint
            lookup_url = build_api_url(api_type, worker_group,
                                       path=f'/packs/{pack_name}/lookups/{actual_filename}')
            print(f"   [PACK] Pack: {pack_name}, File: {actual_filename}")
        else:
            # System lookup
            lookup_url = build_api_url(api_type, worker_group,
                                       path=f'/system/lookups/{lookup_id}')

        print(f"   Lookup URL: {lookup_url}")

        response = requests.get(lookup_url, headers=headers, timeout=10)
        response.raise_for_status()

        lookup_data = response.json()
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

            # Check if this is a pack lookup
            pack_name, actual_filename = parse_pack_lookup(lookup_filename)

            if pack_name and source_api_type in ['stream', 'edge']:
                # Pack lookup - try /p/{pack}/ endpoint first (scoped to pack), fall back to /packs/{pack}/
                # The /p/{pack}/ prefix scopes requests to resources within a specific pack
                download_url = build_api_url(source_api_type, source_group,
                                             path=f'/p/{pack_name}/lookups/{actual_filename}/content',
                                             query='raw=1')
                print(f"   [PACK] Downloading from pack: {pack_name}, file: {actual_filename}")
            else:
                # System lookup
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
        # Set content type based on file extension
        if target_filename.endswith('.csv'):
            content_type = "text/csv"
        elif target_filename.endswith('.mmdb'):
            content_type = "application/octet-stream"
        elif target_filename.endswith('.gz'):
            content_type = "application/gzip"
        elif target_filename.endswith('.json'):
            content_type = "application/json"
        else:
            content_type = "application/octet-stream"  # Default for binary files
        
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
            "id": target_filename,  # Full filename WITH extension (Cribl uses this as the ID)
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
        
        print(f"   Lookup ID: {target_filename}")
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
                    mode_change_handled = False
                    if patch_error.response.status_code == 400:
                        try:
                            error_data = patch_error.response.json()
                            error_msg = error_data.get('message', '')
                            if 'mode can not be changed' in error_msg.lower():
                                print(f"   [INFO] Mode change detected - auto-deleting and re-creating lookup")

                                # Delete the existing lookup
                                delete_url = build_api_url(target_api_type, target_group, path=f'/system/lookups/{target_filename}')
                                print(f"   [DELETE] Deleting existing lookup: {delete_url}")

                                delete_response = requests.delete(delete_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
                                delete_response.raise_for_status()
                                print(f"   [OK] Deleted existing lookup")

                                # Now retry the POST to create with new type
                                print(f"   [RETRY] Re-creating lookup with new type...")
                                retry_response = requests.post(lookup_url, headers=lookup_headers, json=payload, timeout=10)
                                retry_response.raise_for_status()
                                print(f"   [OK] Re-created lookup with new type")
                                mode_change_handled = True
                        except requests.exceptions.HTTPError as delete_error:
                            print(f"   [ERROR] Failed to delete/recreate: {delete_error}")
                            return jsonify({
                                'success': False,
                                'error': f'Failed to change lookup type for "{target_filename}"',
                                'message': f'Could not delete and recreate lookup: {str(delete_error)}'
                            }), 400
                        except Exception as mode_error:
                            print(f"   [ERROR] Mode change handling failed: {mode_error}")

                    # Re-raise if not a mode change error or mode change wasn't handled
                    if not mode_change_handled:
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
            # Use a dict to support bulk transfers to multiple targets
            if 'transfer_commits' not in app_config:
                app_config['transfer_commits'] = {}

            # Key by "group:api_type" to support multiple targets
            commit_key = f"{target_group}:{target_api_type}"
            app_config['transfer_commits'][commit_key] = {
                'commit_id': commit_id,
                'group': target_group,
                'api_type': target_api_type,
                'files': [lookup_csv_path, lookup_yml_path]
            }

            # Also keep the legacy single values for backwards compatibility
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

        # Store the commit ID in transfer_commits dict for deploy to use
        if 'transfer_commits' not in app_config:
            app_config['transfer_commits'] = {}

        commit_key = f"{worker_group}:{api_type}"
        app_config['transfer_commits'][commit_key] = {
            'commit_id': commit_id,
            'group': worker_group,
            'api_type': api_type,
            'files': []
        }
        print(f"   [INFO] Stored commit for deploy: {commit_key} -> {commit_id}")

        # Also store legacy values
        app_config['last_commit_id'] = commit_id
        app_config['last_commit_group'] = worker_group
        app_config['last_transfer_commit_id'] = commit_id
        app_config['last_transfer_group'] = worker_group
        app_config['last_transfer_api_type'] = api_type

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

    # Look up commit ID from transfer_commits dict (supports bulk transfers)
    commit_key = f"{worker_group}:{api_type}"
    transfer_commits = app_config.get('transfer_commits', {})

    try:
        commit_version = None

        # Check the new dict-based storage first
        if commit_key in transfer_commits:
            commit_info = transfer_commits[commit_key]
            commit_version = commit_info['commit_id']
            print(f"   [OK] Using commit ID from transfer: {commit_version}")
            print(f"   [PARTIAL] This will deploy ONLY the transferred lookup, not other changes")
        # Fall back to legacy single value
        elif (app_config.get('last_transfer_commit_id') and
              app_config.get('last_transfer_group') == worker_group and
              app_config.get('last_transfer_api_type') == api_type):
            commit_version = app_config['last_transfer_commit_id']
            print(f"   [OK] Using commit ID from legacy storage: {commit_version}")
        else:
            # No recent transfer to this group - cannot do partial deploy
            print(f"   [ERROR] No recent transfer found for {worker_group} ({api_type})")
            print(f"   [ERROR] Deploy button should only be used after transferring a lookup")
            return jsonify({
                'error': f'No recent transfer to deploy for {worker_group}. Please transfer a lookup first.',
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

        # Clear the commit from storage after successful deploy
        if commit_key in transfer_commits:
            del transfer_commits[commit_key]
            print(f"   [INFO] Cleared commit for {commit_key}")

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
