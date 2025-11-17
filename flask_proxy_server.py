from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
from datetime import datetime, timedelta
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from collections import Counter
import re

app = Flask(__name__, static_folder='.')
CORS(app)

# Mist API Configuration
MIST_CONFIG = {
    'base_url': 'https://api.ac5.mist.com/api/v1',
    'org_id': 'ab23e4f0-82fc-4758-8153-ed7aacb24336',
    'access_token': 'cNfM9IUSfCOBno1eU80eGldJZtxF3e4BgAPQSU4AM9WvGnDAYE6lgDbbK9lygEEiCa6uao9pcls1td05IIFfMXd2J5lMFKjn'
}

# Perplexity AI Configuration
PERPLEXITY_CONFIG = {
    'api_key': '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',
    'api_url': 'https://api.perplexity.ai/chat/completions',
    'model': 'sonar'
}

# Thread-safe cache for AP and WLAN mappings
cache = {
    'sites': {},
    'aps': {},
    'wlans': {}
}
cache_lock = threading.Lock()

# API Intent Pattern Mapping - Maps user queries to Mist API endpoints
API_PATTERNS = {
    'synthetic_test': {
        'keywords': ['dhcp', 'dns', 'arp', 'synthetic test', 'connectivity test', 'dhcp latency', 
                     'dns latency', 'gateway', 'marvis test', 'network test'],
        'endpoints': ['synthetic_test_results', 'synthetic_test_details'],
        'description': 'DHCP/DNS/ARP connectivity testing'
    },
    'client_stats': {
        'keywords': ['signal', 'rssi', 'snr', 'noise', 'channel', 'bandwidth', 'throughput', 
                     'speed', 'rate', 'wireless stats', 'client performance', 'connection quality'],
        'endpoints': ['client_stats'],
        'description': 'Client wireless statistics'
    },
    'client_events': {
        'keywords': ['events', 'history', 'connection log', 'disconnection', 'authentication', 
                     'event log', 'connection history', 'failures', 'what happened'],
        'endpoints': ['client_events'],
        'description': 'Client connection event history'
    },
    'ap_stats': {
        'keywords': ['ap stats', 'access point', 'ap performance', 'ap utilization', 
                     'ap channel', 'ap clients', 'device stats'],
        'endpoints': ['ap_stats', 'site_devices'],
        'description': 'Access Point statistics'
    },
    'wlan_config': {
        'keywords': ['wlan', 'ssid config', 'vlan', 'ssid settings', 'wlan template', 
                     'network config', 'ssid', 'wireless network'],
        'endpoints': ['site_wlans'],
        'description': 'WLAN/SSID configuration'
    },
    'alarms': {
        'keywords': ['alarm', 'alert', 'issue', 'problem', 'error', 'warning', 'critical'],
        'endpoints': ['org_alarms', 'site_alarms'],
        'description': 'Network alarms and alerts'
    },
    'site_clients': {
        'keywords': ['all clients', 'connected clients', 'active clients', 'client list', 
                     'how many clients'],
        'endpoints': ['site_clients'],
        'description': 'All connected clients on site'
    },
    'troubleshoot': {
        'keywords': ['troubleshoot', 'diagnose', 'marvis suggestion', 'recommendation', 
                     'what to check', 'root cause'],
        'endpoints': ['marvis_troubleshoot'],
        'description': 'Marvis AI troubleshooting'
    }
}

def get_headers():
    """Generate authentication headers for Mist API"""
    return {
        'Authorization': f'Token {MIST_CONFIG["access_token"]}',
        'Content-Type': 'application/json'
    }

def format_mac_to_colon(mac):
    """Convert MAC address to colon format"""
    mac_clean = mac.replace(':', '').replace('-', '').replace('.', '').strip()
    return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2)).lower()

def get_all_sites():
    """Fetch all sites in the organization"""
    try:
        url = f"{MIST_CONFIG['base_url']}/orgs/{MIST_CONFIG['org_id']}/sites"
        response = requests.get(url, headers=get_headers(), timeout=30)
        response.raise_for_status()
        sites = response.json()

        with cache_lock:
            for site in sites:
                cache['sites'][site['id']] = site['name']

        return sites
    except Exception as e:
        print(f"❌ Error fetching sites: {str(e)}")
        return []

def get_site_aps(site_id):
    """Fetch all APs for a specific site"""
    try:
        url = f"{MIST_CONFIG['base_url']}/sites/{site_id}/devices"
        response = requests.get(url, headers=get_headers(), timeout=30)
        response.raise_for_status()
        devices = response.json()

        with cache_lock:
            for device in devices:
                if device.get('type') == 'ap':
                    cache['aps'][device['mac']] = device.get('name', device['mac'])

        return devices
    except Exception as e:
        print(f"❌ Error fetching APs for site {site_id}: {str(e)}")
        return []

def get_site_wlans(site_id):
    """Fetch all WLANs for a specific site"""
    try:
        url = f"{MIST_CONFIG['base_url']}/sites/{site_id}/wlans"
        response = requests.get(url, headers=get_headers(), timeout=30)
        response.raise_for_status()
        wlans = response.json()

        with cache_lock:
            for wlan in wlans:
                cache['wlans'][wlan['id']] = wlan.get('ssid', wlan['id'])

        return wlans
    except Exception as e:
        print(f"❌ Error fetching WLANs for site {site_id}: {str(e)}")
        return []

def search_client_in_site(site, mac_no_colon):
    """Search for a client in a specific site (thread-safe function)"""
    site_id = site['id']
    site_name = site['name']
    
    try:
        search_url = f"{MIST_CONFIG['base_url']}/sites/{site_id}/clients/search"
        params = {
            'mac': mac_no_colon,
            'limit': 100,
            'duration': '7d'
        }

        print(f"  → Checking site: {site_name}")
        response = requests.get(search_url, headers=get_headers(), params=params, timeout=10)

        if response.status_code == 200:
            search_data = response.json()
            if search_data.get('results'):
                client_found = search_data['results'][0]
                print(f"✅ Client found in site: {site_name}")
                return {
                    'found': True,
                    'client': client_found,
                    'site_id': site_id,
                    'site_name': site_name
                }
    except Exception as e:
        print(f"  ⚠️ Error checking site {site_name}: {str(e)}")
    
    return {'found': False}

def get_ap_name(ap_mac):
    """Get AP name from MAC address"""
    with cache_lock:
        return cache['aps'].get(ap_mac, ap_mac)

def get_wlan_name(wlan_id):
    """Get WLAN name from WLAN ID"""
    with cache_lock:
        return cache['wlans'].get(wlan_id, wlan_id)

def get_site_name(site_id):
    """Get site name from site ID"""
    with cache_lock:
        return cache['sites'].get(site_id, site_id)

# ============================================================================
# INTELLIGENT API ROUTING - Maps user queries to Mist API calls
# ============================================================================

def detect_api_intent(question, context):
    """
    Analyze user question and determine which Mist APIs to call
    Returns dictionary of intents with confidence scores
    """
    question_lower = question.lower()
    detected_intents = {}
    
    for intent_name, intent_config in API_PATTERNS.items():
        # Check if any keywords match
        matches = sum(1 for keyword in intent_config['keywords'] if keyword in question_lower)
        if matches > 0:
            detected_intents[intent_name] = {
                'confidence': matches,
                'endpoints': intent_config['endpoints'],
                'description': intent_config['description']
            }
    
    # Sort by confidence (number of keyword matches)
    detected_intents = dict(sorted(detected_intents.items(), 
                                  key=lambda x: x[1]['confidence'], 
                                  reverse=True))
    
    return detected_intents

def fetch_synthetic_test_data(site_id, mac_address):
    """
    Fetch synthetic test data (DHCP/DNS/ARP/Application)
    Two-step process:
    1. Get test results to find latest test_id
    2. Get test details using test_id
    """
    try:
        end_time = int(datetime.now().timestamp())
        start_time = int((datetime.now() - timedelta(days=7)).timestamp())
        
        # Step 1: Get test results to find test_id
        url = f"{MIST_CONFIG['base_url']}/labs/orgs/{MIST_CONFIG['org_id']}/synthetic_test"
        params = {
            'q': 'test_results',
            'start': start_time,
            'end': end_time,
            'site_id': site_id,
            'limit': 100,
            'page': 1
        }
        
        print(f"   🔍 Step 1: Fetching synthetic test results...")
        response = requests.get(url, headers=get_headers(), params=params, timeout=30)
        response.raise_for_status()
        
        results = response.json()
        
        # Handle different response formats
        if isinstance(results, dict) and 'data' in results:
            results = results['data']
        
        if not results or len(results) == 0:
            print(f"   ⚠️ No synthetic test results found")
            return None
        
        # Get latest test_id
        if isinstance(results, list):
            latest_test = results[0]
            test_id = latest_test.get('test_id')
        else:
            test_id = results.get('test_id')
        
        if not test_id:
            print(f"   ⚠️ No test_id found in results")
            return None
        
        print(f"   ✅ Found latest test_id: {test_id}")
        
        # Step 2: Get detailed test data using test_id
        detail_params = {
            'q': 'test_details',
            'view': 'table',
            'site_id': site_id,
            'test_id': test_id
        }
        
        print(f"   🔍 Step 2: Fetching test details for test_id={test_id}...")
        detail_response = requests.get(url, headers=get_headers(), params=detail_params, timeout=30)
        detail_response.raise_for_status()
        
        detailed_data = detail_response.json()
        print(f"   ✅ Got detailed synthetic test data")
        
        return detailed_data
        
    except Exception as e:
        print(f"   ❌ Error fetching synthetic test: {str(e)}")
        return None

def parse_synthetic_test_metrics(test_data):
    """
    Parse all metrics from synthetic test data
    Returns: DHCP, DNS, ARP, and Application metrics
    """
    if not test_data or 'data' not in test_data:
        return None
    
    metrics = {
        'dhcp': None,
        'dns': None,
        'arp': None,
        'application': None,
        'ap_name': None,
        'test_time': None
    }
    
    try:
        data = test_data['data']
        test_details = data.get('test_details', [])
        
        # Get test metadata
        metrics['test_time'] = datetime.fromtimestamp(data.get('start_time', 0)).strftime('%Y-%m-%d %H:%M:%S')
        
        for detail in test_details:
            ap_name = detail.get('ap_name', 'Unknown')
            metrics['ap_name'] = ap_name
            
            vlans = detail.get('vlans', [])
            
            for vlan in vlans:
                connectivity = vlan.get('connectivity', [])
                
                for conn in connectivity:
                    test_type = conn.get('test_type')
                    test_detail = conn.get('test_detail', {})
                    
                    # Parse DHCP
                    if test_type == 'DHCP':
                        dhcpv4 = test_detail.get('dhcpv4', {})
                        metrics['dhcp'] = {
                            'ack_latency': dhcpv4.get('ack_latency'),
                            'offer_latency': dhcpv4.get('offer_latency'),
                            'server': dhcpv4.get('server'),
                            'ip_assigned': dhcpv4.get('ip'),
                            'gateway': dhcpv4.get('gw'),
                            'dns_servers': dhcpv4.get('dns', []),
                            'lease_time': dhcpv4.get('lease_time'),
                            'state': dhcpv4.get('state'),
                            'summary': dhcpv4.get('summary'),
                            'status': conn.get('test_status')
                        }
                    
                    # Parse DNS
                    elif test_type == 'DNS':
                        urls = test_detail.get('urls', [])
                        latencies = [u.get('latency', 0) for u in urls if u.get('latency')]
                        
                        metrics['dns'] = {
                            'status': conn.get('test_status'),
                            'failed_servers': conn.get('failed_servers', []),
                            'failed_urls': conn.get('failed_urls', []),
                            'avg_latency': sum(latencies) / len(latencies) if latencies else None,
                            'min_latency': min(latencies) if latencies else None,
                            'max_latency': max(latencies) if latencies else None,
                            'urls_tested': len(urls),
                            'test_details': urls[:5]  # First 5 URL tests
                        }
                    
                    # Parse ARP
                    elif test_type == 'ARP':
                        ips = test_detail.get('ips', [])
                        if ips and len(ips) > 0:
                            metrics['arp'] = {
                                'latency': ips[0].get('latency'),
                                'gateway_ip': ips[0].get('ip'),
                                'gateway_mac': ips[0].get('mac'),
                                'status': conn.get('test_status')
                            }
                    
                    # Parse Application/CURL
                    elif test_type in ['CURL', 'APPLICATION']:
                        urls = test_detail.get('urls', [])
                        metrics['application'] = {
                            'status': conn.get('test_status'),
                            'urls_tested': len(urls),
                            'failed_urls': conn.get('failed_urls', []),
                            'test_details': urls[:5]
                        }
        
        return metrics
        
    except Exception as e:
        print(f"   ❌ Error parsing synthetic test metrics: {str(e)}")
        return None

def fetch_client_wireless_stats(site_id, mac_address):
    """Fetch real-time client wireless statistics"""
    try:
        mac_no_colon = mac_address.replace(':', '')
        url = f"{MIST_CONFIG['base_url']}/sites/{site_id}/stats/clients/{mac_no_colon}"
        
        print(f"   🔍 Fetching client wireless stats...")
        response = requests.get(url, headers=get_headers(), timeout=30)
        response.raise_for_status()
        
        stats = response.json()
        print(f"   ✅ Got client wireless stats")
        
        return {
            'rssi': stats.get('rssi'),
            'snr': stats.get('snr'),
            'channel': stats.get('channel'),
            'band': stats.get('band'),
            'tx_rate': stats.get('tx_rate'),
            'rx_rate': stats.get('rx_rate'),
            'tx_pkts': stats.get('tx_pkts'),
            'rx_pkts': stats.get('rx_pkts'),
            'tx_bytes': stats.get('tx_bytes'),
            'rx_bytes': stats.get('rx_bytes'),
            'tx_retries': stats.get('tx_retries'),
            'rx_retries': stats.get('rx_retries'),
            'uptime': stats.get('uptime'),
            'idle_time': stats.get('idle_time')
        }
        
    except Exception as e:
        print(f"   ❌ Error fetching client stats: {str(e)}")
        return None

def fetch_ap_stats(site_id, ap_mac):
    """Fetch AP statistics"""
    try:
        url = f"{MIST_CONFIG['base_url']}/sites/{site_id}/stats/devices/{ap_mac}"
        
        print(f"   🔍 Fetching AP stats for {ap_mac}...")
        response = requests.get(url, headers=get_headers(), timeout=30)
        response.raise_for_status()
        
        stats = response.json()
        print(f"   ✅ Got AP stats")
        
        return {
            'name': stats.get('name'),
            'model': stats.get('model'),
            'status': stats.get('status'),
            'uptime': stats.get('uptime'),
            'cpu_util': stats.get('cpu_util'),
            'mem_util': stats.get('mem_util'),
            'num_clients': stats.get('num_clients'),
            'version': stats.get('version'),
            'ip': stats.get('ip')
        }
        
    except Exception as e:
        print(f"   ❌ Error fetching AP stats: {str(e)}")
        return None

def fetch_wlan_config(site_id):
    """Fetch WLAN/SSID configuration"""
    try:
        url = f"{MIST_CONFIG['base_url']}/sites/{site_id}/wlans"
        
        print(f"   🔍 Fetching WLAN configurations...")
        response = requests.get(url, headers=get_headers(), timeout=30)
        response.raise_for_status()
        
        wlans = response.json()
        print(f"   ✅ Got {len(wlans)} WLAN configs")
        
        # Parse relevant WLAN info
        wlan_list = []
        for wlan in wlans:
            wlan_list.append({
                'ssid': wlan.get('ssid'),
                'enabled': wlan.get('enabled'),
                'vlan_id': wlan.get('vlan_id'),
                'auth': wlan.get('auth'),
                'encryption': wlan.get('encryption'),
                'band': wlan.get('band'),
                'hide_ssid': wlan.get('hide_ssid')
            })
        
        return wlan_list
        
    except Exception as e:
        print(f"   ❌ Error fetching WLAN config: {str(e)}")
        return None

def format_api_data_for_ai(api_data):
    """
    Format fetched API data into structured text for AI context
    """
    context_parts = []
    
    # Synthetic Test Metrics
    if 'synthetic_test' in api_data and api_data['synthetic_test']:
        metrics = api_data['synthetic_test']
        
        context_parts.append("=" * 60)
        context_parts.append("📊 REAL-TIME SYNTHETIC TEST RESULTS")
        context_parts.append("=" * 60)
        context_parts.append(f"Test Run From: {metrics.get('ap_name', 'Unknown AP')}")
        context_parts.append(f"Test Time: {metrics.get('test_time', 'N/A')}")
        context_parts.append("")
        
        # DHCP Metrics
        if metrics.get('dhcp'):
            dhcp = metrics['dhcp']
            context_parts.append("🔹 DHCP TEST RESULTS:")
            context_parts.append(f"   Status: {dhcp['status']}")
            context_parts.append(f"   ACK Latency: {dhcp['ack_latency']} ms")
            context_parts.append(f"   Offer Latency: {dhcp['offer_latency']} ms")
            context_parts.append(f"   DHCP Server: {dhcp['server']}")
            context_parts.append(f"   IP Assigned: {dhcp['ip_assigned']}")
            context_parts.append(f"   Gateway: {dhcp['gateway']}")
            context_parts.append(f"   DNS Servers: {', '.join(dhcp['dns_servers'])}")
            context_parts.append(f"   State: {dhcp['state']}")
            context_parts.append(f"   Summary: {dhcp['summary']}")
            context_parts.append("")
        
        # DNS Metrics
        if metrics.get('dns'):
            dns = metrics['dns']
            context_parts.append("🔹 DNS TEST RESULTS:")
            context_parts.append(f"   Status: {dns['status']}")
            context_parts.append(f"   URLs Tested: {dns['urls_tested']}")
            context_parts.append(f"   Average Latency: {dns['avg_latency']:.1f} ms" if dns['avg_latency'] else "   Average Latency: N/A")
            context_parts.append(f"   Failed Servers: {', '.join(dns['failed_servers']) if dns['failed_servers'] else 'None'}")
            context_parts.append(f"   Failed URLs: {', '.join(dns['failed_urls'][:3]) if dns['failed_urls'] else 'None'}")
            context_parts.append("")
        
        # ARP Metrics
        if metrics.get('arp'):
            arp = metrics['arp']
            context_parts.append("🔹 ARP TEST RESULTS:")
            context_parts.append(f"   Status: {arp['status']}")
            context_parts.append(f"   ARP Latency: {arp['latency']} ms")
            context_parts.append(f"   Gateway IP: {arp['gateway_ip']}")
            context_parts.append(f"   Gateway MAC: {arp['gateway_mac']}")
            context_parts.append("")
    
    # Client Wireless Stats
    if 'client_stats' in api_data and api_data['client_stats']:
        stats = api_data['client_stats']
        context_parts.append("=" * 60)
        context_parts.append("📡 REAL-TIME CLIENT WIRELESS STATISTICS")
        context_parts.append("=" * 60)
        context_parts.append(f"RSSI: {stats.get('rssi', 'N/A')} dBm")
        context_parts.append(f"SNR: {stats.get('snr', 'N/A')} dB")
        context_parts.append(f"Channel: {stats.get('channel', 'N/A')}")
        context_parts.append(f"Band: {stats.get('band', 'N/A')}")
        context_parts.append(f"TX Rate: {stats.get('tx_rate', 'N/A')} Mbps")
        context_parts.append(f"RX Rate: {stats.get('rx_rate', 'N/A')} Mbps")
        context_parts.append(f"TX Packets: {stats.get('tx_pkts', 'N/A')}")
        context_parts.append(f"RX Packets: {stats.get('rx_pkts', 'N/A')}")
        context_parts.append(f"TX Retries: {stats.get('tx_retries', 'N/A')}")
        context_parts.append(f"RX Retries: {stats.get('rx_retries', 'N/A')}")
        context_parts.append(f"Uptime: {stats.get('uptime', 'N/A')} seconds")
        context_parts.append("")
    
    # AP Stats
    if 'ap_stats' in api_data and api_data['ap_stats']:
        ap = api_data['ap_stats']
        context_parts.append("=" * 60)
        context_parts.append("🔧 ACCESS POINT STATISTICS")
        context_parts.append("=" * 60)
        context_parts.append(f"AP Name: {ap.get('name', 'N/A')}")
        context_parts.append(f"Model: {ap.get('model', 'N/A')}")
        context_parts.append(f"Status: {ap.get('status', 'N/A')}")
        context_parts.append(f"Uptime: {ap.get('uptime', 'N/A')} seconds")
        context_parts.append(f"CPU Utilization: {ap.get('cpu_util', 'N/A')}%")
        context_parts.append(f"Memory Utilization: {ap.get('mem_util', 'N/A')}%")
        context_parts.append(f"Connected Clients: {ap.get('num_clients', 'N/A')}")
        context_parts.append(f"Firmware: {ap.get('version', 'N/A')}")
        context_parts.append("")
    
    # WLAN Config
    if 'wlan_config' in api_data and api_data['wlan_config']:
        wlans = api_data['wlan_config']
        context_parts.append("=" * 60)
        context_parts.append("🌐 WLAN/SSID CONFIGURATIONS")
        context_parts.append("=" * 60)
        for i, wlan in enumerate(wlans[:5], 1):  # Show first 5 WLANs
            context_parts.append(f"{i}. SSID: {wlan.get('ssid', 'N/A')}")
            context_parts.append(f"   Enabled: {wlan.get('enabled', 'N/A')}")
            context_parts.append(f"   VLAN: {wlan.get('vlan_id', 'N/A')}")
            context_parts.append(f"   Auth: {wlan.get('auth', 'N/A')}")
            context_parts.append(f"   Encryption: {wlan.get('encryption', 'N/A')}")
            context_parts.append("")
    
    return "\n".join(context_parts) if context_parts else ""

def intelligent_api_router(question, context):
    """
    Main intelligent API routing function
    Analyzes question, determines which APIs to call, fetches data
    """
    site_id = context.get('site_id', '')
    mac_address = context.get('mac_address', '')
    
    if not site_id or not mac_address:
        print("   ⚠️ Missing site_id or mac_address for API routing")
        return {}
    
    # Detect intents
    intents = detect_api_intent(question, context)
    
    if not intents:
        print("   ℹ️ No specific API intents detected - using context only")
        return {}
    
    print(f"   🎯 Detected {len(intents)} intent(s): {list(intents.keys())[:3]}")
    
    fetched_data = {}
    
    # Fetch data based on detected intents (top 3 most relevant)
    for intent_name in list(intents.keys())[:3]:
        
        # Synthetic Test (DHCP/DNS/ARP)
        if intent_name == 'synthetic_test':
            print(f"   📡 Calling: Synthetic Test API")
            test_data = fetch_synthetic_test_data(site_id, mac_address)
            if test_data:
                metrics = parse_synthetic_test_metrics(test_data)
                if metrics:
                    fetched_data['synthetic_test'] = metrics
        
        # Client Wireless Stats
        elif intent_name == 'client_stats':
            print(f"   📡 Calling: Client Stats API")
            stats = fetch_client_wireless_stats(site_id, mac_address)
            if stats:
                fetched_data['client_stats'] = stats
        
        # AP Stats
        elif intent_name == 'ap_stats':
            print(f"   📡 Calling: AP Stats API")
            # Get AP MAC from context or fetch it
            ap_mac = context.get('last_ap_mac')
            if ap_mac:
                ap_stats = fetch_ap_stats(site_id, ap_mac)
                if ap_stats:
                    fetched_data['ap_stats'] = ap_stats
        
        # WLAN Config
        elif intent_name == 'wlan_config':
            print(f"   📡 Calling: WLAN Config API")
            wlan_config = fetch_wlan_config(site_id)
            if wlan_config:
                fetched_data['wlan_config'] = wlan_config
    
    return fetched_data

# ============================================================================
# EXISTING ENDPOINTS (Kept intact)
# ============================================================================

@app.route('/')
def index():
    """Serve the index.html file"""
    return send_from_directory('.', 'index.html')

@app.route('/api/client-insights', methods=['POST'])
def get_client_insights():
    """Search for client across all sites using concurrent requests"""
    try:
        data = request.get_json()
        mac_input = data.get('mac_address', '')

        if not mac_input:
            return jsonify({'success': False, 'error': 'MAC address is required'}), 400

        mac_colon = format_mac_to_colon(mac_input)
        mac_no_colon = mac_colon.replace(':', '')

        print(f"🔍 Searching for client {mac_colon} across all sites...")

        sites = get_all_sites()
        if not sites:
            return jsonify({'success': False, 'error': 'Could not retrieve sites'}), 500

        print(f"📊 Searching across {len(sites)} sites concurrently...")

        client_found = None
        found_site_id = None
        found_site_name = None

        max_workers = min(20, len(sites))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_site = {
                executor.submit(search_client_in_site, site, mac_no_colon): site 
                for site in sites
            }
            
            for future in as_completed(future_to_site):
                result = future.result()
                if result['found']:
                    client_found = result['client']
                    found_site_id = result['site_id']
                    found_site_name = result['site_name']
                    for f in future_to_site:
                        f.cancel()
                    break

        if not client_found:
            return jsonify({'success': False, 'error': 'Client not found in any site'}), 404

        print(f"📡 Fetching APs and WLANs for site: {found_site_name}")
        with ThreadPoolExecutor(max_workers=2) as executor:
            ap_future = executor.submit(get_site_aps, found_site_id)
            wlan_future = executor.submit(get_site_wlans, found_site_id)
            ap_future.result()
            wlan_future.result()

        ap_roaming_names = []
        if isinstance(client_found.get('ap'), list):
            for ap_mac in client_found.get('ap', []):
                ap_roaming_names.append(get_ap_name(ap_mac))

        last_ap_mac = client_found.get('last_ap', 'N/A')
        last_ap_name = get_ap_name(last_ap_mac)

        insights = {
            'mac_address': mac_colon,
            'site_name': get_site_name(found_site_id),
            'site_id': found_site_id,
            'last_ap_name': last_ap_name,
            'last_ap_mac': last_ap_mac,
            'last_ip': client_found.get('last_ip') or client_found.get('ip', 'N/A'),
            'last_vlan': client_found.get('last_vlan', 'N/A'),
            'ap_roaming_names': ap_roaming_names,
            'ssid': client_found.get('ssid', 'N/A'),
            'band': client_found.get('band', 'N/A')
        }

        return jsonify({'success': True, 'insights': insights})

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return jsonify({'success': False, 'error': f'Error: {str(e)}'}), 500

@app.route('/api/marvis-suggestions', methods=['POST'])
def get_marvis_suggestions():
    """Fetch Marvis AI troubleshooting suggestions"""
    try:
        data = request.get_json()
        mac_input = data.get('mac_address', '')
        site_id = data.get('site_id', '')

        if not mac_input or not site_id:
            return jsonify({'success': False, 'error': 'MAC address and site ID are required'}), 400

        mac_colon = format_mac_to_colon(mac_input)
        mac_no_colon = mac_colon.replace(':', '')

        end_time = int(datetime.now().timestamp())
        start_time = int((datetime.now() - timedelta(days=7)).timestamp())

        marvis_url = f"{MIST_CONFIG['base_url']}/orgs/{MIST_CONFIG['org_id']}/troubleshoot"
        params = {
            'mac': mac_no_colon,
            'site_id': site_id,
            'start': start_time,
            'end': end_time
        }

        print(f"🤖 Fetching Marvis AI suggestions for: {mac_colon}")
        response = requests.get(marvis_url, headers=get_headers(), params=params, timeout=30)
        response.raise_for_status()

        marvis_data = response.json()
        suggestions = marvis_data.get('results', [])

        print(f"✅ Found {len(suggestions)} Marvis suggestions")
        return jsonify({
            'success': True,
            'suggestions': suggestions,
            'total_suggestions': len(suggestions)
        })

    except Exception as e:
        print(f"⚠️ Marvis error: {str(e)}")
        return jsonify({'success': True, 'suggestions': [], 'total_suggestions': 0})

@app.route('/api/client-events', methods=['POST'])
def get_client_events():
    """Fetch client events from the site where client was found"""
    try:
        data = request.get_json()
        mac_input = data.get('mac_address', '')
        site_id = data.get('site_id', '')

        if not mac_input or not site_id:
            return jsonify({'success': False, 'error': 'MAC address and site ID are required'}), 400

        mac_colon = format_mac_to_colon(mac_input)
        mac_no_colon = mac_colon.replace(':', '')

        end_time = int(datetime.now().timestamp())
        start_time = int((datetime.now() - timedelta(days=7)).timestamp())

        event_types = [
            'CLIENT_JOINED_CALL', 'CLIENT_LEFT_CALL', 'CLIENT_DISCONNECTED_FROM_CALL',
            'CLIENT_ARP_FAILURE', 'CLIENT_ASSOCIATION', 'CLIENT_ASSOCIATION_FAILURE',
            'CLIENT_ASSOCIATION_PMKC', 'CLIENT_AUTH_ASSOCIATION', 'CLIENT_AUTH_ASSOCIATION_11R',
            'CLIENT_AUTH_ASSOCIATION_OKC', 'CLIENT_AUTH_REASSOCIATION', 'CLIENT_AUTH_REASSOCIATION_11R',
            'CLIENT_AUTH_REASSOCIATION_OKC', 'CLIENT_AUTHENTICATED', 'CLIENT_AUTHENTICATED_11R',
            'CLIENT_AUTHENTICATED_OKC', 'CLIENT_DEASSOCIATION', 'CLIENT_DEAUTHENTICATED',
            'CLIENT_DEAUTHENTICATION', 'CLIENT_DNS_OK', 'CLIENT_EXCESSIVE_ARPING_GW',
            'CLIENT_GW_ARP_FAILURE', 'CLIENT_GW_ARP_OK', 'CLIENT_IP_ASSIGNED',
            'CLIENT_IPV6_ASSIGNED', 'CLIENT_LOCAL_SUPPORT_PAGE', 'CLIENT_REASSOCIATION',
            'CLIENT_REASSOCIATION_PMKC', 'DEFAULT_GATEWAY_SPOOFING_DETECTED',
            'DEVICE_NOT_ENROLLED_IN_AIRWATCH', 'HTTP_REDIR_PROCESSED', 'MARVIS_DNS_FAILURE',
            'MARVIS_EVENT_CAPTIVE_PORTAL_AUTHORIZED', 'MARVIS_EVENT_CAPTIVE_PORTAL_FAILURE',
            'MARVIS_EVENT_CLIENT_AUTH_DENIED', 'MARVIS_EVENT_CLIENT_AUTH_FAILURE',
            'MARVIS_EVENT_CLIENT_AUTH_FAILURE_11R', 'MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC',
            'MARVIS_EVENT_CLIENT_DHCP_FAILURE', 'MARVIS_EVENT_CLIENT_DHCPV6_FAILURE',
            'MARVIS_EVENT_CLIENT_DHCP_NAK', 'MARVIS_EVENT_CLIENT_DHCPV6_NAK',
            'MARVIS_EVENT_CLIENT_DHCP_STUCK', 'MARVIS_EVENT_CLIENT_DHCPV6_STUCK',
            'MARVIS_EVENT_CLIENT_FAILED_DHCP_INFORM', 'MARVIS_EVENT_CLIENT_FBT_FAILURE',
            'MARVIS_EVENT_CLIENT_FBT_SUCCESS', 'MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE',
            'MARVIS_EVENT_CLIENT_MAC_AUTH_SUCCESS', 'MARVIS_EVENT_CLIENT_STATIC_IP_BLOCKED',
            'MARVIS_EVENT_CLIENT_STATIC_DNS_BLOCKED', 'MARVIS_EVENT_CLIENT_WXLAN_POLICY_LOOKUP_FAILURE',
            'MARVIS_EVENT_STA_LEAVING', 'MARVIS_EVENT_WLC_FT_KEY_NOT_FOUND',
            'MARVIS_EVENT_WXLAN_CAPTIVE_PORT_FLOW_REDIRECT', 'MARVIS_HEALTH_EVENT_BAD_IP_ASSIGNMENT_PATTERN',
            'REPEATED_AUTH_FAILURES', 'RADIUS_DAS_NOTIFY', 'SA_QUERY_TIMEOUT',
            'MARVIS_EVENT_SAE_AUTH_FAILURE', 'NAC_IDP_GROUPS_LOOKUP_SUCCESS',
            'NAC_IDP_GROUPS_LOOKUP_FAILURE', 'NAC_IDP_LOOKUP_FAILURE',
            'NAC_CLIENT_CERT_CHECK_SUCCESS', 'NAC_CLIENT_CERT_CHECK_FAILURE',
            'NAC_SERVER_CERT_VALIDATION_SUCCESS', 'NAC_SERVER_CERT_VALIDATION_FAILURE',
            'NAC_CLIENT_CERT_EXPIRED', 'NAC_IDP_UNKNOWN', 'NAC_IDP_UNREACHABLE',
            'NAC_IDP_ADMIN_CONFIG_FAILURE', 'NAC_IDP_USER_LOOKUP_FAILURE',
            'NAC_IDP_AUTHC_SUCCESS', 'NAC_IDP_AUTHC_FAILURE', 'NAC_CLIENT_PERMIT',
            'NAC_CLIENT_DENY', 'NAC_MDM_LOOKUP_SUCCESS', 'NAC_MDM_LOOKUP_FAILURE',
            'NAC_IDP_USER_DISABLED', 'NAC_CLIENT_USER_CERT_CHECK_SUCCESS',
            'NAC_CLIENT_USER_CERT_CHECK_FAILURE', 'NAC_CLIENT_MACHINE_CERT_CHECK_SUCCESS',
            'NAC_CLIENT_MACHINE_CERT_CHECK_FAILURE', 'NAC_CLIENT_USER_CERT_EXPIRED',
            'NAC_CLIENT_MACHINE_CERT_EXPIRED', 'NAC_CLIENT_CERT_REVOKED',
            'NAC_CLIENT_USER_CERT_REVOKED', 'NAC_CLIENT_MACHINE_CERT_REVOKED',
            'NAC_CLIENT_COA_DISCONNECT', 'NAC_CLIENT_COA_REAUTH',
            'NAC_MDM_DEVICE_NOT_ENROLLED', 'NAC_CLIENT_IP_ASSIGNED',
            'NAC_SESSION_ENDED', 'NAC_CLIENT_PPSK_KEY_FOUND', 'NAC_CLIENT_PPSK_KEY_NOT_FOUND',
            'NAC_FIREWALL_CLIENT_LOGIN_SUCCESS', 'NAC_FIREWALL_CLIENT_LOGIN_FAILURE',
            'NAC_FIREWALL_CLIENT_LOGOUT_SUCCESS', 'NAC_FIREWALL_CLIENT_LOGOUT_FAILURE',
            'NAC_SESSION_STARTED', 'NAC_CLIENT_GUEST_REDIRECTION_IN_PROGRESS',
            'NAC_CLIENT_GUEST_REGISTERED', 'NAC_CLIENT_GUEST_LOGIN_ATTEMPT_FAILURE'
        ]

        events_url = f"{MIST_CONFIG['base_url']}/sites/{site_id}/clients/events"
        params = {
            'type': ','.join(event_types),
            'mac': mac_no_colon,
            'limit': 1000,
            'start': start_time,
            'end': end_time
        }
        events_url_SNR_OS_RSSI = f"{MIST_CONFIG['base_url']}/sites/{site_id}/clients?mac={mac_no_colon}"
        params = {
            'type': ','.join(event_types),
            'mac': mac_no_colon,
            'limit': 1000,
            'start': start_time,
            'end': end_time
        }

        print(f"📡 Fetching events for: {mac_colon}")
        response = requests.get(events_url, headers=get_headers(), params=params, timeout=30)
        response.raise_for_status()

        events_data = response.json()
        events = events_data.get('results', [])

        processed_events = []
        for event in events:
            ap_mac = event.get('ap', 'N/A')
            wlan_id = event.get('wlan_id', 'N/A')

            processed_events.append({
                'timestamp': event.get('timestamp', 0),
                'timestamp_formatted': datetime.fromtimestamp(event.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                'type': event.get('type', 'N/A'),
                'ap_name': get_ap_name(ap_mac),
                'ap_mac': ap_mac,
                'ssid': event.get('ssid', 'N/A'),
                'bssid': event.get('bssid', 'N/A'),
                'rssi': event.get('rssi', 'N/A'),
                'snr': event.get('snr', 'N/A'),
                'channel': event.get('channel', 'N/A'),
                'band': event.get('band', 'N/A'),
                'vlan': event.get('vlan', 'N/A'),
                'proto': event.get('proto', 'N/A'),
                'key_mgmt': event.get('key_mgmt', 'N/A'),
                'status_code': event.get('status_code', 'N/A'),
                'reason_code': event.get('reason_code', 'N/A'),
                'text': event.get('text', 'N/A'),
                'gateway': ', '.join(event.get('gateway', [])),
                'arp_latency': event.get('arp_latency', 'N/A'),
                'capabilities': event.get('capabilities', 'N/A'),
                'num_streams': event.get('num_streams', 'N/A'),
                'auth_type': event.get('auth_type', 'N/A'),
                'time_since_assoc': event.get('time_since_assoc', 'N/A'),
                'wlan_name': get_wlan_name(wlan_id),
                'wlan_id': wlan_id
            })

        processed_events.sort(key=lambda x: x['timestamp'], reverse=True)
        analysis = analyze_all_events(events) if events else None

        print(f"✅ Found {len(processed_events)} events")
        return jsonify({
            'success': True,
            'events': processed_events,
            'total_events': len(processed_events),
            'analysis': analysis
        })

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return jsonify({'success': False, 'error': f'Error: {str(e)}'}), 500

def analyze_all_events(events):
    """Comprehensive analysis of all client events"""
    if not events:
        return None

    latest = max(events, key=lambda x: x.get('timestamp', 0))
    event_types_counter = Counter([e.get('type', 'UNKNOWN') for e in events])
    reason_codes_counter = Counter([e.get('reason_code', 0) for e in events if e.get('reason_code') not in ['N/A', None, 0]])
    
    disconnection_events = [e for e in events if 'DISCONNECT' in e.get('type', '').upper() or 
                           'DEAUTH' in e.get('type', '').upper() or
                           'LEAVING' in e.get('type', '').upper()]
    
    failure_events = [e for e in events if 'FAILURE' in e.get('type', '').upper() or 
                     'DENIED' in e.get('type', '').upper() or
                     'NAK' in e.get('type', '').upper()]
    
    rssi_values = [e.get('rssi') for e in events if e.get('rssi') not in ['N/A', None]]
    snr_values = [e.get('snr') for e in events if e.get('snr') not in ['N/A', None]]
    
    avg_rssi = sum(rssi_values) / len(rssi_values) if rssi_values else None
    avg_snr = sum(snr_values) / len(snr_values) if snr_values else None
    min_rssi = min(rssi_values) if rssi_values else None
    
    patterns = detect_patterns(events)
    
    issues = []
    suggestions = []
    severity = 'healthy'
    
    latest_type = latest.get('type', '')
    latest_reason_code = latest.get('reason_code', 0)
    latest_status_code = latest.get('status_code', 0)
    latest_rssi = latest.get('rssi')
    latest_snr = latest.get('snr')
    
    if 'FAILURE' in latest_type or 'DENIED' in latest_type or 'DISCONNECT' in latest_type:
        issues.append(f"⚠️ Latest Event Issue: {latest_type}")
        severity = 'warning'
        
        if latest_reason_code and latest_reason_code != 0:
            reason_explanation = get_reason_code_explanation(latest_reason_code)
            suggestions.append(f"Latest Disconnect Reason Code {latest_reason_code}: {reason_explanation}")
    
    if latest_status_code and latest_status_code != 0:
        status_explanation = get_status_code_explanation(latest_status_code)
        issues.append(f"⚠️ Non-zero Status Code: {latest_status_code}")
        suggestions.append(f"Status Code {latest_status_code}: {status_explanation}")
        severity = 'warning'
    
    if len(disconnection_events) > 5:
        issues.append(f"🔴 Frequent Disconnections: {len(disconnection_events)} events in 7 days")
        suggestions.append("Client is disconnecting frequently. Check signal strength, roaming issues, or authentication problems.")
        severity = 'critical'
    elif len(disconnection_events) > 2:
        issues.append(f"⚠️ Multiple Disconnections: {len(disconnection_events)} events detected")
        suggestions.append("Monitor client for stability issues.")
        if severity == 'healthy':
            severity = 'warning'
    
    if len(failure_events) > 10:
        issues.append(f"🔴 High Failure Rate: {len(failure_events)} failure events in 7 days")
        suggestions.append("Investigate authentication, DHCP, or DNS configuration issues.")
        severity = 'critical'
    elif len(failure_events) > 5:
        issues.append(f"⚠️ Multiple Failures: {len(failure_events)} failure events detected")
        if severity == 'healthy':
            severity = 'warning'
    
    if latest_rssi and latest_rssi != 'N/A':
        if latest_rssi < -80:
            issues.append(f"🔴 Critical Signal: Current RSSI {latest_rssi} dBm")
            suggestions.append("URGENT: Very weak signal. Move client closer to AP or add more APs.")
            severity = 'critical'
        elif latest_rssi < -70:
            issues.append(f"⚠️ Weak Signal: Current RSSI {latest_rssi} dBm")
            suggestions.append("Consider repositioning client or AP for better coverage.")
            if severity == 'healthy':
                severity = 'warning'
    
    auth_failures = sum(1 for e in events if 'AUTH' in e.get('type', '').upper() and 'FAILURE' in e.get('type', '').upper())
    if auth_failures > 5:
        issues.append(f"🔴 Authentication Issues: {auth_failures} auth failures")
        suggestions.append("Check credentials, RADIUS server, and certificate validity.")
        severity = 'critical'
    
    dhcp_failures = sum(1 for e in events if 'DHCP' in e.get('type', '').upper() and 'FAILURE' in e.get('type', '').upper())
    if dhcp_failures > 3:
        issues.append(f"🔴 DHCP Problems: {dhcp_failures} DHCP failures")
        suggestions.append("Verify DHCP server availability and IP address pool capacity.")
    
    dns_failures = sum(1 for e in events if 'DNS' in e.get('type', '').upper() and 'FAILURE' in e.get('type', '').upper())
    if dns_failures > 3:
        issues.append(f"⚠️ DNS Issues: {dns_failures} DNS failures")
        suggestions.append("Check DNS server configuration and connectivity.")
    
    top_reason_codes = []
    for reason_code, count in reason_codes_counter.most_common(3):
        explanation = get_reason_code_explanation(reason_code)
        top_reason_codes.append({
            'code': reason_code,
            'count': count,
            'explanation': explanation
        })
    
    if not issues:
        issues.append("✅ No significant issues detected")
        suggestions.append("Client connection appears healthy and stable")
    
    return {
        'latest_event_type': latest_type,
        'timestamp': datetime.fromtimestamp(latest.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S'),
        'latest_reason_code': latest_reason_code,
        'latest_status_code': latest_status_code,
        'latest_rssi': latest_rssi if latest_rssi else 'N/A',
        'latest_snr': latest_snr if latest_snr else 'N/A',
        'severity': severity,
        'issues': issues,
        'suggestions': suggestions,
        'event_summary': {
            'total_events': len(events),
            'disconnections': len(disconnection_events),
            'failures': len(failure_events),
            'auth_failures': auth_failures,
            'dhcp_failures': dhcp_failures,
            'dns_failures': dns_failures
        },
        'top_events': [{'type': k, 'count': v} for k, v in event_types_counter.most_common(5)],
        'top_reason_codes': top_reason_codes,
        'signal_stats': {
            'avg_rssi': f"{avg_rssi:.1f}" if avg_rssi else 'N/A',
            'min_rssi': f"{min_rssi:.1f}" if min_rssi else 'N/A',
            'avg_snr': f"{avg_snr:.1f}" if avg_snr else 'N/A',
            'latest_snr': f"{latest_snr:.1f}" if latest_snr else 'N/A'
        }
    }

def detect_patterns(events):
    """Detect patterns in events"""
    patterns = []
    sorted_events = sorted(events, key=lambda x: x.get('timestamp', 0))
    
    connect_events = ['CLIENT_ASSOCIATION', 'CLIENT_AUTHENTICATED', 'CLIENT_IP_ASSIGNED']
    disconnect_events = ['CLIENT_DEAUTHENTICATED', 'CLIENT_DEASSOCIATION', 'MARVIS_EVENT_STA_LEAVING']
    
    rapid_cycles = 0
    for i in range(len(sorted_events) - 1):
        current_event = sorted_events[i]
        next_event = sorted_events[i + 1]
        
        time_diff = next_event.get('timestamp', 0) - current_event.get('timestamp', 0)
        
        if (any(evt in current_event.get('type', '') for evt in connect_events) and
            any(evt in next_event.get('type', '') for evt in disconnect_events) and
            time_diff < 60):
            rapid_cycles += 1
    
    if rapid_cycles > 3:
        patterns.append({
            'description': f'Rapid Connect/Disconnect Cycles: {rapid_cycles} occurrences',
            'suggestion': 'Client is connecting and disconnecting rapidly. Check for authentication issues, weak signal, or configuration problems.',
            'severity': 'critical'
        })
    
    return patterns

def get_reason_code_explanation(code):
    """Get detailed explanation for IEEE 802.11 reason codes"""
    reason_codes = {
        1: "Unspecified reason - Check AP logs for more details",
        2: "Previous authentication invalid - Re-authentication required",
        3: "Client leaving network - Normal user-initiated disconnection",
        4: "Inactivity timeout - Client idle for too long, check power-saving settings",
        5: "AP unable to handle all clients - AP at capacity, consider load balancing",
        15: "4-way handshake timeout - Verify PSK/802.1X credentials and timing",
        23: "IEEE 802.1X authentication failed - Check RADIUS server and credentials",
        34: "Poor channel conditions - RF interference or weak signal"
    }
    return reason_codes.get(code, f"Unknown reason code - Consult IEEE 802.11 specifications")

def get_status_code_explanation(code):
    """Get detailed explanation for IEEE 802.11 status codes"""
    status_codes = {
        0: "Success",
        1: "Unspecified failure",
        17: "Association denied - AP unable to handle additional stations",
        23: "Association request rejected - Power capability unacceptable"
    }
    return status_codes.get(code, f"Unknown status code")

# ============================================================================
# ENHANCED AI ASSISTANT WITH INTELLIGENT API ROUTING
# ============================================================================

@app.route('/api/ai-assistant', methods=['POST'])
def ai_assistant():
    """
    Enhanced AI Assistant with intelligent API routing
    Automatically detects intent and fetches relevant data from Mist APIs
    """
    try:
        data = request.get_json()
        question = data.get('question', '')
        context = data.get('context', {})

        if not question:
            return jsonify({'success': False, 'error': 'Question is required'}), 400

        mac_address = context.get('mac_address', 'Unknown')
        site_name = context.get('site_name', 'Unknown')
        site_id = context.get('site_id', '')
        latest_event = context.get('latest_event', 'None')
        issues = context.get('issues', [])

        print(f"🤖 AI Assistant Query: {question[:80]}...")

        # STEP 1: Intelligent API Routing - Detect intent and fetch data
        api_data = intelligent_api_router(question, context)
        
        # STEP 2: Format fetched data for AI context
        api_context = format_api_data_for_ai(api_data) if api_data else ""

        # STEP 3: Build comprehensive prompt
        base_context = f"""You are a Juniper Mist wireless network expert troubleshooting client connectivity issues.

**CLIENT INFORMATION:**
- MAC Address: {mac_address}
- Site: {site_name}
- Latest Event: {latest_event}
- Detected Issues: {', '.join(issues[:3]) if issues else 'None detected'}"""

        full_prompt = base_context
        
        if api_context:
            full_prompt += f"\n\n{api_context}"
        
        full_prompt += f"""

**USER QUESTION:** {question}

**INSTRUCTIONS:**
- Provide a specific, data-driven answer using the REAL metrics shown above
- Give exact numbers from the data when available
- Provide actionable troubleshooting steps
- Explain what the metrics mean in context
- If metrics indicate issues, explain the root cause and remediation steps
- Be concise but thorough"""

        # STEP 4: Call Perplexity API
        headers = {
            'Authorization': f'Bearer {PERPLEXITY_CONFIG["api_key"]}',
            'Content-Type': 'application/json'
        }

        payload = {
            'model': 'sonar',
            'messages': [
                {'role': 'system', 'content': 'You are an expert Juniper Mist wireless network engineer with deep knowledge of WiFi troubleshooting, 802.11 protocols, and network diagnostics.'},
                {'role': 'user', 'content': full_prompt}
            ],
            'max_tokens': 2000,
            'temperature': 0.2,
            'stream': False
        }

        response = requests.post(
            PERPLEXITY_CONFIG['api_url'],
            headers=headers,
            json=payload,
            timeout=45
        )

        if response.status_code != 200:
            return jsonify({
                'success': False,
                'error': f'AI service error (Status {response.status_code})'
            }), 500

        result = response.json()
        answer = result['choices'][0]['message']['content']

        apis_called = list(api_data.keys()) if api_data else []
        print(f"✅ AI Response Generated ({len(answer)} chars)")
        print(f"   📡 APIs Called: {apis_called if apis_called else 'None (using cached context)'}")

        return jsonify({
            'success': True,
            'answer': answer,
            'model': 'sonar',
            'data_fetched': bool(api_data),
            'apis_called': apis_called
        })

    except Exception as e:
        print(f"❌ AI Assistant Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': f'Error: {str(e)}'
        }), 500

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Juniper Mist Client Insights Dashboard")
    print("   Flask Proxy Server - PORT 5002 (ENHANCED)")
    print("=" * 60)
    print("\n🧠 INTELLIGENT API ROUTING ENABLED")
    print("   ✓ Automatic intent detection from user queries")
    print("   ✓ Dynamic API call routing based on question")
    print("   ✓ Multi-step API calls (synthetic test, etc.)")
    print("   ✓ Real-time data fetching and analysis")
    print("\n📡 Starting server with CONCURRENT SEARCH...")
    print("\n✅ Server URL: http://localhost:5002")
    print("✅ Searches across ALL sites automatically")
    print("⚡ Uses parallel requests for faster searches")
    print("🔍 Advanced event analysis and pattern detection")
    print("🤖 AI-powered troubleshooting with live data")
    print("\n💡 Make sure index.html is in the same directory!")
    print("\n🔧 Press CTRL+C to stop")
    print("=" * 60)
    print()

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
