#!/usr/bin/env python3
"""
EntryShark Enhanced Analyzer with AI Vision
Analyzes network topology images using Mistral Pixtral and combines with PCAP analysis
"""

import base64
import json
import os
import requests
from datetime import datetime
from pathlib import Path
import sys

# Load .env file if available
try:
    from dotenv import load_dotenv
    # Load from parent directory
    env_path = Path(__file__).parent.parent / '.env'
    load_dotenv(env_path)
except ImportError:
    print("⚠️  python-dotenv not installed. Install with: py -3 -m pip install python-dotenv")

# Import our working analyzer components
try:
    from scapy.all import rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available. Install with: py -3 -m pip install scapy")

# Import Rust ML functions
try:
    from rustml import detect_port_scan, is_suspicious_port
    RUSTML_AVAILABLE = True
except ImportError:
    RUSTML_AVAILABLE = False

class NetworkTopologyAnalyzer:
    def __init__(self, api_key=None):
        """Initialize the topology analyzer with Mistral API"""
        self.api_key = api_key or os.getenv('MISTRAL_API_KEY')
        self.api_url = "https://api.mistral.ai/v1/chat/completions"
        self.network_context = {}
        
    def encode_image(self, image_path):
        """Encode image to base64 for API"""
        with open(image_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode('utf-8')
    
    def analyze_network_topology(self, image_path):
        """Analyze network topology image using Mistral Pixtral"""
        if not self.api_key:
            print("⚠️  No Mistral API key found. Set MISTRAL_API_KEY environment variable.")
            return self._fallback_topology_analysis(image_path)
        
        try:
            # Encode the image
            base64_image = self.encode_image(image_path)
            
            # Prepare the request
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            payload = {
                "model": "pixtral-12b-2409",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": """Analyze this network topology diagram and provide a detailed assessment in JSON format. Include:

1. Network segments and their purposes (DMZ, internal, management, etc.)
2. Critical infrastructure components (servers, firewalls, routers, switches)
3. Expected traffic patterns and protocols
4. Potential security boundaries and trust zones
5. Normal vs suspicious traffic indicators for this specific network
6. IP address ranges and subnets if visible
7. Any security controls or monitoring points

Format your response as valid JSON with these keys:
- network_segments: array of {name, purpose, ip_range, security_level}
- infrastructure: array of {type, name, role, criticality}
- expected_traffic: array of {source, destination, protocol, port, purpose}
- security_boundaries: array of {name, controls, trust_level}
- threat_indicators: array of {pattern, severity, description}
- recommendations: array of security recommendations"""
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{base64_image}"
                                }
                            }
                        ]
                    }
                ],
                "max_tokens": 2000,
                "temperature": 0.1
            }
            
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            content = result['choices'][0]['message']['content']
            
            # Try to extract JSON from the response
            try:
                # Look for JSON in the response
                start_idx = content.find('{')
                end_idx = content.rfind('}') + 1
                if start_idx != -1 and end_idx != 0:
                    json_content = content[start_idx:end_idx]
                    self.network_context = json.loads(json_content)
                else:
                    # Fallback: create structured data from text
                    self.network_context = self._parse_text_response(content)
            except json.JSONDecodeError:
                # Fallback: create basic structure from text response
                self.network_context = self._parse_text_response(content)
            
            print("✅ Network topology analyzed successfully with AI vision")
            return self.network_context
            
        except Exception as e:
            print(f"⚠️  AI vision analysis failed: {e}")
            return self._fallback_topology_analysis(image_path)
    
    def _parse_text_response(self, text):
        """Parse text response into structured format"""
        return {
            "network_segments": [
                {"name": "Unknown", "purpose": "Inferred from image", "ip_range": "TBD", "security_level": "medium"}
            ],
            "infrastructure": [
                {"type": "unknown", "name": "Network devices", "role": "routing/switching", "criticality": "high"}
            ],
            "expected_traffic": [
                {"source": "internal", "destination": "external", "protocol": "HTTP/HTTPS", "port": "80/443", "purpose": "web browsing"}
            ],
            "security_boundaries": [
                {"name": "perimeter", "controls": ["firewall"], "trust_level": "medium"}
            ],
            "threat_indicators": [
                {"pattern": "unusual_ports", "severity": "medium", "description": "Traffic on non-standard ports"},
                {"pattern": "external_connections", "severity": "high", "description": "Unexpected external communications"}
            ],
            "recommendations": ["Monitor for unusual traffic patterns", "Implement network segmentation"],
            "ai_analysis": text[:500] + "..." if len(text) > 500 else text
        }
    
    def _fallback_topology_analysis(self, image_path):
        """Fallback analysis when AI vision is not available"""
        print("🔄 Using fallback topology analysis...")
        
        filename = Path(image_path).name.lower()
        
        # Basic inference from filename and common patterns
        if "business" in filename or "corporate" in filename:
            network_type = "business"
        elif "engineering" in filename or "dev" in filename:
            network_type = "engineering"
        elif "dmz" in filename:
            network_type = "dmz"
        else:
            network_type = "general"
        
        # Create basic network context
        self.network_context = {
            "network_segments": [
                {"name": f"{network_type}_network", "purpose": f"{network_type} operations", "ip_range": "192.168.0.0/16", "security_level": "medium"},
                {"name": "external", "purpose": "internet", "ip_range": "0.0.0.0/0", "security_level": "low"}
            ],
            "infrastructure": [
                {"type": "router", "name": "edge_router", "role": "internet_gateway", "criticality": "high"},
                {"type": "switch", "name": "core_switch", "role": "internal_routing", "criticality": "high"},
                {"type": "firewall", "name": "perimeter_fw", "role": "security", "criticality": "high"}
            ],
            "expected_traffic": [
                {"source": "internal", "destination": "external", "protocol": "HTTP/HTTPS", "port": "80/443", "purpose": "web_browsing"},
                {"source": "internal", "destination": "internal", "protocol": "SMB", "port": "445", "purpose": "file_sharing"},
                {"source": "external", "destination": "internal", "protocol": "SSH", "port": "22", "purpose": "remote_admin"}
            ],
            "security_boundaries": [
                {"name": "perimeter", "controls": ["firewall", "router_acl"], "trust_level": "high"},
                {"name": "internal_segmentation", "controls": ["vlan", "subnet"], "trust_level": "medium"}
            ],
            "threat_indicators": [
                {"pattern": "port_scan", "severity": "high", "description": "Multiple port probes from single source"},
                {"pattern": "data_exfiltration", "severity": "high", "description": "Large outbound transfers"},
                {"pattern": "lateral_movement", "severity": "medium", "description": "Internal host scanning"},
                {"pattern": "c2_communication", "severity": "high", "description": "Regular beaconing to external IPs"}
            ],
            "recommendations": [
                "Monitor for port scanning activities",
                "Implement DLP for data exfiltration detection",
                "Use network segmentation to limit lateral movement",
                "Deploy IDS/IPS for threat detection"
            ],
            "analysis_method": "fallback_inference"
        }
        
        return self.network_context

class EnhancedPcapAnalyzer:
    def __init__(self, topology_context=None):
        self.topology_context = topology_context or {}
        self.contextual_findings = []
    
    def extract_features_with_scapy(self, pcap_file):
        """Extract features from PCAP using Scapy"""
        if not SCAPY_AVAILABLE:
            print("❌ Scapy not available for PCAP parsing")
            return []
            
        try:
            print(f"📁 Reading PCAP with Scapy: {Path(pcap_file).name}")
            packets = rdpcap(str(pcap_file))
            
            packets_data = []
            
            for pkt in packets:
                try:
                    if IP in pkt:
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        packet_size = len(pkt)
                        
                        src_port = 0
                        dst_port = 0
                        protocol = "Other"
                        
                        if TCP in pkt:
                            src_port = pkt[TCP].sport
                            dst_port = pkt[TCP].dport
                            protocol = "TCP"
                        elif UDP in pkt:
                            src_port = pkt[UDP].sport
                            dst_port = pkt[UDP].dport
                            protocol = "UDP"
                        
                        packet_info = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': protocol,
                            'packet_size': packet_size,
                            'timestamp': float(pkt.time) if hasattr(pkt, 'time') else 0.0
                        }
                        
                        packets_data.append(packet_info)
                        
                except Exception:
                    continue  # Skip malformed packets
            
            return packets_data
            
        except Exception as e:
            print(f"❌ Error reading PCAP: {str(e)}")
            return []
    
    def analyze_with_context(self, pcap_files, output_file=None):
        """Analyze PCAP files with network topology context"""
        all_results = []
        
        for pcap_file in pcap_files:
            print(f"\n🔍 Analyzing {Path(pcap_file).name}...")
            
            # Extract features using Scapy
            packets_data = self.extract_features_with_scapy(pcap_file)
            if not packets_data:
                print(f"❌ Failed to extract features from {pcap_file}")
                continue
            
            # Analyze packets with context
            result = self.analyze_packets_with_context(packets_data, pcap_file)
            all_results.append(result)
        
        # Generate enhanced report
        if output_file:
            self._save_enhanced_report(all_results, output_file)
        
        return all_results
    
    def analyze_packets_with_context(self, packets_data, pcap_file):
        """Analyze packets with topology context"""
        findings = []
        
        # Basic statistics
        stats = {
            'total_packets': len(packets_data),
            'unique_ips': len(set([p['src_ip'] for p in packets_data] + [p['dst_ip'] for p in packets_data])),
            'protocols': {},
            'top_ports': {}
        }
        
        # Count protocols and ports
        for packet in packets_data:
            protocol = packet['protocol']
            stats['protocols'][protocol] = stats['protocols'].get(protocol, 0) + 1
            
            if packet['dst_port'] > 0:
                stats['top_ports'][packet['dst_port']] = stats['top_ports'].get(packet['dst_port'], 0) + 1
        
        # Sort top ports
        stats['top_ports'] = dict(sorted(stats['top_ports'].items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Enhanced Security Analysis
        print(f"🔍 Running comprehensive threat analysis on {len(packets_data)} packets...")
        
        # 1. Port Scanning Detection (Enhanced)
        port_scan_findings = self._detect_port_scanning(packets_data)
        findings.extend(port_scan_findings)
        
        # 2. Suspicious Ports and Services
        suspicious_port_findings = self._detect_suspicious_ports(packets_data)
        findings.extend(suspicious_port_findings)
        
        # 3. Unusual Traffic Patterns
        traffic_anomaly_findings = self._detect_traffic_anomalies(packets_data)
        findings.extend(traffic_anomaly_findings)
        
        # 4. Potential Data Exfiltration
        exfiltration_findings = self._detect_data_exfiltration(packets_data)
        findings.extend(exfiltration_findings)
        
        # 5. Brute Force Detection
        brute_force_findings = self._detect_brute_force_attempts(packets_data)
        findings.extend(brute_force_findings)
        
        # 6. Network Reconnaissance
        recon_findings = self._detect_network_reconnaissance(packets_data)
        findings.extend(recon_findings)
        
        # 7. Malware Communication Patterns
        malware_findings = self._detect_malware_communication(packets_data)
        findings.extend(malware_findings)
        
        # 8. Advanced Threat Detection
        advanced_findings = self._detect_advanced_threats(packets_data)
        findings.extend(advanced_findings)
        
        # 9. DNS Tunneling Detection
        dns_findings = self._detect_dns_tunneling(packets_data)
        findings.extend(dns_findings)
        
        # 10. Covert Channel Detection
        covert_findings = self._detect_covert_channels(packets_data)
        findings.extend(covert_findings)
        
        # 11. RustML analysis (if available)
        if RUSTML_AVAILABLE:
            try:
                rust_findings = self._run_rustml_analysis(packets_data)
                # Map RustML findings to canonical types before adding
                mapped_rust_findings = self._map_rustml_to_canonical(rust_findings)
                findings.extend(mapped_rust_findings)
            except Exception as e:
                findings.append({
                    'type': 'rustml_analysis_error',
                    'severity': 'low',
                    'count': 1,
                    'description': f"RustML analysis failed: {str(e)}",
                    'evidence': {'error': str(e)},
                    'data': []
                })
        
        # 9. Topology-specific analysis
        if self.topology_context:
            contextual_findings = self._analyze_with_topology_context(packets_data)
            findings.extend(contextual_findings)
        
        print(f"✅ Found {len(findings)} potential security issues")
        
        return {
            'file': pcap_file,
            'timestamp': datetime.now().isoformat(),
            'stats': stats,
            'findings': findings,
            'topology_context': self.topology_context
        }
    
    def _detect_port_scanning(self, packets_data):
        """Enhanced port scanning detection"""
        findings = []
        
        # Group by source IP and count unique destination ports
        src_to_ports = {}
        src_to_hosts = {}
        
        for packet in packets_data:
            src_ip = packet['src_ip']
            dst_ip = packet['dst_ip']
            dst_port = packet['dst_port']
            
            if src_ip not in src_to_ports:
                src_to_ports[src_ip] = set()
                src_to_hosts[src_ip] = set()
            
            src_to_ports[src_ip].add(dst_port)
            src_to_hosts[src_ip].add(dst_ip)
        
        # Detect potential port scans
        for src_ip, ports in src_to_ports.items():
            port_count = len(ports)
            host_count = len(src_to_hosts[src_ip])
            
            # Calculate confidence based on scan characteristics
            confidence = 0.5  # Base confidence
            
            # Multiple criteria for port scanning
            if port_count > 20:  # Scanning many ports
                severity = 'high' if port_count > 100 else 'medium'
                
                # Boost confidence based on scan characteristics
                if port_count > 100:
                    confidence = 0.9
                elif port_count > 50:
                    confidence = 0.8
                else:
                    confidence = 0.7
                
                # Additional confidence boost for multi-host scanning
                if host_count > 5:
                    confidence = min(confidence + 0.1, 1.0)
                
                findings.append({
                    'type': 'port_scanning',
                    'severity': severity,
                    'count': port_count,
                    'confidence': confidence,
                    'description': f"Host {src_ip} scanned {port_count} ports across {host_count} hosts",
                    'evidence': {
                        'scanner_ip': src_ip,
                        'source_ip': src_ip,
                        'target_count': host_count,
                        'total_ports': port_count,
                        'ports_scanned': port_count,
                        'hosts_targeted': host_count,
                        'sample_ports': list(ports)[:20]
                    },
                    'data': []
                })
            
            # Horizontal scanning (same port, multiple hosts)
            if host_count > 10:
                findings.append({
                    'type': 'horizontal_scanning',
                    'severity': 'high',
                    'count': host_count,
                    'description': f"Host {src_ip} performed horizontal scan across {host_count} hosts",
                    'evidence': {
                        'source_ip': src_ip,
                        'hosts_scanned': host_count,
                        'sample_hosts': list(src_to_hosts[src_ip])[:10]
                    },
                    'data': []
                })
        
        return findings
    
    def _detect_suspicious_ports(self, packets_data):
        """Detect connections to suspicious ports"""
        findings = []
        
        # Define suspicious ports and their categories
        suspicious_ports = {
            # Remote Access Trojans
            1337: "RDAT (Remote Access Trojan)",
            31337: "Back Orifice Trojan",
            12345: "NetBus Trojan",
            20034: "NetBus Pro Trojan",
            
            # Common attack vectors
            4444: "Metasploit common port",
            5555: "Common backdoor port",
            8080: "HTTP Proxy (often malicious)",
            9999: "Common malware port",
            
            # Crypto mining
            3333: "Stratum mining protocol",
            4444: "Mining pool port",
            
            # Dark web / anonymity
            9050: "Tor SOCKS proxy",
            9051: "Tor control port",
            
            # Database attacks
            1521: "Oracle database (often targeted)",
            3306: "MySQL (if unexpected)",
            5432: "PostgreSQL (if unexpected)"
        }
        
        suspicious_connections = []
        
        for packet in packets_data:
            dst_port = packet['dst_port']
            if dst_port in suspicious_ports:
                suspicious_connections.append({
                    'src_ip': packet['src_ip'],
                    'dst_ip': packet['dst_ip'],
                    'dst_port': dst_port,
                    'description': suspicious_ports[dst_port],
                    'timestamp': packet['timestamp']
                })
        
        if suspicious_connections:
            # Group by port for summary
            port_summary = {}
            for conn in suspicious_connections:
                port = conn['dst_port']
                if port not in port_summary:
                    port_summary[port] = {
                        'count': 0,
                        'description': conn['description'],
                        'unique_sources': set(),
                        'unique_destinations': set()
                    }
                port_summary[port]['count'] += 1
                port_summary[port]['unique_sources'].add(conn['src_ip'])
                port_summary[port]['unique_destinations'].add(conn['dst_ip'])
            
            for port, info in port_summary.items():
                severity = 'high' if info['count'] > 10 or len(info['unique_sources']) > 5 else 'medium'
                findings.append({
                    'type': 'suspicious_ports',
                    'severity': severity,
                    'count': info['count'],
                    'description': f"Suspicious activity on port {port}: {info['description']}",
                    'evidence': {
                        'port': port,
                        'connections': info['count'],
                        'unique_sources': len(info['unique_sources']),
                        'unique_destinations': len(info['unique_destinations']),
                        'source_ips': list(info['unique_sources'])[:10]
                    },
                    'data': [conn for conn in suspicious_connections if conn['dst_port'] == port][:10]
                })
        
        return findings
    
    def _detect_traffic_anomalies(self, packets_data):
        """Detect unusual traffic patterns"""
        findings = []
        
        # Analyze traffic volume patterns
        ip_traffic = {}
        for packet in packets_data:
            src_ip = packet['src_ip']
            packet_size = packet['packet_size']
            
            if src_ip not in ip_traffic:
                ip_traffic[src_ip] = {'total_bytes': 0, 'packet_count': 0}
            
            ip_traffic[src_ip]['total_bytes'] += packet_size
            ip_traffic[src_ip]['packet_count'] += 1
        
        # Find hosts with unusually high traffic
        for ip, traffic in ip_traffic.items():
            avg_packet_size = traffic['total_bytes'] / traffic['packet_count']
            
            # Flag large data transfers
            if traffic['total_bytes'] > 100_000_000:  # > 100MB
                findings.append({
                    'type': 'large_data_transfer',
                    'severity': 'high',
                    'count': 1,
                    'description': f"Host {ip} transferred {traffic['total_bytes']/1_000_000:.1f}MB of data",
                    'evidence': {
                        'host': ip,
                        'total_bytes': traffic['total_bytes'],
                        'packet_count': traffic['packet_count'],
                        'avg_packet_size': avg_packet_size
                    },
                    'data': []
                })
            
            # Flag hosts with unusual packet patterns
            if avg_packet_size > 8000:  # Very large average packet size
                findings.append({
                    'type': 'unusual_packet_size',
                    'severity': 'medium',
                    'count': traffic['packet_count'],
                    'description': f"Host {ip} has unusually large average packet size ({avg_packet_size:.0f} bytes)",
                    'evidence': {
                        'host': ip,
                        'avg_packet_size': avg_packet_size,
                        'packet_count': traffic['packet_count']
                    },
                    'data': []
                })
        
        return findings
    
    def _detect_data_exfiltration(self, packets_data):
        """Detect potential data exfiltration"""
        findings = []
        
        # Group outbound traffic by destination
        outbound_traffic = {}
        for packet in packets_data:
            src_ip = packet['src_ip']
            dst_ip = packet['dst_ip']
            
            # Assume internal network is 192.168.x.x, 10.x.x.x, 172.16-31.x.x
            is_internal_src = (src_ip.startswith('192.168.') or 
                             src_ip.startswith('10.') or 
                             any(src_ip.startswith(f'172.{i}.') for i in range(16, 32)))
            
            is_external_dst = not (dst_ip.startswith('192.168.') or 
                                 dst_ip.startswith('10.') or 
                                 any(dst_ip.startswith(f'172.{i}.') for i in range(16, 32)))
            
            if is_internal_src and is_external_dst:
                key = f"{src_ip}->{dst_ip}"
                if key not in outbound_traffic:
                    outbound_traffic[key] = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'bytes_sent': 0,
                        'packet_count': 0,
                        'ports': set()
                    }
                
                outbound_traffic[key]['bytes_sent'] += packet['packet_size']
                outbound_traffic[key]['packet_count'] += 1
                outbound_traffic[key]['ports'].add(packet['dst_port'])
        
        # Analyze for potential exfiltration
        for conn_key, traffic in outbound_traffic.items():
            # Large outbound transfers
            if traffic['bytes_sent'] > 50_000_000:  # > 50MB
                findings.append({
                    'type': 'potential_data_exfiltration',
                    'severity': 'high',
                    'count': 1,
                    'description': f"Large outbound transfer: {traffic['bytes_sent']/1_000_000:.1f}MB to external host",
                    'evidence': {
                        'src_ip': traffic['src_ip'],
                        'dst_ip': traffic['dst_ip'],
                        'bytes_sent': traffic['bytes_sent'],
                        'packet_count': traffic['packet_count'],
                        'ports_used': list(traffic['ports'])
                    },
                    'data': []
                })
            
            # Multiple ports to same destination (potential tunneling)
            if len(traffic['ports']) > 5:
                findings.append({
                    'type': 'multi_port_communication',
                    'severity': 'medium',
                    'count': len(traffic['ports']),
                    'description': f"Communication to external host using {len(traffic['ports'])} different ports",
                    'evidence': {
                        'src_ip': traffic['src_ip'],
                        'dst_ip': traffic['dst_ip'],
                        'ports_used': list(traffic['ports']),
                        'total_bytes': traffic['bytes_sent']
                    },
                    'data': []
                })
        
        return findings
    
    def _detect_brute_force_attempts(self, packets_data):
        """Detect brute force login attempts with enhanced source IP tracking"""
        findings = []
        
        # Common authentication ports
        auth_ports = {22: 'SSH', 23: 'Telnet', 21: 'FTP', 3389: 'RDP', 
                      139: 'SMB', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 
                      80: 'HTTP', 443: 'HTTPS', 25: 'SMTP', 110: 'POP3', 143: 'IMAP'}
        
        # Group connections by source IP and destination port for brute force detection
        auth_attempts = {}
        port_attack_summary = {}
        
        for packet in packets_data:
            dst_port = packet['dst_port']
            src_ip = packet['src_ip']
            dst_ip = packet['dst_ip']
            
            # Check both known auth ports and high-frequency connections to any port
            if dst_port in auth_ports or dst_port in [80, 443, 8080, 8443]:
                key = f"{src_ip}->{dst_ip}:{dst_port}"
                
                if key not in auth_attempts:
                    auth_attempts[key] = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'port': dst_port,
                        'service': auth_ports.get(dst_port, f'Port {dst_port}'),
                        'attempts': 0
                    }
                
                auth_attempts[key]['attempts'] += 1
                
                # Track per-port summaries
                if dst_port not in port_attack_summary:
                    port_attack_summary[dst_port] = {
                        'total_attempts': 0,
                        'source_ips': set(),
                        'target_ips': set(),
                        'service': auth_ports.get(dst_port, f'Port {dst_port}')
                    }
                
                port_attack_summary[dst_port]['total_attempts'] += 1
                port_attack_summary[dst_port]['source_ips'].add(src_ip)
                port_attack_summary[dst_port]['target_ips'].add(dst_ip)
        
        # Analyze for brute force patterns - individual source attacks
        for attempt_key, attempt in auth_attempts.items():
            if attempt['attempts'] > 20:  # Many attempts to same service
                severity = 'high' if attempt['attempts'] > 100 else 'medium'
                findings.append({
                    'type': 'brute_force_attempts',
                    'severity': severity,
                    'count': attempt['attempts'],
                    'description': f"Brute force attack from {attempt['src_ip']} against {attempt['service']} on {attempt['dst_ip']}",
                    'evidence': {
                        'src_ip': attempt['src_ip'],
                        'dst_ip': attempt['dst_ip'],
                        'service': attempt['service'],
                        'target_port': attempt['port'],
                        'attempt_count': attempt['attempts'],
                        'source_count': 1,
                        'failed_attempts': attempt['attempts']  # Assume all are failed attempts
                    },
                    'data': attempt
                })
        
        # Analyze for coordinated attacks on specific ports
        for port, summary in port_attack_summary.items():
            if summary['total_attempts'] > 50 and len(summary['source_ips']) > 1:
                severity = 'high' if summary['total_attempts'] > 500 else 'medium'
                findings.append({
                    'type': 'brute_force_attempts',
                    'severity': severity,
                    'count': summary['total_attempts'],
                    'description': f"Coordinated brute force attack against {summary['service']} from {len(summary['source_ips'])} sources",
                    'evidence': {
                        'target_port': port,
                        'service': summary['service'],
                        'source_count': len(summary['source_ips']),
                        'target_count': len(summary['target_ips']),
                        'failed_attempts': summary['total_attempts'],
                        'attempt_count': summary['total_attempts'],
                        'source_ips': list(summary['source_ips'])[:10],  # Top 10 sources
                        'target_ips': list(summary['target_ips'])[:5]    # Top 5 targets
                    },
                    'data': {
                        'port': port,
                        'total_attempts': summary['total_attempts'],
                        'unique_sources': len(summary['source_ips']),
                        'unique_targets': len(summary['target_ips'])
                    }
                })
        
        return findings
    
    def _detect_network_reconnaissance(self, packets_data):
        """Detect network reconnaissance activities with enhanced source tracking"""
        findings = []
        
        # Track IP scanning patterns
        src_scan_patterns = {}
        
        for packet in packets_data:
            src_ip = packet['src_ip']
            dst_ip = packet['dst_ip']
            
            if src_ip not in src_scan_patterns:
                src_scan_patterns[src_ip] = {
                    'unique_destinations': set(),
                    'unique_ports': set(),
                    'packet_count': 0
                }
            
            src_scan_patterns[src_ip]['unique_destinations'].add(dst_ip)
            src_scan_patterns[src_ip]['unique_ports'].add(packet['dst_port'])
            src_scan_patterns[src_ip]['packet_count'] += 1
        
        # Analyze patterns
        for src_ip, pattern in src_scan_patterns.items():
            dest_count = len(pattern['unique_destinations'])
            port_count = len(pattern['unique_ports'])
            
            # Network sweep detection (scanning many hosts)
            if dest_count > 10:  # Lowered threshold for better detection
                severity = 'high' if dest_count > 50 else 'medium'
                
                # Analyze network ranges being scanned
                network_ranges = self._analyze_network_ranges(pattern['unique_destinations'])
                
                findings.append({
                    'type': 'network_reconnaissance',
                    'severity': severity,
                    'count': dest_count,
                    'description': f"Network reconnaissance from {src_ip}: {dest_count} hosts scanned",
                    'evidence': {
                        'scanner_ip': src_ip,        # Use consistent field name
                        'src_ip': src_ip,            # Also include for backward compatibility
                        'hosts_contacted': dest_count,
                        'ports_involved': port_count,
                        'network_ranges': network_ranges,
                        'sample_destinations': sorted(list(pattern['unique_destinations']))[:20],
                        'sample_ports': sorted(list(pattern['unique_ports']))[:20]
                    },
                    'data': {
                        'scanner': src_ip,
                        'targets_count': dest_count,
                        'network_ranges': network_ranges
                    }
                })
            
            # Service enumeration (scanning many ports on few hosts)
            if port_count > 30 and dest_count < 10:
                findings.append({
                    'type': 'service_enumeration',
                    'severity': 'medium',
                    'count': port_count,
                    'description': f"Service enumeration from {src_ip}: {port_count} ports scanned on {dest_count} hosts",
                    'evidence': {
                        'scanner_ip': src_ip,
                        'src_ip': src_ip,
                        'ports_scanned': port_count,
                        'hosts_targeted': dest_count,
                        'target_hosts': sorted(list(pattern['unique_destinations'])),
                        'sample_ports': sorted(list(pattern['unique_ports']))[:20]
                    },
                    'data': {
                        'scanner': src_ip,
                        'ports_count': port_count,
                        'hosts_count': dest_count
                    }
                })
        
        return findings
    
    def _detect_malware_communication(self, packets_data):
        """Detect malware communication patterns"""
        findings = []
        
        # Track communication patterns that might indicate C2
        comm_patterns = {}
        
        for packet in packets_data:
            src_ip = packet['src_ip']
            dst_ip = packet['dst_ip']
            dst_port = packet['dst_port']
            
            # Skip internal-to-internal communication
            is_internal_src = (src_ip.startswith('192.168.') or src_ip.startswith('10.'))
            is_external_dst = not (dst_ip.startswith('192.168.') or dst_ip.startswith('10.'))
            
            if is_internal_src and is_external_dst:
                key = f"{src_ip}->{dst_ip}:{dst_port}"
                if key not in comm_patterns:
                    comm_patterns[key] = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'packet_count': 0,
                        'regular_intervals': []
                    }
                
                comm_patterns[key]['packet_count'] += 1
                comm_patterns[key]['regular_intervals'].append(packet['timestamp'])
        
        # Analyze for C2 patterns
        for comm_key, comm in comm_patterns.items():
            # Regular beaconing (consistent intervals)
            if comm['packet_count'] > 20:
                intervals = comm['regular_intervals']
                if len(intervals) > 10:
                    # Check for regular timing patterns
                    time_diffs = [intervals[i+1] - intervals[i] for i in range(len(intervals)-1)]
                    avg_interval = sum(time_diffs) / len(time_diffs)
                    
                    # If most intervals are similar, might be beaconing
                    regular_count = sum(1 for diff in time_diffs if abs(diff - avg_interval) < avg_interval * 0.3)
                    if regular_count > len(time_diffs) * 0.7:  # 70% regular intervals
                        findings.append({
                            'type': 'potential_c2_beaconing',
                            'severity': 'high',
                            'count': comm['packet_count'],
                            'description': f"Regular communication pattern detected (potential C2 beaconing)",
                            'evidence': {
                                'src_ip': comm['src_ip'],
                                'dst_ip': comm['dst_ip'],
                                'dst_port': comm['dst_port'],
                                'packet_count': comm['packet_count'],
                                'avg_interval': avg_interval,
                                'regularity_percentage': (regular_count / len(time_diffs)) * 100
                            },
                            'data': []
                        })
            
            # Unusual ports for external communication
            suspicious_c2_ports = [8080, 8443, 9001, 9002, 4444, 5555, 6666, 7777, 8888, 9999]
            if comm['dst_port'] in suspicious_c2_ports:
                findings.append({
                    'type': 'suspicious_c2_port',
                    'severity': 'medium',
                    'count': comm['packet_count'],
                    'description': f"Communication on suspicious C2 port {comm['dst_port']}",
                    'evidence': {
                        'src_ip': comm['src_ip'],
                        'dst_ip': comm['dst_ip'],
                        'dst_port': comm['dst_port'],
                        'packet_count': comm['packet_count']
                    },
                    'data': []
                })
        
        return findings
    
    def _run_rustml_analysis(self, packets_data):
        """Run RustML analysis with error handling and enhanced source IP detection"""
        findings = []
        
        try:
            # Enhanced port scan detection with source IP details
            if RUSTML_AVAILABLE:
                try:
                    # Try the new enhanced RustML functions first
                    port_scan_results = detect_port_scan(packets_data, threshold=20)
                    if port_scan_results:
                        # Handle structured data from enhanced RustML
                        for scan_data in port_scan_results[:10]:
                            if isinstance(scan_data, dict):
                                source_ip = scan_data.get('source', 'Unknown')
                                ports_scanned = scan_data.get('ports_scanned', 0)
                                targets_count = scan_data.get('targets_count', 0)
                                scan_intensity = scan_data.get('scan_intensity', 0.0)
                                
                                findings.append({
                                    'type': 'rustml_port_scanning',
                                    'severity': 'high',
                                    'count': 1,
                                    'description': f"Port scan from {source_ip}: {ports_scanned} ports scanned across {targets_count} targets",
                                    'evidence': {
                                        'source_ip': source_ip,
                                        'ports_scanned': ports_scanned,
                                        'targets_count': targets_count,
                                        'scan_intensity': round(scan_intensity, 2),
                                        'ports_list': (scan_data.get('ports_list') or [])[:20],
                                        'targets_list': (scan_data.get('targets_list') or [])[:10]
                                    },
                                    'data': scan_data
                                })
                    
                    # Try network sweep detection
                    try:
                        from rustml import detect_network_sweep
                        sweep_results = detect_network_sweep(packets_data, min_targets=5)
                        if sweep_results:
                            for sweep_data in sweep_results[:5]:
                                if isinstance(sweep_data, dict):
                                    scanner_ip = sweep_data.get('scanner', 'Unknown')
                                    targets_count = sweep_data.get('targets_count', 0)
                                    
                                    findings.append({
                                        'type': 'rustml_network_sweep',
                                        'severity': 'high',
                                        'count': 1,
                                        'description': f"Network reconnaissance from {scanner_ip}: {targets_count} targets scanned",
                                        'evidence': {
                                            'scanner_ip': scanner_ip,
                                            'targets_count': targets_count,
                                            'network_ranges': sweep_data.get('network_ranges', []),
                                            'targets_sample': (sweep_data.get('targets_list') or [])[:10]
                                        },
                                        'data': sweep_data
                                    })
                    except ImportError:
                        pass  # Function not available
                    
                except Exception as rustml_error:
                    # Fallback to basic RustML analysis
                    basic_findings = self._run_basic_rustml_analysis(packets_data)
                    findings.extend(basic_findings)
                    
            else:
                # RustML not available, use Python-based enhanced detection
                enhanced_findings = self._run_enhanced_python_analysis(packets_data)
                findings.extend(enhanced_findings)
                
        except Exception as e:
            findings.append({
                'type': 'rustml_error',
                'severity': 'low',
                'count': 1,
                'description': f"RustML analysis failed: {str(e)}",
                'evidence': {},
                'data': {'error': str(e)}
            })
            
        return findings
    
    def _run_basic_rustml_analysis(self, packets_data):
        """Fallback basic RustML analysis"""
        findings = []
        
        try:
            # Basic port scan detection
            port_scans = detect_port_scan(packets_data, 20)
            if port_scans:
                findings.append({
                    'type': 'rustml_port_scanning',
                    'severity': 'high',
                    'count': len(port_scans),
                    'description': f"RustML detected {len(port_scans)} port scanning activities",
                    'evidence': {
                        'scanning_activities': len(port_scans),
                        'threshold_used': 20
                    },
                    'data': port_scans[:10] if port_scans and isinstance(port_scans[0], dict) else ["Port scan detected"] * min(len(port_scans), 10)
                })

            # Suspicious port detection
            suspicious_conns = []
            for packet in packets_data:
                if is_suspicious_port(packet['dst_port']):
                    suspicious_conns.append(packet)

            if suspicious_conns:
                findings.append({
                    'type': 'rustml_suspicious_ports',
                    'severity': 'medium',
                    'count': len(suspicious_conns),
                    'description': f"RustML flagged {len(suspicious_conns)} connections to suspicious ports",
                    'evidence': {
                        'suspicious_connections': len(suspicious_conns),
                        'sample_ports': list(set([p['dst_port'] for p in suspicious_conns[:20]]))
                    },
                    'data': suspicious_conns[:10]
                })
                
        except Exception as e:
            findings.append({
                'type': 'rustml_basic_error',
                'severity': 'low',
                'count': 1,
                'description': f"Basic RustML analysis failed: {str(e)}",
                'evidence': {},
                'data': {'error': str(e)}
            })
            
        return findings
    
    def _run_enhanced_python_analysis(self, packets_data):
        """Enhanced Python-based analysis when RustML is not available"""
        findings = []
        
        try:
            # Enhanced port scan detection with source IP tracking
            ip_port_map = {}
            ip_target_map = {}
            
            for packet in packets_data:
                src_ip = packet['src_ip']
                dst_ip = packet['dst_ip']
                dst_port = packet['dst_port']
                
                # Track ports per source IP
                if src_ip not in ip_port_map:
                    ip_port_map[src_ip] = set()
                    ip_target_map[src_ip] = set()
                
                ip_port_map[src_ip].add(dst_port)
                ip_target_map[src_ip].add(dst_ip)
            
            # Detect port scanning (20+ ports per IP)
            for src_ip, ports in ip_port_map.items():
                if len(ports) >= 20:
                    targets = ip_target_map[src_ip]
                    scan_intensity = len(ports) / len(targets) if targets else len(ports)
                    
                    findings.append({
                        'type': 'enhanced_port_scanning',
                        'severity': 'high',
                        'count': 1,
                        'description': f"Port scan from {src_ip}: {len(ports)} ports scanned across {len(targets)} targets",
                        'evidence': {
                            'source_ip': src_ip,
                            'ports_scanned': len(ports),
                            'targets_count': len(targets),
                            'scan_intensity': round(scan_intensity, 2),
                            'ports_list': sorted(list(ports))[:20],
                            'targets_list': sorted(list(targets))[:10]
                        },
                        'data': {
                            'source': src_ip,
                            'ports_scanned': len(ports),
                            'targets_count': len(targets),
                            'scan_intensity': scan_intensity
                        }
                    })
            
            # Detect network sweeps (5+ targets per IP)
            for src_ip, targets in ip_target_map.items():
                if len(targets) >= 5:
                    # Analyze network ranges
                    network_ranges = self._analyze_network_ranges(targets)
                    
                    findings.append({
                        'type': 'enhanced_network_sweep',
                        'severity': 'high',
                        'count': 1,
                        'description': f"Network reconnaissance from {src_ip}: {len(targets)} targets scanned",
                        'evidence': {
                            'scanner_ip': src_ip,
                            'targets_count': len(targets),
                            'network_ranges': network_ranges,
                            'targets_sample': sorted(list(targets))[:10]
                        },
                        'data': {
                            'scanner': src_ip,
                            'targets_count': len(targets),
                            'network_ranges': network_ranges
                        }
                    })
                    
        except Exception as e:
            findings.append({
                'type': 'enhanced_analysis_error',
                'severity': 'low',
                'count': 1,
                'description': f"Enhanced Python analysis failed: {str(e)}",
                'evidence': {},
                'data': {'error': str(e)}
            })
            
        return findings
    
    def _analyze_network_ranges(self, target_ips):
        """Analyze target IPs to identify network ranges being scanned"""
        ranges = {}
        
        for ip in target_ips:
            parts = ip.split('.')
            if len(parts) == 4:
                # Group by /24 network
                network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                if network not in ranges:
                    ranges[network] = 0
                ranges[network] += 1
        
        # Return networks with 3+ IPs
        return [network for network, count in ranges.items() if count >= 3]
    
    def _analyze_with_topology_context(self, packets_data):
        """Analyze packets with network topology context"""
        contextual_findings = []
        
        if not self.topology_context:
            return contextual_findings
        
        # Get expected traffic patterns from topology
        expected_traffic = self.topology_context.get('expected_traffic', [])
        threat_indicators = self.topology_context.get('threat_indicators', [])
        network_segments = self.topology_context.get('network_segments', [])
        
        # Analyze against expected patterns
        for packet in packets_data:
            findings = self._check_packet_against_context(packet, expected_traffic, threat_indicators, network_segments)
            contextual_findings.extend(findings)
        
        # Aggregate findings
        finding_summary = {}
        for finding in contextual_findings:
            key = f"{finding['type']}_{finding['severity']}"
            if key not in finding_summary:
                finding_summary[key] = {
                    'type': finding['type'],
                    'severity': finding['severity'],
                    'count': 0,
                    'description': finding['description'],
                    'examples': []
                }
            finding_summary[key]['count'] += 1
            if len(finding_summary[key]['examples']) < 3:
                finding_summary[key]['examples'].append(finding.get('evidence', ''))
        
        return list(finding_summary.values())
    
    def _check_packet_against_context(self, packet, expected_traffic, threat_indicators, network_segments):
        """Check individual packet against topology context"""
        findings = []
        
        src_ip = packet['src_ip']
        dst_ip = packet['dst_ip']
        dst_port = packet['dst_port']
        protocol = packet['protocol']
        
        # Check if traffic matches expected patterns
        traffic_expected = False
        for expected in expected_traffic:
            if (expected.get('protocol', '').upper() in protocol.upper() and
                str(dst_port) in str(expected.get('port', ''))):
                traffic_expected = True
                break
        
        # Check against threat indicators
        for indicator in threat_indicators:
            pattern = indicator.get('pattern', '')
            severity = indicator.get('severity', 'medium')
            
            if pattern == 'port_scan' and dst_port > 1024:
                findings.append({
                    'type': 'potential_port_scan',
                    'severity': severity,
                    'description': f"Traffic to high port {dst_port} - potential scanning",
                    'evidence': f"{src_ip} -> {dst_ip}:{dst_port}",
                    'timestamp': packet['timestamp']
                })
            
            elif pattern == 'data_exfiltration' and packet['packet_size'] > 1500:
                findings.append({
                    'type': 'potential_data_exfiltration',
                    'severity': severity,
                    'description': f"Large packet size {packet['packet_size']} bytes",
                    'evidence': f"{src_ip} -> {dst_ip} ({packet['packet_size']} bytes)",
                    'timestamp': packet['timestamp']
                })
            
            elif pattern == 'c2_communication' and not traffic_expected:
                findings.append({
                    'type': 'unexpected_communication',
                    'severity': severity,
                    'description': f"Communication not matching expected traffic patterns",
                    'evidence': f"{src_ip} -> {dst_ip}:{dst_port} ({protocol})",
                    'timestamp': packet['timestamp']
                })
        
        # Check network segmentation violations
        for segment in network_segments:
            if segment.get('security_level') == 'high':
                # Flag any external communication from high-security segments
                if src_ip.startswith('192.168.') and not dst_ip.startswith('192.168.'):
                    findings.append({
                        'type': 'segmentation_violation',
                        'severity': 'high',
                        'description': f"High-security segment communicating externally",
                        'evidence': f"{src_ip} -> {dst_ip}:{dst_port}",
                        'timestamp': packet['timestamp']
                    })
        
        return findings
    
    def _save_enhanced_report(self, all_results, output_file):
        """Save enhanced analysis report with normalization and deduplication"""
        # Create output directory path
        output_dir = Path(__file__).parent.parent / "analysis outputs"
        output_dir.mkdir(exist_ok=True)
        
        # Auto-generate filename if not provided
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"enhanced_analysis_{timestamp}.json"
        
        # Create full paths for output files
        json_path = output_dir / output_file
        text_path = output_dir / output_file.replace('.json', '.txt')
        csv_path = output_dir / output_file.replace('.json', '.csv')
        
        # Normalize and aggregate findings across all files
        print("🔧 Normalizing and deduplicating findings...")
        normalized_findings, normalized_summary = self._normalize_and_aggregate_findings(all_results)
        
        # Apply topology-aware filtering if available
        if self.topology_context:
            print("🌐 Applying topology-aware filtering...")
            normalized_findings = self._apply_topology_filtering(normalized_findings, self.topology_context)
        
        # Apply whitelist filtering to reduce false positives
        print("🔍 Applying whitelist filtering for false positives...")
        normalized_findings = self._apply_whitelist_filtering(normalized_findings)
        
        # Apply confidence filtering
        print("🎯 Applying confidence-based filtering...")
        high_confidence_findings = self._apply_confidence_filtering(normalized_findings, min_confidence=0.6)
        
        # Calculate summary based on NORMALIZED findings, not raw counts
        final_summary = {
            'total_threats': sum(f.get('count', 0) for f in high_confidence_findings),
            'high_severity': sum(f.get('count', 0) for f in high_confidence_findings if f.get('severity') == 'high'),
            'medium_severity': sum(f.get('count', 0) for f in high_confidence_findings if f.get('severity') == 'medium'),
            'low_severity': sum(f.get('count', 0) for f in high_confidence_findings if f.get('severity') == 'low'),
            'unique_findings': len(high_confidence_findings),
            'contextual_findings': 0  # Will be updated if topology context available
        }
        
        # Sort findings by severity and confidence
        severity_order = {"high": 3, "medium": 2, "low": 1}
        high_confidence_findings.sort(key=lambda x: (severity_order.get(x["severity"], 0), x["confidence"]), reverse=True)
        
        # Update results with normalized findings
        updated_results = []
        for result in all_results:
            updated_result = result.copy()
            updated_result['findings'] = [f for f in normalized_findings 
                                        if any(self.evidence_match(f, orig) for orig in result.get('findings', []))]
            updated_results.append(updated_result)
        
        # Generate top suspicious IPs and timeline data
        top_attackers = self._extract_top_attackers(high_confidence_findings)
        attack_timeline = self._generate_attack_timeline(all_results)
        
        # Update final summary with additional metadata
        final_summary.update({
            "high_confidence_findings": len(high_confidence_findings),
            "top_attackers": top_attackers[:10],
            "attack_timeline_summary": attack_timeline
        })
        
        report = {
            'analysis_metadata': {
                'timestamp': datetime.now().isoformat(),
                'analyzer_version': 'EntryShark Enhanced v1.0',
                'topology_context_available': bool(self.topology_context),
                'files_analyzed': len(all_results),
                'normalization_applied': True,
                'confidence_threshold': 0.6
            },
            'network_topology': self.topology_context,
            'pcap_analysis': updated_results,
            'normalized_findings': high_confidence_findings,
            'summary': final_summary  # Use the corrected summary
        }
        
        # Save as JSON
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save as CSV for analysis
        self._save_findings_csv(high_confidence_findings, csv_path)
        
        # Also save as human-readable text
        self._save_readable_report(report, text_path)
        
        print(f"✅ Enhanced report saved to: {json_path}")
        print(f"✅ Readable report saved to: {text_path}")
        print(f"✅ CSV export saved to: {csv_path}")
        print(f"📊 Summary: {final_summary['total_threats']} total threats, "
              f"{final_summary['unique_findings']} unique findings, "
              f"{len(high_confidence_findings)} high-confidence threats")

    def _map_rustml_to_canonical(self, rustml_findings):
        """Map rustml result names to canonical finding types and return mapped list."""
        mapping = {
            "rustml_port_scanning": "port_scanning",
            "rustml_port_scan": "port_scanning", 
            "rustml_suspicious_ports": "suspicious_ports",
            "rustml_network_sweep": "network_reconnaissance",
            "enhanced_port_scanning": "port_scanning",
            "enhanced_network_sweep": "network_reconnaissance",
            "port_scan": "port_scanning",  # normalize variants
            "horizontal_scanning": "network_reconnaissance",
            "network_sweep": "network_reconnaissance"
        }
        
        mapped = []
        for r in rustml_findings:
            rt = r.copy()
            typ = rt.get("type", "").lower()
            
            # Apply mapping if exists
            if typ in mapping:
                rt["type"] = mapping[typ]
            
            # Mark source so we can give rustml credit but avoid double counts
            source = "enhanced_analysis" if typ.startswith("enhanced_") else "rustml"
            rt.setdefault("source", source)
            mapped.append(rt)
        
        return mapped

    def evidence_match(self, normalized_finding, original_finding):
        """Helper function to match normalized findings with original findings"""
        norm_ev = normalized_finding.get("evidence", {})
        orig_ev = original_finding.get("evidence", {})
        
        # Simple matching based on IPs and ports
        return (norm_ev.get("src_ip") == orig_ev.get("src_ip") or
                norm_ev.get("scanner_ip") == orig_ev.get("scanner_ip") or
                norm_ev.get("source_ip") == orig_ev.get("source_ip"))

    def _save_findings_csv(self, findings, csv_path):
        """Save findings to CSV for further analysis"""
        import csv
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['type', 'severity', 'count', 'confidence', 'source_ip', 'target_ip', 
                         'target_port', 'description', 'detector_sources']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for finding in findings:
                evidence = finding.get('evidence', {})
                writer.writerow({
                    'type': finding.get('type', ''),
                    'severity': finding.get('severity', ''),
                    'count': finding.get('count', 0),
                    'confidence': finding.get('confidence', 0.0),
                    'source_ip': evidence.get('scanner_ip') or evidence.get('src_ip') or evidence.get('source_ip') or '',
                    'target_ip': evidence.get('target_ip') or evidence.get('dst_ip') or '',
                    'target_port': evidence.get('target_port') or evidence.get('port') or '',
                    'description': finding.get('description', ''),
                    'detector_sources': ','.join(finding.get('detector_sources', []))
                })

    def _extract_top_attackers(self, findings):
        """Extract top attacker IPs from findings"""
        from collections import defaultdict
        
        attacker_stats = defaultdict(lambda: {'threat_count': 0, 'severity_score': 0, 'attack_types': set()})
        
        for finding in findings:
            evidence = finding.get('evidence', {})
            attacker_ip = evidence.get('scanner_ip') or evidence.get('src_ip') or evidence.get('source_ip')
            
            if attacker_ip and attacker_ip != 'Unknown':
                stats = attacker_stats[attacker_ip]
                stats['threat_count'] += finding.get('count', 1)
                stats['attack_types'].add(finding.get('type', 'unknown'))
                
                # Calculate severity score
                severity = finding.get('severity', 'low').lower()
                severity_scores = {'high': 3, 'medium': 2, 'low': 1}
                stats['severity_score'] += severity_scores.get(severity, 1) * finding.get('count', 1)
        
        # Convert to list and sort by severity score
        top_attackers = []
        for ip, stats in attacker_stats.items():
            top_attackers.append({
                'ip': ip,
                'threat_count': stats['threat_count'],
                'severity_score': stats['severity_score'],
                'attack_types': list(stats['attack_types']),
                'risk_level': 'high' if stats['severity_score'] > 100 else 'medium' if stats['severity_score'] > 20 else 'low'
            })
        
        return sorted(top_attackers, key=lambda x: x['severity_score'], reverse=True)

    def _generate_attack_timeline(self, all_results):
        """Generate attack timeline summary"""
        timeline_summary = {
            'total_events': 0,
            'peak_attack_periods': [],
            'attack_duration_estimate': 'unknown',
            'most_active_protocols': []
        }
        
        # Simple timeline analysis based on available data
        total_events = sum(len(result.get('findings', [])) for result in all_results)
        timeline_summary['total_events'] = total_events
        
        if total_events > 0:
            # Estimate attack duration based on file count and findings
            if len(all_results) > 1:
                timeline_summary['attack_duration_estimate'] = f"Multi-file analysis ({len(all_results)} files)"
            else:
                timeline_summary['attack_duration_estimate'] = "Single capture analysis"
        
        return timeline_summary
    
    def _save_readable_report(self, report, text_file):
        """Save enhanced human-readable security report"""
        with open(text_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("🦈 EntryShark Enhanced Security Analysis Report\n")
            f.write("=" * 60 + "\n\n")
            
            # Executive Summary
            threat_summary = self._generate_threat_summary(report)
            f.write("📋 EXECUTIVE SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write(f"Overall Risk Level: {threat_summary['overall_risk']}\n")
            f.write(f"Total Security Findings: {threat_summary['total_findings']}\n")
            f.write(f"Critical Issues: {threat_summary['critical_count']}\n")
            f.write(f"High Priority Issues: {threat_summary['high_count']}\n")
            f.write(f"Medium Priority Issues: {threat_summary['medium_count']}\n\n")
            
            # Key Findings
            if threat_summary['key_findings']:
                f.write("🎯 KEY SECURITY FINDINGS\n")
                f.write("-" * 25 + "\n")
                for finding in threat_summary['key_findings']:
                    f.write(f"• {finding}\n")
                f.write("\n")
            
            # Metadata
            metadata = report['analysis_metadata']
            f.write(f"📅 Analysis Details\n")
            f.write("-" * 18 + "\n")
            f.write(f"Timestamp: {metadata['timestamp']}\n")
            f.write(f"Analyzer Version: {metadata['analyzer_version']}\n")
            f.write(f"Files Analyzed: {metadata['files_analyzed']}\n")
            f.write(f"AI Context: {'Enhanced with topology' if metadata['topology_context_available'] else 'Standard analysis'}\n\n")
            
            # Network Topology Analysis
            if report.get('network_topology'):
                f.write("🌐 NETWORK TOPOLOGY INTELLIGENCE\n")
                f.write("-" * 35 + "\n")
                
                topology = report['network_topology']
                
                if 'network_segments' in topology:
                    f.write("Network Architecture:\n")
                    for segment in topology['network_segments']:
                        f.write(f"  📍 {segment.get('name', 'Unknown Segment')}\n")
                        f.write(f"     Purpose: {segment.get('purpose', 'N/A')}\n")
                        f.write(f"     Security Level: {segment.get('security_level', 'unknown')}\n\n")
                
                if 'threat_indicators' in topology:
                    f.write("AI-Predicted Threat Patterns:\n")
                    for indicator in topology['threat_indicators']:
                        severity_icon = "🔴" if indicator.get('severity') == 'high' else "🟡" if indicator.get('severity') == 'medium' else "🟢"
                        f.write(f"  {severity_icon} {indicator.get('pattern', 'Unknown Pattern')}\n")
                        f.write(f"     Risk: {indicator.get('description', 'N/A')}\n\n")
            
            # Detailed Security Analysis
            f.write("🔍 DETAILED SECURITY ANALYSIS\n")
            f.write("-" * 32 + "\n")
            
            for i, result in enumerate(report['pcap_analysis']):
                filename = Path(result['file']).name
                f.write(f"\n📁 Analysis of: {filename}\n")
                f.write("=" * (len(filename) + 15) + "\n")
                
                # Network Statistics
                stats = result['stats']
                f.write(f"📊 Network Statistics:\n")
                f.write(f"   Total Packets Analyzed: {stats['total_packets']:,}\n")
                f.write(f"   Unique IP Addresses: {stats['unique_ips']}\n")
                f.write(f"   Protocols Observed: {', '.join(stats['protocols'].keys())}\n")
                
                # Protocol breakdown
                if stats['protocols']:
                    f.write(f"   Protocol Distribution:\n")
                    for protocol, count in stats['protocols'].items():
                        percentage = (count / stats['total_packets']) * 100
                        f.write(f"     • {protocol}: {count:,} packets ({percentage:.1f}%)\n")
                f.write("\n")
                
                # Security Findings
                if result.get('findings'):
                    f.write("🚨 SECURITY FINDINGS\n")
                    f.write("-" * 18 + "\n")
                    
                    # Group findings by severity
                    findings_by_severity = {'high': [], 'medium': [], 'low': []}
                    for finding in result['findings']:
                        severity = finding.get('severity', 'low')
                        findings_by_severity[severity].append(finding)
                    
                    # Report by severity
                    for severity in ['high', 'medium', 'low']:
                        if findings_by_severity[severity]:
                            severity_icon = "🔴" if severity == 'high' else "🟡" if severity == 'medium' else "🟢"
                            f.write(f"\n{severity_icon} {severity.upper()} SEVERITY THREATS:\n")
                            
                            for finding in findings_by_severity[severity]:
                                self._format_finding_detail(f, finding)
                    
                else:
                    f.write("✅ No significant security threats detected in this file.\n\n")
            
            # Summary section
            if 'summary' in report:
                f.write("📊 ANALYSIS SUMMARY\n")
                f.write("-" * 20 + "\n")
                summary = report['summary']
                f.write(f"Total Threats Detected: {summary.get('total_threats', 0)}\n")
                f.write(f"High Severity Issues: {summary.get('high_severity', 0)}\n")
                f.write(f"Medium Severity Issues: {summary.get('medium_severity', 0)}\n")
                f.write(f"Context-Aware Findings: {summary.get('contextual_findings', 0)}\n\n")
            
            # Recommendations
            f.write("💡 SECURITY RECOMMENDATIONS\n")
            f.write("-" * 27 + "\n")
            recommendations = self._generate_recommendations(report)
            for rec in recommendations:
                f.write(f"• {rec}\n")
            
            # Footer
            f.write(f"\n{'=' * 60}\n")
            f.write("Report generated by EntryShark Enhanced PCAP Analyzer\n")
            f.write("For technical support, consult the EntryShark documentation.\n")
    
    def _format_finding_detail(self, f, finding):
        """Format individual finding with detailed information"""
        finding_type = finding.get('type', 'unknown')
        count = finding.get('count', 0)
        description = finding.get('description', '')
        
        # Custom formatting for different threat types
        if finding_type == 'port_scanning':
            f.write(f"   🔍 Port Scanning Activity: {count} scan events detected\n")
            if finding.get('evidence'):
                evidence = finding['evidence']
                f.write(f"      Source: {evidence.get('scanner_ip', 'Unknown')}\n")
                f.write(f"      Targets: {evidence.get('target_count', 0)} hosts\n")
                f.write(f"      Ports Scanned: {evidence.get('total_ports', 0)}\n")
        
        elif finding_type == 'brute_force_attempts':
            f.write(f"   🔨 Brute Force Attack: {count} attempts detected\n")
            if finding.get('evidence'):
                evidence = finding['evidence']
                f.write(f"      Target Service: Port {evidence.get('target_port', 'Unknown')}\n")
                f.write(f"      Attack Sources: {evidence.get('source_count', 0)} IPs\n")
                f.write(f"      Failed Attempts: {evidence.get('failed_attempts', 0)}\n")
        
        elif finding_type == 'suspicious_ports':
            f.write(f"   ⚠️  Suspicious Port Activity: {count} connections\n")
            if finding.get('evidence'):
                evidence = finding['evidence']
                ports = evidence.get('suspicious_ports', [])
                f.write(f"      Ports: {', '.join(map(str, ports[:10]))}\n")
                if len(ports) > 10:
                    f.write(f"      ... and {len(ports) - 10} more\n")
        
        elif finding_type == 'network_reconnaissance':
            f.write(f"   🔎 Network Reconnaissance: {count} sweep events\n")
            if finding.get('evidence'):
                evidence = finding['evidence']
                f.write(f"      Scanner: {evidence.get('scanner_ip', 'Unknown')}\n")
                f.write(f"      Network Range: {evidence.get('target_range', 'Unknown')}\n")
        
        elif finding_type == 'lateral_movement_admin':
            f.write(f"   ↔️  Lateral Movement: Administrative service access\n")
            if finding.get('evidence'):
                evidence = finding['evidence']
                f.write(f"      Source: {evidence.get('src_ip', 'Unknown')}\n")
                f.write(f"      Target: {evidence.get('dst_ip', 'Unknown')}\n")
                f.write(f"      Admin Ports: {', '.join(map(str, evidence.get('admin_ports', [])))}\n")
        
        elif finding_type == 'dns_tunneling_large_packets':
            f.write(f"   🕳️  DNS Tunneling Detected: {count} large DNS packets\n")
            f.write(f"      Potential data exfiltration via DNS protocol\n")
        
        elif finding_type == 'large_file_transfer':
            f.write(f"   📤 Large File Transfer: {description}\n")
            if finding.get('evidence'):
                evidence = finding['evidence']
                f.write(f"      Size: {evidence.get('total_bytes', 0) / 1_000_000:.1f} MB\n")
                f.write(f"      Protocol: Port {evidence.get('port', 'Unknown')}\n")
        
        else:
            f.write(f"   ⚠️  {finding_type.replace('_', ' ').title()}: {description or f'{count} events'}\n")
        
        f.write("\n")
    
    def _generate_threat_summary(self, report):
        """Generate executive threat summary from normalized findings"""
        total_findings = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        key_findings = []
        
        # Use normalized findings if available, otherwise fall back to pcap_analysis
        if 'normalized_findings' in report:
            findings_to_analyze = report['normalized_findings']
        else:
            findings_to_analyze = []
            for result in report['pcap_analysis']:
                findings_to_analyze.extend(result.get('findings', []))
        
        for finding in findings_to_analyze:
            total_findings += 1
            severity = finding.get('severity', 'low').lower()
            finding_type = finding.get('type', '')
            count = finding.get('count', 0)
            confidence = finding.get('confidence', 0.75)
            
            if severity == 'critical':
                critical_count += 1
            elif severity == 'high':
                high_count += 1
            elif severity == 'medium':
                medium_count += 1
            
            # Add significant findings to key findings (high confidence + high impact)
            if (severity in ['high', 'critical'] or count > 50) and confidence > 0.7:
                evidence = finding.get('evidence', {})
                if finding_type == 'port_scan':
                    source_ip = evidence.get('scanner_ip') or evidence.get('src_ip', 'unknown source')
                    key_findings.append(f"Port scanning activity detected from {source_ip} (confidence: {confidence:.1f})")
                elif finding_type == 'brute_force_attempts':
                    target_port = evidence.get('target_port', 'unknown')
                    key_findings.append(f"Brute force attack with {count} attempts on port {target_port} (confidence: {confidence:.1f})")
                elif finding_type == 'network_reconnaissance':
                    key_findings.append(f"Network reconnaissance: {count} sweep events detected (confidence: {confidence:.1f})")
                elif finding_type == 'suspicious_ports':
                    key_findings.append(f"Suspicious port activity: {count} connections to unusual services (confidence: {confidence:.1f})")
                elif finding_type == 'lateral_movement_admin':
                    src_ip = evidence.get('src_ip', 'unknown')
                    dst_ip = evidence.get('dst_ip', 'unknown')
                    key_findings.append(f"Lateral movement detected: {src_ip} → {dst_ip} (confidence: {confidence:.1f})")
        
        # Determine overall risk based on severity and confidence
        if critical_count > 0:
            overall_risk = "🔴 CRITICAL"
        elif high_count >= 3:
            overall_risk = "🔴 HIGH"
        elif high_count > 0 or medium_count >= 5:
            overall_risk = "🟡 MEDIUM"
        elif medium_count > 0:
            overall_risk = "🟢 LOW-MEDIUM"
        else:
            overall_risk = "🟢 LOW"
        
        return {
            'overall_risk': overall_risk,
            'total_findings': total_findings,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'key_findings': key_findings[:5]  # Top 5 key findings
        }
    
    def _generate_recommendations(self, report):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        finding_types = set()
        for result in report['pcap_analysis']:
            if result.get('findings'):
                for finding in result['findings']:
                    finding_types.add(finding.get('type', ''))
        
        # Generate specific recommendations based on findings
        if 'port_scanning' in finding_types:
            recommendations.append("Implement network segmentation and intrusion detection systems to detect and block port scanning attempts")
            recommendations.append("Configure firewall rules to limit unnecessary port exposure and log suspicious scanning activity")
        
        if 'brute_force_attempts' in finding_types:
            recommendations.append("Enable account lockout policies and implement multi-factor authentication for critical services")
            recommendations.append("Deploy fail2ban or similar tools to automatically block IP addresses after failed login attempts")
        
        if 'suspicious_ports' in finding_types:
            recommendations.append("Review and validate all open ports - close unnecessary services and restrict access to authorized users only")
            recommendations.append("Implement application whitelisting and regular vulnerability assessments")
        
        if 'network_reconnaissance' in finding_types:
            recommendations.append("Deploy network monitoring tools to detect and alert on reconnaissance activities")
            recommendations.append("Implement honeypots to detect and analyze attacker behavior patterns")
        
        if 'lateral_movement_admin' in finding_types:
            recommendations.append("Implement privileged access management (PAM) and monitor administrative service usage")
            recommendations.append("Use network segmentation to limit lateral movement between network segments")
        
        if 'dns_tunneling_large_packets' in finding_types:
            recommendations.append("Implement DNS monitoring and filtering to detect data exfiltration attempts")
            recommendations.append("Configure DNS servers to block suspicious domains and monitor large DNS responses")
        
        # General recommendations
        recommendations.extend([
            "Regularly update and patch all network devices and software systems",
            "Conduct periodic security assessments and penetration testing",
            "Implement comprehensive logging and monitoring across all network infrastructure",
            "Establish an incident response plan for detected security threats",
            "Provide security awareness training for all personnel"
        ])
        
        return recommendations[:8]  # Return top 8 recommendations
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write("🦈 EntryShark Enhanced Analysis Report\n")
            f.write("=" * 50 + "\n\n")
            
            # Metadata
            metadata = report['analysis_metadata']
            f.write(f"📅 Analysis Time: {metadata['timestamp']}\n")
            f.write(f"🔧 Analyzer Version: {metadata['analyzer_version']}\n")
            f.write(f"📁 Files Analyzed: {metadata['files_analyzed']}\n")
            f.write(f"🖼️  Topology Context: {'Yes' if metadata['topology_context_available'] else 'No'}\n\n")
            
            # Network Topology Summary
            if report.get('network_topology'):
                f.write("🌐 NETWORK TOPOLOGY ANALYSIS\n")
                f.write("-" * 30 + "\n")
                
                topology = report['network_topology']
                
                if 'network_segments' in topology:
                    f.write("Network Segments:\n")
                    for segment in topology['network_segments']:
                        f.write(f"  • {segment.get('name', 'Unknown')}: {segment.get('purpose', 'N/A')} "
                               f"(Security: {segment.get('security_level', 'unknown')})\n")
                    f.write("\n")
                
                if 'threat_indicators' in topology:
                    f.write("Expected Threat Patterns:\n")
                    for indicator in topology['threat_indicators']:
                        f.write(f"  • {indicator.get('pattern', 'Unknown')}: {indicator.get('description', 'N/A')} "
                               f"(Severity: {indicator.get('severity', 'unknown')})\n")
                    f.write("\n")
            
            # PCAP Analysis Results
            f.write("📊 PCAP ANALYSIS RESULTS\n")
            f.write("-" * 30 + "\n")
            
            for i, result in enumerate(report['pcap_analysis']):
                filename = Path(result['file']).name
                f.write(f"\nFile {i+1}: {filename}\n")
                f.write("." * 25 + "\n")
                
                f.write(f"Total Packets: {result['stats']['total_packets']}\n")
                f.write(f"Unique IPs: {result['stats']['unique_ips']}\n")
                f.write(f"Protocols: {', '.join(result['stats']['protocols'].keys())}\n")
                
                # Process findings
                if result.get('findings'):
                    for finding in result['findings']:
                        finding_type = finding.get('type', 'unknown')
                        severity = finding.get('severity', 'low')
                        count = finding.get('count', 0)
                        
                        severity_emoji = "🔴" if severity == 'high' else "🟡" if severity == 'medium' else "🟢"
                        
                        if finding_type == 'port_scanning':
                            f.write(f"� {severity_emoji} Port Scans Detected: {count}\n")
                            if finding.get('data'):
                                data = finding.get('data') or []
                                for scan in data[:3]:
                                    f.write(f"   • {scan}\n")
                        
                        elif finding_type == 'suspicious_ports':
                            f.write(f"🚨 {severity_emoji} Suspicious Port Activity: {count} connections\n")
                            if finding.get('data'):
                                data = finding.get('data') or []
                                ports = [str(item.get('dst_port', 'unknown')) for item in data[:5]]
                                f.write(f"   • Ports: {', '.join(ports)}\n")
                        
                        elif finding_type == 'large_packets':
                            f.write(f"📦 {severity_emoji} Large Packets: {count}\n")
                        
                        else:
                            f.write(f"⚠️  {severity_emoji} {finding_type.title()}: {count}\n")
                            if finding.get('description'):
                                f.write(f"   • {finding['description']}\n")
                
                # Topology context findings
                if result.get('topology_context'):
                    f.write("\n🌐 Topology Context Analysis Available\n")
                
                f.write("\n")
            
            # Summary
            if 'summary' in report:
                f.write("📋 SUMMARY\n")
                f.write("-" * 20 + "\n")
                summary = report['summary']
                f.write(f"Total Threats Detected: {summary.get('total_threats', 0)}\n")
                f.write(f"High Severity Issues: {summary.get('high_severity', 0)}\n")
                f.write(f"Medium Severity Issues: {summary.get('medium_severity', 0)}\n")
                f.write(f"Context-Aware Findings: {summary.get('contextual_findings', 0)}\n")
    
    def _normalize_and_aggregate_findings(self, pcap_entries):
        """
        Normalize findings across all files, deduplicate similar findings,
        compute totals and severity breakdown. Returns (normalized_entries, summary).
        """
        from collections import defaultdict
        
        def finding_key(f):
            """Generate a key for deduplication based on type and core evidence"""
            ev = f.get("evidence", {})
            # Normalize finding types to a common format
            finding_type = f.get("type", "unknown")
            
            # Comprehensive type normalization
            type_mappings = {
                'rustml_port_scan': 'port_scanning',
                'rustml_port_scanning': 'port_scanning', 
                'port_scan': 'port_scanning',
                'rustml_suspicious_ports': 'suspicious_ports',
                'rustml_brute_force': 'brute_force_attempts',
                'brute_force_attempt': 'brute_force_attempts',
                'network_sweep': 'network_reconnaissance',
                'horizontal_scanning': 'network_reconnaissance',
                'service_enumeration': 'port_scanning'
            }
            
            # Apply normalization mapping
            normalized_type = type_mappings.get(finding_type, finding_type)
            
            # Create deduplication key
            key_parts = [
                normalized_type,
                ev.get("scanner_ip") or ev.get("source_ip") or ev.get("src_ip"),
                ev.get("target_ip") or ev.get("dst_ip"),
                str(ev.get("target_port") or ev.get("port") or "")
            ]
            return tuple(str(p) for p in key_parts)

        global_findings_map = {}
        severity_counts = defaultdict(int)
        total_threats = 0
        finding_sources = defaultdict(set)  # Track which detectors found each finding

        # Process all findings from all files
        for entry in pcap_entries:
            for finding in entry.get("findings", []):
                key = finding_key(finding)
                
                # Track detector sources
                detector_source = "rustml" if finding.get("type", "").startswith("rustml_") else "rule_based"
                finding_sources[key].add(detector_source)
                
                if key in global_findings_map:
                    # Merge with existing finding
                    existing = global_findings_map[key]
                    existing["count"] += finding.get("count", 1)
                    existing["confidence"] = max(existing.get("confidence", 0.5), finding.get("confidence", 0.5))
                    
                    # Merge evidence (keep most detailed)
                    if finding.get("evidence") and len(str(finding["evidence"])) > len(str(existing.get("evidence", {}))):
                        existing["evidence"] = finding["evidence"]
                    
                    # Merge sample data (limited size)
                    if finding.get("data"):
                        existing.setdefault("data", [])
                        data_to_extend = finding.get("data") or []
                        if isinstance(data_to_extend, list):
                            existing["data"].extend(data_to_extend[:3])
                            existing["data"] = existing["data"][:10]  # Cap at 10 samples
                else:
                    # Normalize finding type using the same mapping
                    normalized_type = finding.get("type", "unknown")
                    type_mappings = {
                        'rustml_port_scan': 'port_scanning',
                        'rustml_port_scanning': 'port_scanning', 
                        'port_scan': 'port_scanning',
                        'rustml_suspicious_ports': 'suspicious_ports',
                        'rustml_brute_force': 'brute_force_attempts',
                        'brute_force_attempt': 'brute_force_attempts',
                        'network_sweep': 'network_reconnaissance',
                        'horizontal_scanning': 'network_reconnaissance',
                        'service_enumeration': 'port_scanning'
                    }
                    normalized_type = type_mappings.get(normalized_type, normalized_type)
                    
                    # Create new normalized finding
                    # Safely process finding data - handle both list and dict cases
                    finding_data = finding.get("data")
                    if finding_data is not None and not isinstance(finding_data, list):
                        # Convert dict or other types to list format
                        if isinstance(finding_data, dict):
                            finding_data = [finding_data]  # Wrap dict in list
                        else:
                            finding_data = []  # Default to empty list for other types
                    
                    normalized_finding = {
                        "type": normalized_type,
                        "severity": finding.get("severity", "medium"),
                        "count": int(finding.get("count", 1)),
                        "description": finding.get("description", ""),
                        "evidence": finding.get("evidence", {}),
                        "data": (finding_data or [])[:10],
                        "confidence": float(finding.get("confidence", 0.75)),
                        "detector_sources": [detector_source]
                    }
                    global_findings_map[key] = normalized_finding

        # Update detector sources in findings
        for key, finding in global_findings_map.items():
            finding["detector_sources"] = list(finding_sources[key])
            if len(finding["detector_sources"]) > 1:
                finding["confidence"] = min(finding["confidence"] + 0.2, 1.0)  # Boost confidence for multi-detector findings

        # Calculate totals and severity breakdown
        normalized_findings = list(global_findings_map.values())
        for finding in normalized_findings:
            count = finding["count"]
            severity = finding["severity"].lower()
            
            total_threats += count
            severity_counts[severity] += count

        # Generate summary
        summary = {
            "total_threats": total_threats,
            "high_severity": severity_counts.get("high", 0),
            "medium_severity": severity_counts.get("medium", 0),
            "low_severity": severity_counts.get("low", 0),
            "unique_findings": len(normalized_findings),
            "contextual_findings": sum(1 for f in normalized_findings if len(f["detector_sources"]) > 1)
        }

        return normalized_findings, summary

    def _apply_topology_filtering(self, findings, network_context=None):
        """Apply topology-aware filtering to reduce false positives"""
        if not network_context:
            return findings
        
        filtered_findings = []
        expected_traffic = network_context.get("expected_traffic", [])
        
        for finding in findings:
            is_expected = False
            evidence = finding.get("evidence", {})
            
            # Check if this finding matches expected traffic patterns
            for expected in expected_traffic:
                if (evidence.get("src_ip") in expected.get("source_ips", []) and
                    evidence.get("dst_ip") in expected.get("destination_ips", []) and
                    evidence.get("port") in expected.get("ports", [])):
                    
                    # Lower severity for expected traffic
                    if finding["severity"] == "high":
                        finding["severity"] = "medium"
                        finding["description"] += " (expected traffic pattern)"
                    elif finding["severity"] == "medium":
                        finding["severity"] = "low"
                        finding["description"] += " (expected traffic pattern)"
                    else:
                        is_expected = True  # Skip low severity expected traffic
                    break
            
            if not is_expected:
                filtered_findings.append(finding)
        
        return filtered_findings

    def _apply_confidence_filtering(self, findings, min_confidence=0.6):
        """Filter findings based on confidence threshold"""
        return [f for f in findings if f.get("confidence", 0.75) >= min_confidence]

    def _apply_whitelist_filtering(self, findings):
        """Apply whitelist rules to reduce false positives"""
        # Define common legitimate traffic patterns that shouldn't be flagged
        legitimate_patterns = {
            # Common ports that are often legitimate
            'legitimate_ports': {
                53,    # DNS
                80,    # HTTP
                443,   # HTTPS
                8080,  # HTTP-Alt
                3389,  # RDP (within expected ranges)
                5060,  # SIP
                5061,  # SIP-TLS
            },
            # Multicast and broadcast ranges
            'multicast_ranges': [
                '224.0.0.0/8',     # IPv4 multicast
                '239.255.255.0/24', # SSDP
            ],
            # Common service discovery protocols
            'service_discovery_ports': {
                1900,  # SSDP/UPnP
                5353,  # mDNS
                137,   # NetBIOS Name Service
                138,   # NetBIOS Datagram
                139,   # NetBIOS Session
            }
        }
        
        filtered_findings = []
        
        for finding in findings:
            should_filter = False
            evidence = finding.get('evidence', {})
            finding_type = finding.get('type', '')
            
            # Check for legitimate service discovery traffic
            if finding_type in ['suspicious_ports', 'port_scanning']:
                target_port = evidence.get('target_port') or evidence.get('port')
                if target_port in legitimate_patterns['service_discovery_ports']:
                    # Lower severity instead of filtering completely
                    if finding['severity'] == 'high':
                        finding['severity'] = 'medium'
                        finding['description'] += ' (service discovery - reduced severity)'
                    elif finding['severity'] == 'medium':
                        finding['severity'] = 'low'
                        finding['description'] += ' (service discovery - reduced severity)'
                    else:
                        should_filter = True  # Skip low severity service discovery
            
            # Filter multicast/broadcast false positives
            dst_ip = evidence.get('target_ip') or evidence.get('dst_ip')
            if dst_ip:
                if dst_ip.startswith('224.') or dst_ip.startswith('239.255.255.'):
                    # Reduce severity for multicast traffic
                    if finding['count'] < 100:  # Only if not excessive
                        should_filter = True
            
            # Keep finding if it passes filters
            if not should_filter:
                filtered_findings.append(finding)
        
        return filtered_findings

    def _generate_summary(self, all_results):
        """Generate analysis summary"""
        total_threats = 0
        high_severity = 0
        medium_severity = 0
        contextual_findings = 0
        
        for result in all_results:
            # Count basic threats
            total_threats += len(result.get('port_scans', []))
            total_threats += len(result.get('suspicious_ports', []))
            total_threats += len(result.get('suspicious_ips', []))
            total_threats += len(result.get('anomalies', []))
            
            # Count contextual findings
            for finding in result.get('contextual_analysis', []):
                contextual_findings += finding.get('count', 0)
                if finding.get('severity') == 'high':
                    high_severity += finding.get('count', 0)
                elif finding.get('severity') == 'medium':
                    medium_severity += finding.get('count', 0)
        
        return {
            'total_threats': total_threats,
            'high_severity': high_severity,
            'medium_severity': medium_severity,
            'contextual_findings': contextual_findings
        }

    def _detect_advanced_threats(self, packets_data):
        """Detect advanced persistent threats and sophisticated attacks"""
        findings = []
        
        # 1. Detect lateral movement patterns
        lateral_findings = self._detect_lateral_movement(packets_data)
        findings.extend(lateral_findings)
        
        # 2. Detect data staging areas
        staging_findings = self._detect_data_staging(packets_data)
        findings.extend(staging_findings)
        
        # 3. Detect protocol anomalies
        protocol_findings = self._detect_protocol_anomalies(packets_data)
        findings.extend(protocol_findings)
        
        return findings
    
    def _detect_lateral_movement(self, packets_data):
        """Detect lateral movement within the network"""
        findings = []
        
        # Track internal-to-internal communications
        internal_comms = {}
        
        for packet in packets_data:
            src_ip = packet['src_ip']
            dst_ip = packet['dst_ip']
            dst_port = packet['dst_port']
            
            # Check if both IPs are internal
            is_src_internal = (src_ip.startswith('192.168.') or src_ip.startswith('10.') or 
                             any(src_ip.startswith(f'172.{i}.') for i in range(16, 32)))
            is_dst_internal = (dst_ip.startswith('192.168.') or dst_ip.startswith('10.') or 
                             any(dst_ip.startswith(f'172.{i}.') for i in range(16, 32)))
            
            if is_src_internal and is_dst_internal and src_ip != dst_ip:
                key = f"{src_ip}->{dst_ip}"
                if key not in internal_comms:
                    internal_comms[key] = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'ports': set(),
                        'packet_count': 0,
                        'admin_ports': set()
                    }
                
                internal_comms[key]['ports'].add(dst_port)
                internal_comms[key]['packet_count'] += 1
                
                # Track administrative ports
                admin_ports = {22, 23, 3389, 5985, 5986, 139, 445}  # SSH, Telnet, RDP, WinRM, SMB
                if dst_port in admin_ports:
                    internal_comms[key]['admin_ports'].add(dst_port)
        
        # Analyze for lateral movement patterns
        for comm_key, comm in internal_comms.items():
            # Host accessing many administrative services
            if len(comm['admin_ports']) >= 3:
                findings.append({
                    'type': 'lateral_movement_admin',
                    'severity': 'high',
                    'count': len(comm['admin_ports']),
                    'description': f"Host {comm['src_ip']} accessed multiple admin services on {comm['dst_ip']}",
                    'evidence': {
                        'src_ip': comm['src_ip'],
                        'dst_ip': comm['dst_ip'],
                        'admin_ports': list(comm['admin_ports']),
                        'total_ports': len(comm['ports'])
                    },
                    'data': []
                })
        
        return findings
    
    def _detect_data_staging(self, packets_data):
        """Detect data staging areas and suspicious file transfers"""
        findings = []
        
        # Track large internal file transfers
        file_transfer_ports = {21, 22, 139, 445, 2049, 111}  # FTP, SSH/SCP, SMB, NFS, RPC
        large_transfers = {}
        
        for packet in packets_data:
            if packet['dst_port'] in file_transfer_ports:
                src_ip = packet['src_ip']
                dst_ip = packet['dst_ip']
                packet_size = packet['packet_size']
                
                key = f"{src_ip}->{dst_ip}:{packet['dst_port']}"
                if key not in large_transfers:
                    large_transfers[key] = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'port': packet['dst_port'],
                        'total_bytes': 0,
                        'packet_count': 0
                    }
                
                large_transfers[key]['total_bytes'] += packet_size
                large_transfers[key]['packet_count'] += 1
        
        # Analyze for suspicious transfers
        for transfer_key, transfer in large_transfers.items():
            # Large file transfers that might indicate data staging
            if transfer['total_bytes'] > 50_000_000:  # > 50MB
                findings.append({
                    'type': 'large_file_transfer',
                    'severity': 'medium',
                    'count': 1,
                    'description': f"Large file transfer: {transfer['total_bytes']/1_000_000:.1f}MB via port {transfer['port']}",
                    'evidence': {
                        'src_ip': transfer['src_ip'],
                        'dst_ip': transfer['dst_ip'],
                        'port': transfer['port'],
                        'total_bytes': transfer['total_bytes'],
                        'packet_count': transfer['packet_count']
                    },
                    'data': []
                })
        
        return findings
    
    def _detect_protocol_anomalies(self, packets_data):
        """Detect protocol anomalies and misuse"""
        findings = []
        
        # Track protocol usage patterns
        protocol_stats = {}
        
        for packet in packets_data:
            protocol = packet['protocol']
            packet_size = packet['packet_size']
            
            # Track protocol statistics
            if protocol not in protocol_stats:
                protocol_stats[protocol] = {
                    'packet_count': 0,
                    'total_bytes': 0,
                    'avg_size': 0
                }
            
            protocol_stats[protocol]['packet_count'] += 1
            protocol_stats[protocol]['total_bytes'] += packet_size
        
        # Calculate averages and detect anomalies
        for protocol, stats in protocol_stats.items():
            if stats['packet_count'] > 0:
                stats['avg_size'] = stats['total_bytes'] / stats['packet_count']
                
                # Detect unusual protocol usage
                if protocol == 'UDP' and stats['avg_size'] > 5000:
                    findings.append({
                        'type': 'unusual_protocol_usage',
                        'severity': 'medium',
                        'count': stats['packet_count'],
                        'description': f"Unusually large UDP packets (avg: {stats['avg_size']:.0f} bytes)",
                        'evidence': {
                            'protocol': protocol,
                            'avg_packet_size': stats['avg_size'],
                            'packet_count': stats['packet_count'],
                            'total_bytes': stats['total_bytes']
                        },
                        'data': []
                    })
        
        return findings
    
    def _detect_dns_tunneling(self, packets_data):
        """Detect DNS tunneling attempts"""
        findings = []
        
        # Look for DNS traffic (port 53)
        dns_packets = [p for p in packets_data if p['dst_port'] == 53 or p['src_port'] == 53]
        
        if not dns_packets:
            return findings
        
        # Analyze DNS traffic patterns
        dns_stats = {
            'query_count': 0,
            'large_packets': 0,
            'frequent_queriers': {}
        }
        
        for packet in dns_packets:
            if packet['dst_port'] == 53:  # Query
                dns_stats['query_count'] += 1
                src_ip = packet['src_ip']
                if src_ip not in dns_stats['frequent_queriers']:
                    dns_stats['frequent_queriers'][src_ip] = 0
                dns_stats['frequent_queriers'][src_ip] += 1
            
            # Large DNS packets might indicate tunneling
            if packet['packet_size'] > 512:  # Normal DNS is usually < 512 bytes
                dns_stats['large_packets'] += 1
        
        # Detect potential DNS tunneling
        if dns_stats['large_packets'] > 10:
            findings.append({
                'type': 'dns_tunneling_large_packets',
                'severity': 'high',
                'count': dns_stats['large_packets'],
                'description': f"Detected {dns_stats['large_packets']} unusually large DNS packets (potential tunneling)",
                'evidence': {
                    'large_packet_count': dns_stats['large_packets'],
                    'total_dns_packets': len(dns_packets)
                },
                'data': []
            })
        
        return findings
    
    def _detect_covert_channels(self, packets_data):
        """Detect covert communication channels"""
        findings = []
        
        # 1. ICMP tunneling detection
        icmp_packets = [p for p in packets_data if p['protocol'] == 'ICMP']
        if len(icmp_packets) > 100:  # Unusual amount of ICMP
            findings.append({
                'type': 'icmp_tunneling_potential',
                'severity': 'medium',
                'count': len(icmp_packets),
                'description': f"Detected {len(icmp_packets)} ICMP packets (potential covert channel)",
                'evidence': {
                    'icmp_packet_count': len(icmp_packets),
                    'total_packets': len(packets_data),
                    'icmp_percentage': (len(icmp_packets) / len(packets_data)) * 100
                },
                'data': []
            })
        
        return findings

def main():
    """Main function for enhanced analysis"""
    if len(sys.argv) < 3:
        print("Usage: python enhanced_analyzer.py <topology_image> <pcap_file1> [pcap_file2] ...")
        print("Example: python enhanced_analyzer.py network_topology.png capture1.pcap capture2.pcap")
        return
    
    topology_image = sys.argv[1]
    pcap_files = sys.argv[2:]
    
    print("🦈 EntryShark Enhanced Analyzer")
    print("=" * 40)
    
    # Step 1: Analyze network topology with AI vision
    print(f"\n🖼️  Analyzing network topology: {Path(topology_image).name}")
    topology_analyzer = NetworkTopologyAnalyzer()
    network_context = topology_analyzer.analyze_network_topology(topology_image)
    
    # Step 2: Analyze PCAP files with context
    print(f"\n📊 Analyzing {len(pcap_files)} PCAP file(s) with topology context...")
    enhanced_analyzer = EnhancedPcapAnalyzer(network_context)
    
    # Generate output filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"enhanced_analysis_{timestamp}.json"
    
    # Run enhanced analysis
    results = enhanced_analyzer.analyze_with_context(pcap_files, output_file)
    
    print(f"\n✅ Analysis complete! Results saved to:")
    print(f"   📄 JSON: {output_file}")
    print(f"   📄 Text: {output_file.replace('.json', '.txt')}")

if __name__ == "__main__":
    main()
