#!/usr/bin/env python3
"""
EntryShark Enhanced Analyzer with Scapy (No Wireshark dependency)
Analyzes network topology images and PCAP files using pure Python libraries
"""

import base64
import json
import os
from datetime import datetime
from pathlib import Path
import sys

# Try scapy first, fallback if not available
try:
    from scapy.all import rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available. Install with: py -3 -m pip install scapy")

class SimpleNetworkAnalyzer:
    def __init__(self):
        self.packets_data = []
        
    def extract_features_from_pcap_scapy(self, pcap_file):
        """Extract features using Scapy instead of pyshark"""
        if not SCAPY_AVAILABLE:
            print("❌ Scapy not available for PCAP parsing")
            return False
            
        try:
            print(f"📁 Reading PCAP with Scapy: {Path(pcap_file).name}")
            packets = rdpcap(str(pcap_file))
            
            self.packets_data = []
            packet_count = 0
            
            for pkt in packets:
                try:
                    # Extract IP information
                    if IP in pkt:
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        packet_size = len(pkt)
                        
                        # Extract port information
                        src_port = 0
                        dst_port = 0
                        protocol = "Other"
                        flags = []
                        
                        if TCP in pkt:
                            src_port = pkt[TCP].sport
                            dst_port = pkt[TCP].dport
                            protocol = "TCP"
                            
                            # Extract TCP flags
                            tcp_flags = pkt[TCP].flags
                            if tcp_flags & 0x02: flags.append("SYN")
                            if tcp_flags & 0x10: flags.append("ACK")
                            if tcp_flags & 0x01: flags.append("FIN")
                            if tcp_flags & 0x04: flags.append("RST")
                            if tcp_flags & 0x08: flags.append("PSH")
                            if tcp_flags & 0x20: flags.append("URG")
                            
                        elif UDP in pkt:
                            src_port = pkt[UDP].sport
                            dst_port = pkt[UDP].dport
                            protocol = "UDP"
                        
                        # Create packet data
                        packet_data = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': protocol,
                            'packet_size': packet_size,
                            'flags': flags,
                            'timestamp': float(pkt.time) if hasattr(pkt, 'time') else 0.0
                        }
                        
                        self.packets_data.append(packet_data)
                        packet_count += 1
                        
                        if packet_count % 1000 == 0:
                            print(f"   Processed {packet_count} packets...")
                            
                except Exception as e:
                    # Skip problematic packets
                    continue
            
            print(f"✅ Extracted features from {len(self.packets_data)} packets")
            return True
            
        except Exception as e:
            print(f"❌ Error reading PCAP file with Scapy: {e}")
            return False

def analyze_network_topology_simple(image_path):
    """Simple topology analysis without AI vision"""
    print(f"🖼️  Analyzing network topology: {Path(image_path).name}")
    
    filename = Path(image_path).name.lower()
    
    # Basic inference from filename
    if "business" in filename:
        network_type = "business"
        security_level = "high"
    elif "engineering" in filename or "dev" in filename:
        network_type = "engineering" 
        security_level = "medium"
    else:
        network_type = "general"
        security_level = "medium"
    
    # Create network context
    network_context = {
        "network_segments": [
            {
                "name": f"{network_type}_internal",
                "purpose": f"{network_type} operations",
                "ip_range": "192.168.0.0/16",
                "security_level": security_level
            },
            {
                "name": "external",
                "purpose": "internet",
                "ip_range": "0.0.0.0/0",
                "security_level": "low"
            }
        ],
        "expected_traffic": [
            {"source": "internal", "destination": "external", "protocol": "HTTP/HTTPS", "port": "80/443", "purpose": "web_browsing"},
            {"source": "internal", "destination": "internal", "protocol": "SMB", "port": "445", "purpose": "file_sharing"},
            {"source": "external", "destination": "internal", "protocol": "RDP", "port": "3389", "purpose": "remote_access"}
        ],
        "threat_indicators": [
            {"pattern": "port_scan", "severity": "high", "description": "Multiple port connection attempts"},
            {"pattern": "data_exfiltration", "severity": "high", "description": "Large outbound data transfers"},
            {"pattern": "lateral_movement", "severity": "medium", "description": "Internal reconnaissance"},
            {"pattern": "suspicious_ports", "severity": "medium", "description": "Connections to uncommon ports"}
        ],
        "analysis_method": "filename_inference"
    }
    
    print(f"✅ Topology analysis complete (method: {network_context['analysis_method']})")
    return network_context

def analyze_packets_with_context(packets_data, network_context):
    """Analyze packets with network context"""
    findings = []
    
    # Basic statistics
    total_packets = len(packets_data)
    protocols = {}
    ports = {}
    ips = set()
    
    # Traffic analysis
    port_connections = {}  # src_ip -> set of dst_ports
    large_packets = []
    suspicious_ports = []
    
    for packet in packets_data:
        # Count protocols
        proto = packet['protocol']
        protocols[proto] = protocols.get(proto, 0) + 1
        
        # Count ports
        dst_port = packet['dst_port']
        if dst_port > 0:
            ports[dst_port] = ports.get(dst_port, 0) + 1
        
        # Track IPs
        ips.add(packet['src_ip'])
        ips.add(packet['dst_ip'])
        
        # Port scan detection
        src_ip = packet['src_ip']
        if src_ip not in port_connections:
            port_connections[src_ip] = set()
        if dst_port > 0:
            port_connections[src_ip].add(dst_port)
        
        # Large packet detection
        if packet['packet_size'] > 1500:
            large_packets.append(packet)
        
        # Suspicious port detection
        if dst_port in [1234, 12345, 54321, 6667, 31337] or dst_port > 50000:
            suspicious_ports.append(packet)
    
    # Generate findings
    findings.append({
        'type': 'traffic_summary',
        'data': {
            'total_packets': total_packets,
            'unique_protocols': len(protocols),
            'unique_ports': len(ports),
            'unique_ips': len(ips),
            'top_protocols': sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:5],
            'top_ports': sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]
        }
    })
    
    # Port scan findings
    potential_scanners = []
    for src_ip, dst_ports in port_connections.items():
        if len(dst_ports) >= 5:  # Threshold for port scanning
            potential_scanners.append({
                'ip': src_ip,
                'ports_scanned': len(dst_ports),
                'ports': sorted(list(dst_ports))[:10]  # Show first 10 ports
            })
    
    if potential_scanners:
        findings.append({
            'type': 'port_scanning',
            'severity': 'high',
            'count': len(potential_scanners),
            'data': potential_scanners
        })
    
    # Large packet findings
    if large_packets:
        findings.append({
            'type': 'large_packets',
            'severity': 'medium',
            'count': len(large_packets),
            'data': large_packets[:5]  # Show first 5
        })
    
    # Suspicious port findings
    if suspicious_ports:
        findings.append({
            'type': 'suspicious_ports',
            'severity': 'high',
            'count': len(suspicious_ports),
            'data': suspicious_ports[:5]  # Show first 5
        })
    
    return findings

def save_analysis_report(topology_context, pcap_results, output_file):
    """Save analysis report to file"""
    # Create output directory path
    output_dir = Path(__file__).parent.parent / "analysis outputs"
    output_dir.mkdir(exist_ok=True)
    
    # Create full paths for output files
    json_path = output_dir / output_file
    text_path = output_dir / output_file.replace('.json', '.txt')
    
    report = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'analyzer': 'EntryShark Simple Analyzer v1.0',
            'files_analyzed': len(pcap_results)
        },
        'network_topology': topology_context,
        'pcap_analysis': pcap_results
    }
    
    # Save JSON report
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    # Save text report
    with open(text_path, 'w', encoding='utf-8') as f:
        f.write("EntryShark Analysis Report\n")
        f.write("=" * 30 + "\n\n")
        
        # Metadata
        f.write(f"Analysis Time: {report['metadata']['timestamp']}\n")
        f.write(f"Files Analyzed: {report['metadata']['files_analyzed']}\n\n")
        
        # Network topology
        f.write("Network Topology Analysis:\n")
        f.write("-" * 25 + "\n")
        topology = report['network_topology']
        
        f.write("Network Segments:\n")
        for segment in topology.get('network_segments', []):
            f.write(f"  - {segment['name']}: {segment['purpose']} (Security: {segment['security_level']})\n")
        
        f.write("\nThreat Indicators:\n")
        for indicator in topology.get('threat_indicators', []):
            f.write(f"  - {indicator['pattern']}: {indicator['description']} (Severity: {indicator['severity']})\n")
        
        # PCAP analysis
        f.write("\n\nPCAP Analysis Results:\n")
        f.write("-" * 25 + "\n")
        
        for result in pcap_results:
            filename = Path(result['file']).name
            f.write(f"\nFile: {filename}\n")
            
            if 'error' in result:
                f.write(f"  Error: {result['error']}\n")
                continue
            
            for finding in result.get('findings', []):
                if finding['type'] == 'traffic_summary':
                    data = finding['data']
                    f.write(f"  Total Packets: {data['total_packets']:,}\n")
                    f.write(f"  Unique IPs: {data['unique_ips']}\n")
                    f.write(f"  Protocols: {dict(data['top_protocols'])}\n")
                    f.write(f"  Top Ports: {dict(data['top_ports'])}\n")
                
                elif finding['type'] == 'port_scanning':
                    f.write(f"  PORT SCANNING DETECTED ({finding['count']} sources):\n")
                    for scanner in finding['data']:
                        f.write(f"    - {scanner['ip']}: scanned {scanner['ports_scanned']} ports\n")
                
                elif finding['type'] == 'suspicious_ports':
                    f.write(f"  SUSPICIOUS PORTS ({finding['count']} connections):\n")
                    for conn in finding['data']:
                        f.write(f"    - {conn['src_ip']} -> {conn['dst_ip']}:{conn['dst_port']}\n")
                
                elif finding['type'] == 'large_packets':
                    f.write(f"  LARGE PACKETS ({finding['count']} packets > 1500 bytes):\n")
                    for pkt in finding['data']:
                        f.write(f"    - {pkt['src_ip']} -> {pkt['dst_ip']}: {pkt['packet_size']} bytes\n")
    
    print(f"JSON report saved to: {json_path}")
    print(f"Text report saved to: {text_path}")

def main():
    """Main function"""
    if len(sys.argv) < 3:
        print("Usage: py -3 simple_analyzer.py <topology_image> <pcap_file1> [pcap_file2] ...")
        print("Example: py -3 simple_analyzer.py network.png capture1.pcap capture2.pcap")
        return
    
    topology_image = sys.argv[1]
    pcap_files = sys.argv[2:]
    
    print("EntryShark Simple Analyzer")
    print("=" * 30)
    
    # Step 1: Analyze network topology
    network_context = analyze_network_topology_simple(topology_image)
    
    # Step 2: Analyze PCAP files
    print(f"\nAnalyzing {len(pcap_files)} PCAP file(s)...")
    
    analyzer = SimpleNetworkAnalyzer()
    pcap_results = []
    
    for pcap_file in pcap_files:
        print(f"\nProcessing: {Path(pcap_file).name}")
        result = {'file': pcap_file}
        
        if analyzer.extract_features_from_pcap_scapy(pcap_file):
            findings = analyze_packets_with_context(analyzer.packets_data, network_context)
            result['findings'] = findings
        else:
            result['error'] = 'Failed to extract features'
        
        pcap_results.append(result)
    
    # Step 3: Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"simple_analysis_{timestamp}.json"
    
    save_analysis_report(network_context, pcap_results, output_file)
    
    print(f"\nAnalysis complete!")
    
    # Summary
    total_packets = 0
    total_findings = 0
    
    for result in pcap_results:
        if 'findings' in result:
            for finding in result['findings']:
                if finding['type'] == 'traffic_summary':
                    total_packets += finding['data']['total_packets']
                else:
                    total_findings += finding.get('count', 1)
    
    print(f"Summary: {total_packets:,} packets analyzed, {total_findings} security findings")

if __name__ == "__main__":
    main()
