#!/usr/bin/env python3
"""
EntryShark GUI - Desktop Application for PCAP Analysis
Drag and drop interface for analyzing network traffic
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD
import threading
import queue
import os
import json
from datetime import datetime
from pathlib import Path
import sys

# Import our working analyzer components
try:
    from scapy.all import rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available. Install with: py -3 -m pip install scapy")

# Import Rust ML functions
try:
    from rustml import analyze_packet_flows, detect_port_scan, detect_network_anomalies
    from rustml import is_suspicious_port, is_suspicious_ip
    RUSTML_AVAILABLE = True
except ImportError:
    RUSTML_AVAILABLE = False
    print("⚠️  RustML not available. Build with: py -3 -m maturin build --release")

# Import Enhanced Analyzer for topology-aware analysis
try:
    from enhanced_analyzer import EnhancedPcapAnalyzer, NetworkTopologyAnalyzer
    ENHANCED_ANALYZER_AVAILABLE = True
except ImportError:
    ENHANCED_ANALYZER_AVAILABLE = False
    print("⚠️  Enhanced Analyzer not available.")

class EntrySharkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🦈 EntryShark - PCAP Analyzer")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Queue for thread communication
        self.result_queue = queue.Queue()
        
        # Current analyzer instance
        self.analyzer = None
        self.analysis_thread = None
        
        self.setup_ui()
        self.setup_drag_drop()
        
        # Start checking for results
        self.check_results()
    
    def setup_ui(self):
        """Set up the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="🦈 EntryShark PCAP Analyzer", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # File selection area
        file_frame = ttk.LabelFrame(main_frame, text="PCAP File Selection", padding="10")
        file_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)
        
        # Drag and drop area
        self.drop_label = ttk.Label(file_frame, 
                                   text="📁 Drag and drop PCAP files here or click Browse",
                                   font=("Arial", 12),
                                   foreground="blue",
                                   background="lightgray",
                                   relief="solid",
                                   borderwidth=2,
                                   padding="20")
        self.drop_label.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Browse button
        self.browse_button = ttk.Button(file_frame, text="Browse Files", 
                                       command=self.browse_files)
        self.browse_button.grid(row=1, column=0, sticky=tk.W)
        
        # Selected files list
        self.files_var = tk.StringVar(value="No files selected")
        files_label = ttk.Label(file_frame, textvariable=self.files_var)
        files_label.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0))
        
        # Network topology section
        topology_frame = ttk.LabelFrame(main_frame, text="Network Topology Analysis (Optional)", padding="10")
        topology_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        topology_frame.columnconfigure(1, weight=1)
        
        # Topology info
        topology_info = ttk.Label(topology_frame, 
                                 text="🤖 Upload network diagram for AI-enhanced contextual analysis",
                                 font=("Arial", 10),
                                 foreground="darkblue")
        topology_info.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 5))
        
        # Topology browse button
        self.topology_button = ttk.Button(topology_frame, text="📸 Select Network Diagram", 
                                         command=self.browse_topology)
        self.topology_button.grid(row=1, column=0, sticky=tk.W)
        
        # Topology file display
        self.topology_var = tk.StringVar(value="No network diagram selected")
        topology_label = ttk.Label(topology_frame, textvariable=self.topology_var)
        topology_label.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0))
        
        # Store selected topology file
        self.topology_file = None
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        self.analyze_button = ttk.Button(button_frame, text="🔍 Analyze PCAP", 
                                        command=self.start_analysis, state="disabled")
        self.analyze_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, text="🗑️ Clear Results", 
                                      command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.save_button = ttk.Button(button_frame, text="💾 Save Report", 
                                     command=self.save_report, state="disabled")
        self.save_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Progress bar
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.grid(row=3, column=0, columnspan=3, pady=(5, 0), sticky=(tk.W, tk.E))
        self.progress_frame.grid_remove()  # Hidden by default
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.progress_label = ttk.Label(self.progress_frame, text="")
        self.progress_label.pack()
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding="5")
        results_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Results text area with scrollbar
        self.results_text = scrolledtext.ScrolledText(results_frame, 
                                                     wrap=tk.WORD, 
                                                     font=("Consolas", 10),
                                                     state=tk.DISABLED)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready - Drop PCAP files to analyze")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, font=("Arial", 9))
        status_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Store selected files
        self.selected_files = []
        
    def setup_drag_drop(self):
        """Set up drag and drop functionality"""
        self.drop_label.drop_target_register(DND_FILES)
        self.drop_label.dnd_bind('<<Drop>>', self.on_drop)
        
        # Make the label clickable for browsing
        self.drop_label.bind("<Button-1>", lambda e: self.browse_files())
        
    def on_drop(self, event):
        """Handle dropped files"""
        files = self.root.tk.splitlist(event.data)
        pcap_files = [f for f in files if f.lower().endswith(('.pcap', '.pcapng', '.cap'))]
        
        if pcap_files:
            self.selected_files = pcap_files
            self.update_file_display()
            self.analyze_button.config(state="normal")
            self.status_var.set(f"Ready to analyze {len(pcap_files)} file(s)")
        else:
            messagebox.showwarning("Invalid Files", 
                                 "Please drop PCAP files (.pcap, .pcapng, .cap)")
    
    def browse_files(self):
        """Browse for PCAP files"""
        files = filedialog.askopenfilenames(
            title="Select PCAP Files",
            filetypes=[
                ("PCAP files", "*.pcap *.pcapng *.cap"),
                ("All files", "*.*")
            ]
        )
        
        if files:
            self.selected_files = list(files)
            self.update_file_display()
            self.analyze_button.config(state="normal")
            self.status_var.set(f"Ready to analyze {len(files)} file(s)")
    
    def browse_topology(self):
        """Browse for network topology image"""
        file = filedialog.askopenfilename(
            title="Select Network Topology Image",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg *.jpeg"),
                ("All files", "*.*")
            ]
        )
        
        if file:
            self.topology_file = file
            filename = os.path.basename(file)
            if len(filename) > 50:
                display_name = filename[:47] + "..."
            else:
                display_name = filename
            self.topology_var.set(f"📸 Selected: {display_name}")
            self.status_var.set("Network topology image selected - Enhanced AI analysis enabled")
    
    def update_file_display(self):
        """Update the display of selected files"""
        if self.selected_files:
            if len(self.selected_files) == 1:
                filename = os.path.basename(self.selected_files[0])
                self.files_var.set(f"Selected: {filename}")
            else:
                self.files_var.set(f"Selected: {len(self.selected_files)} files")
        else:
            self.files_var.set("No files selected")
    
    def start_analysis(self):
        """Start analysis in a separate thread"""
        if not self.selected_files:
            messagebox.showwarning("No Files", "Please select PCAP files to analyze")
            return
        
        # Disable buttons during analysis
        self.analyze_button.config(state="disabled")
        self.save_button.config(state="disabled")
        
        # Show progress bar
        self.progress_frame.grid()
        self.progress_bar.start()
        self.progress_label.config(text="Initializing analysis...")
        
        # Clear previous results
        self.clear_results()
        
        # Start analysis thread
        self.analysis_thread = threading.Thread(target=self.analyze_files, daemon=True)
        self.analysis_thread.start()
        
        self.status_var.set("Analysis in progress...")
    
    def analyze_files(self):
        """Analyze PCAP files using Scapy (runs in separate thread)"""
        try:
            if not SCAPY_AVAILABLE:
                self.result_queue.put(("error", "Scapy not available. Install with: py -3 -m pip install scapy"))
                return
            
            # Initialize results variable
            all_results = []
            
            # Check if we should use enhanced analysis with topology
            use_enhanced_analysis = (self.topology_file and 
                                   ENHANCED_ANALYZER_AVAILABLE and 
                                   os.path.exists(self.topology_file))
            
            if use_enhanced_analysis:
                self.result_queue.put(("progress", "🤖 Initializing AI-Enhanced Analysis..."))
                try:
                    # Step 1: Analyze network topology
                    self.result_queue.put(("progress", f"📸 Analyzing network topology: {os.path.basename(self.topology_file)}"))
                    topology_analyzer = NetworkTopologyAnalyzer()
                    network_context = topology_analyzer.analyze_network_topology(self.topology_file)
                    
                    # Step 2: Analyze PCAP files with context
                    self.result_queue.put(("progress", "🔍 Running enhanced PCAP analysis with topology context..."))
                    enhanced_analyzer = EnhancedPcapAnalyzer(network_context)
                    results = enhanced_analyzer.analyze_with_context(self.selected_files)
                    
                    # Save enhanced results
                    self.result_queue.put(("progress", "💾 Saving enhanced analysis results..."))
                    enhanced_analyzer._save_enhanced_report(results, None)  # Will auto-generate filename
                    
                    # Format results for GUI display
                    self.result_queue.put(("enhanced_results", results))
                    
                    # Set all_results for the final complete message
                    all_results = results
                    
                except Exception as e:
                    self.result_queue.put(("error", f"Enhanced analysis failed: {str(e)}. Falling back to standard analysis."))
                    use_enhanced_analysis = False
            
            if not use_enhanced_analysis:
                # Standard analysis without topology
                all_results = []
                
                for i, pcap_file in enumerate(self.selected_files):
                    # Update progress
                    progress_msg = f"Analyzing {os.path.basename(pcap_file)} ({i+1}/{len(self.selected_files)})"
                    self.result_queue.put(("progress", progress_msg))
                    
                    # Extract features using Scapy
                    self.result_queue.put(("progress", f"Reading packets from {os.path.basename(pcap_file)}..."))
                    packets_data = self.extract_features_with_scapy(pcap_file)
                    
                    if not packets_data:
                        self.result_queue.put(("error", f"Failed to analyze {pcap_file}"))
                        continue
                    
                    # Run analysis
                    self.result_queue.put(("progress", f"Running security analysis on {os.path.basename(pcap_file)}..."))
                    
                    # Capture analysis results
                    results = self.analyze_packets_with_context(packets_data, pcap_file)
                    all_results.append(results)
                
                # Save results to analysis outputs folder
                self.result_queue.put(("progress", "Saving analysis results..."))
                self.save_gui_results(all_results)
                
                # Send final results
                self.result_queue.put(("results", all_results))
            self.result_queue.put(("complete", all_results))
            
        except Exception as e:
            self.result_queue.put(("error", f"Analysis failed: {str(e)}"))
    
    def extract_features_with_scapy(self, pcap_file):
        """Extract features from PCAP using Scapy"""
        try:
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
                        
                        # Update progress every 1000 packets
                        if len(packets_data) % 1000 == 0:
                            self.result_queue.put(("progress", f"Processed {len(packets_data)} packets..."))
                            
                except Exception as e:
                    continue  # Skip malformed packets
            
            return packets_data
            
        except Exception as e:
            self.result_queue.put(("error", f"Error reading PCAP: {str(e)}"))
            return []
    
    def analyze_packets_with_context(self, packets_data, pcap_file):
        """Analyze packets for security findings"""
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
        
        # Security analysis
        if RUSTML_AVAILABLE:
            try:
                # Port scan detection
                port_scans = detect_port_scan(packets_data)
                if port_scans:
                    findings.append({
                        'type': 'port_scanning',
                        'severity': 'high',
                        'count': len(port_scans),
                        'data': port_scans[:10]  # Limit display
                    })
                
                # Large packet detection
                large_packets = [p for p in packets_data if p['packet_size'] > 1500]
                if large_packets:
                    findings.append({
                        'type': 'large_packets',
                        'severity': 'medium',
                        'count': len(large_packets),
                        'data': large_packets[:10]  # Limit display
                    })
                
                # Suspicious port detection
                suspicious_conns = []
                for packet in packets_data:
                    if is_suspicious_port(packet['dst_port']):
                        suspicious_conns.append(packet)
                
                if suspicious_conns:
                    findings.append({
                        'type': 'suspicious_ports',
                        'severity': 'medium',
                        'count': len(suspicious_conns),
                        'data': suspicious_conns[:10]  # Limit display
                    })
                        
            except Exception as e:
                findings.append({
                    'type': 'analysis_error',
                    'severity': 'low',
                    'count': 1,
                    'data': [{'error': str(e)}]
                })
        
        return {
            'file': pcap_file,
            'timestamp': datetime.now().isoformat(),
            'stats': stats,
            'findings': findings
        }
    
    def save_gui_results(self, all_results):
        """Save GUI analysis results to output folder"""
        try:
            # Create output directory
            output_dir = Path(__file__).parent.parent / "analysis outputs"
            output_dir.mkdir(exist_ok=True)
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = output_dir / f"gui_analysis_{timestamp}.json"
            text_path = output_dir / f"gui_analysis_{timestamp}.txt"
            
            # Create report
            report = {
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'analyzer': 'EntryShark GUI v1.0',
                    'files_analyzed': len(all_results)
                },
                'analysis_results': all_results
            }
            
            # Save JSON
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            # Save text summary
            with open(text_path, 'w', encoding='utf-8') as f:
                f.write("EntryShark GUI Analysis Report\n")
                f.write("=" * 35 + "\n\n")
                f.write(f"Analysis Time: {report['metadata']['timestamp']}\n")
                f.write(f"Files Analyzed: {len(all_results)}\n\n")
                
                for result in all_results:
                    f.write(f"File: {os.path.basename(result['file'])}\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"Total Packets: {result['stats']['total_packets']}\n")
                    f.write(f"Unique IPs: {result['stats']['unique_ips']}\n")
                    f.write(f"Protocols: {result['stats']['protocols']}\n")
                    f.write(f"Top Ports: {result['stats']['top_ports']}\n")
                    
                    if result['findings']:
                        f.write("\nSecurity Findings:\n")
                        for finding in result['findings']:
                            f.write(f"  - {finding['type'].upper()}: {finding['count']} instances ({finding['severity']} severity)\n")
                    
                    f.write("\n")
            
            self.result_queue.put(("progress", f"Results saved to {json_path.name}"))
            
        except Exception as e:
            self.result_queue.put(("error", f"Failed to save results: {str(e)}"))
    
    def check_results(self):
        """Check for results from analysis thread"""
        try:
            while True:
                msg_type, data = self.result_queue.get_nowait()
                
                if msg_type == "progress":
                    self.progress_label.config(text=data)
                
                elif msg_type == "error":
                    self.progress_bar.stop()
                    self.progress_frame.grid_remove()
                    self.analyze_button.config(state="normal")
                    self.status_var.set("Analysis failed")
                    self.append_result(f"❌ Error: {data}\n")
                    messagebox.showerror("Analysis Error", data)
                
                elif msg_type == "complete":
                    self.progress_bar.stop()
                    self.progress_frame.grid_remove()
                    self.analyze_button.config(state="normal")
                    self.save_button.config(state="normal")
                    self.status_var.set("Analysis complete")
                    
                    # Display results
                    self.display_results(data)
                
                elif msg_type == "enhanced_results":
                    self.progress_bar.stop()
                    self.progress_frame.grid_remove()
                    self.analyze_button.config(state="normal")
                    self.save_button.config(state="normal")
                    self.status_var.set("🤖 AI-Enhanced Analysis complete")
                    
                    # Display enhanced results
                    self.display_enhanced_results(data)
                
                elif msg_type == "results":
                    self.result_queue.put(("complete", data))
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.check_results)
    
    def display_results(self, all_results):
        """Display analysis results in the GUI"""
        self.clear_results()
        
        total_packets = 0
        total_findings = 0
        
        self.append_result("🦈 ENTRYSHARK ANALYSIS RESULTS\n")
        self.append_result("="*60 + "\n\n")
        
        for i, results in enumerate(all_results):
            filename = os.path.basename(results['file'])
            stats = results.get('stats', {})
            findings = results.get('findings', [])
            
            # Update totals
            total_packets += stats.get('total_packets', 0)
            total_findings += sum(f.get('count', 0) for f in findings)
            
            self.append_result(f"📄 File: {filename}\n")
            self.append_result(f"⏰ Analyzed: {results['timestamp']}\n")
            self.append_result("-" * 40 + "\n")
            
            # Basic Statistics
            self.append_result("📊 STATISTICS:\n")
            self.append_result(f"   Total Packets: {stats.get('total_packets', 0):,}\n")
            self.append_result(f"   Unique IPs: {stats.get('unique_ips', 0)}\n")
            self.append_result(f"   Protocols: {stats.get('protocols', {})}\n")
            
            top_ports = stats.get('top_ports', {})
            if top_ports:
                self.append_result(f"   Top Ports: {dict(list(top_ports.items())[:5])}\n")
            self.append_result("\n")
            
            # Security Findings
            self.append_result("🔍 SECURITY FINDINGS:\n")
            if findings:
                for finding in findings:
                    severity_icon = "🔴" if finding['severity'] == 'high' else "🟡" if finding['severity'] == 'medium' else "🟢"
                    self.append_result(f"   {severity_icon} {finding['type'].upper()}: {finding['count']} instances\n")
                    
                    # Show sample data for some finding types
                    if finding['type'] == 'port_scanning' and 'data' in finding:
                        for scanner in finding['data'][:3]:  # Show first 3
                            self.append_result(f"      • {scanner}\n")
                    elif finding['type'] == 'suspicious_ports' and 'data' in finding:
                        for conn in finding['data'][:3]:  # Show first 3
                            self.append_result(f"      • {conn.get('src_ip', 'N/A')} -> {conn.get('dst_ip', 'N/A')}:{conn.get('dst_port', 'N/A')}\n")
                    elif finding['type'] == 'large_packets' and 'data' in finding:
                        for pkt in finding['data'][:3]:  # Show first 3
                            self.append_result(f"      • {pkt.get('src_ip', 'N/A')} -> {pkt.get('dst_ip', 'N/A')}: {pkt.get('packet_size', 0)} bytes\n")
                self.append_result("\n")
            else:
                self.append_result("   ✅ No security issues detected\n\n")
            
            if i < len(all_results) - 1:  # Not last item
                self.append_result("\n" + "="*60 + "\n\n")
        
        # Summary
        self.append_result("📋 SUMMARY\n")
        self.append_result("="*20 + "\n")
        self.append_result(f"Files Analyzed: {len(all_results)}\n")
        self.append_result(f"Total Packets: {total_packets:,}\n")
        self.append_result(f"Security Findings: {total_findings}\n")
        
        if total_findings > 0:
            self.append_result("\n⚠️  Review security findings above for potential threats.\n")
        else:
            self.append_result("\n✅ No security issues detected across all files.\n")
        
        # Store results for saving
        self.current_results = all_results
    
    def display_enhanced_results(self, all_results):
        """Display enhanced analysis results with topology context"""
        self.clear_results()
        
        total_packets = 0
        total_findings = 0
        
        self.append_result("🦈 ENTRYSHARK AI-ENHANCED ANALYSIS RESULTS\n")
        self.append_result("="*60 + "\n\n")
        
        if self.topology_file:
            self.append_result(f"🤖 AI Topology Analysis: {os.path.basename(self.topology_file)}\n")
            self.append_result("🌐 Network context applied to security analysis\n\n")
        
        for i, results in enumerate(all_results):
            filename = os.path.basename(results['file'])
            stats = results.get('stats', {})
            findings = results.get('findings', [])
            
            # Update totals
            total_packets += stats.get('total_packets', 0)
            total_findings += sum(f.get('count', 0) for f in findings)
            
            self.append_result(f"📄 File: {filename}\n")
            self.append_result(f"⏰ Analyzed: {results['timestamp']}\n")
            self.append_result("-" * 40 + "\n")
            
            # Basic Statistics
            self.append_result("📊 STATISTICS:\n")
            self.append_result(f"   Total Packets: {stats.get('total_packets', 0):,}\n")
            self.append_result(f"   Unique IPs: {stats.get('unique_ips', 0)}\n")
            self.append_result(f"   Protocols: {stats.get('protocols', {})}\n")
            
            top_ports = stats.get('top_ports', {})
            if top_ports:
                self.append_result(f"   Top Ports: {dict(list(top_ports.items())[:5])}\n")
            self.append_result("\n")
            
            # Enhanced Security Findings
            self.append_result("🔍 AI-ENHANCED SECURITY FINDINGS:\n")
            if findings:
                for finding in findings:
                    severity_icon = "🔴" if finding['severity'] == 'high' else "🟡" if finding['severity'] == 'medium' else "🟢"
                    self.append_result(f"   {severity_icon} {finding['type'].upper()}: {finding['count']} instances")
                    
                    # Add context note if available
                    if finding.get('context_note'):
                        self.append_result(f" ({finding['context_note']})")
                    self.append_result("\n")
                    
                    # Show sample data for findings
                    if 'data' in finding:
                        if finding['type'] == 'port_scanning':
                            for scanner in finding['data'][:3]:
                                self.append_result(f"      • {scanner}\n")
                        elif finding['type'] == 'suspicious_ports':
                            ports = [str(item.get('dst_port', 'unknown')) for item in finding['data'][:5]]
                            self.append_result(f"      • Ports: {', '.join(ports)}\n")
                
                self.append_result("\n")
            else:
                self.append_result("   ✅ No security issues detected\n\n")
            
            # Topology Context
            if results.get('topology_context'):
                self.append_result("🌐 NETWORK TOPOLOGY CONTEXT:\n")
                topology = results['topology_context']
                
                if 'network_segments' in topology:
                    segments = topology['network_segments'][:3]  # Show first 3
                    for segment in segments:
                        self.append_result(f"   • {segment.get('name', 'Unknown')}: {segment.get('purpose', 'N/A')}\n")
                
                if 'threat_indicators' in topology:
                    indicators = topology['threat_indicators'][:3]  # Show first 3
                    for indicator in indicators:
                        self.append_result(f"   ⚠️  {indicator.get('pattern', 'Unknown')}: {indicator.get('description', 'N/A')}\n")
                
                self.append_result("\n")
            
            if i < len(all_results) - 1:  # Not last item
                self.append_result("\n" + "="*60 + "\n\n")
        
        # Enhanced Summary
        self.append_result("📋 AI-ENHANCED SUMMARY\n")
        self.append_result("="*30 + "\n")
        self.append_result(f"Files Analyzed: {len(all_results)}\n")
        self.append_result(f"Total Packets: {total_packets:,}\n")
        self.append_result(f"Security Findings: {total_findings}\n")
        self.append_result(f"AI Context: {'Enabled' if self.topology_file else 'Disabled'}\n")
        
        if total_findings > 0:
            self.append_result("\n⚠️  Review AI-enhanced security findings above for contextual threats.\n")
        else:
            self.append_result("\n✅ No security issues detected with AI analysis.\n")
        
        self.append_result("\n💡 Enhanced analysis complete! Check 'analysis outputs' folder for detailed reports.\n")
        
        # Store results for saving
        self.current_results = all_results
    
    def append_result(self, text):
        """Append text to results area"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, text)
        self.results_text.config(state=tk.DISABLED)
        self.results_text.see(tk.END)
    
    def clear_results(self):
        """Clear the results area"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.current_results = None
    
    def save_report(self):
        """Save analysis report to file"""
        if not hasattr(self, 'current_results') or not self.current_results:
            messagebox.showwarning("No Results", "No analysis results to save")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save Analysis Report",
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                if filename.lower().endswith('.json'):
                    # Save as JSON
                    with open(filename, 'w') as f:
                        json.dump(self.current_results, f, indent=2)
                else:
                    # Save as text
                    text_content = self.results_text.get(1.0, tk.END)
                    with open(filename, 'w') as f:
                        f.write(text_content)
                
                messagebox.showinfo("Report Saved", f"Analysis report saved to:\n{filename}")
                self.status_var.set(f"Report saved to {os.path.basename(filename)}")
                
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save report:\n{str(e)}")

def main():
    """Main application entry point"""
    try:
        # Try to import the Rust module
        import rustml
    except ImportError:
        error_msg = """
EntryShark Error: Rust ML backend not found!

Please build the Rust backend first:
1. cd rustml
2. maturin develop --release

Or run the setup script:
python setup.py
"""
        print(error_msg)
        messagebox.showerror("Missing Backend", error_msg)
        return
    
    # Create the main window
    root = TkinterDnD.Tk()
    app = EntrySharkApp(root)
    
    # Set window icon (optional)
    try:
        root.iconbitmap("shark.ico")  # You can add a shark icon if available
    except:
        pass
    
    # Run the application
    root.mainloop()

if __name__ == "__main__":
    main()
