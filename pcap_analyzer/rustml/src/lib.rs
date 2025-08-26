use pyo3::prelude::*;
use serde::Serialize;
use serde_json;
use std::collections::{HashMap, HashSet};
use pcap_parser::*;
use std::fs::File;
use std::io::Read;

#[derive(Serialize)]
struct PacketFeature {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    packet_size: usize,
    timestamp: f64,
}

#[derive(Serialize)]
struct PcapSummary {
    total_packets: usize,
    unique_src_ips: usize,
    unique_dst_ips: usize,
    top_ports: Vec<(u16, usize)>,
    packets: Vec<PacketFeature>,
}

#[pyfunction]
fn extract_pcap_features(path: &str, max_packets: usize) -> PyResult<String> {
    let mut packets = Vec::new();
    let mut src_ips = HashSet::new();
    let mut dst_ips = HashSet::new();
    let mut port_counts: HashMap<u16, usize> = HashMap::new();
    let mut total_packets = 0;

    let mut file = File::open(path).map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Failed to open pcap: {}", e)))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Failed to read pcap: {}", e)))?;

    let mut remaining = &buffer[..];
    let (rem, _header) = parse_pcap_header(remaining).map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Failed to parse pcap header: {:?}", e)))?;
    remaining = rem;

    while !remaining.is_empty() && total_packets < max_packets {
        match parse_pcap_frame(remaining) {
            Ok((rem, frame)) => {
                remaining = rem;
                let data = frame.data;
                let ts = frame.ts_sec as f64 + (frame.ts_usec as f64) / 1_000_000.0;
                
                // Minimal parsing: try to extract IP/port info (IPv4/TCP/UDP only)
                if data.len() < 34 { continue; }
                let ethertype = u16::from_be_bytes([data[12], data[13]]);
                if ethertype != 0x0800 { continue; } // IPv4 only
                let src_ip = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
                let dst_ip = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);
                src_ips.insert(src_ip.clone());
                dst_ips.insert(dst_ip.clone());
                let protocol = data[23];
                let (src_port, dst_port, proto_str) = match protocol {
                    6 if data.len() >= 38 => ( // TCP
                        u16::from_be_bytes([data[34], data[35]]),
                        u16::from_be_bytes([data[36], data[37]]),
                        "TCP".to_string()
                    ),
                    17 if data.len() >= 38 => ( // UDP
                        u16::from_be_bytes([data[34], data[35]]),
                        u16::from_be_bytes([data[36], data[37]]),
                        "UDP".to_string()
                    ),
                    _ => (0, 0, "Other".to_string()),
                };
                *port_counts.entry(dst_port).or_insert(0) += 1;
                packets.push(PacketFeature {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol: proto_str,
                    packet_size: data.len(),
                    timestamp: ts,
                });
                total_packets += 1;
            }
            Err(_) => break, // End of file or error
        }
    }
    
    // Top 10 ports
    let mut top_ports: Vec<(u16, usize)> = port_counts.into_iter().collect();
    top_ports.sort_by(|a, b| b.1.cmp(&a.1));
    top_ports.truncate(10);
    let summary = PcapSummary {
        total_packets,
        unique_src_ips: src_ips.len(),
        unique_dst_ips: dst_ips.len(),
        top_ports,
        packets,
    };
    Ok(serde_json::to_string(&summary).unwrap())
}

/// Analyze packet flows for anomaly detection
#[pyfunction]
fn analyze_packet_flows(packets: Vec<(String, String, u16, u16, String)>) -> PyResult<Vec<String>> {
    let mut anomalies = Vec::new();
    
    // Simple anomaly detection logic
    for (src_ip, dst_ip, src_port, dst_port, protocol) in packets {
        // Check for suspicious ports
        if dst_port == 22 || dst_port == 23 || dst_port == 3389 {
            anomalies.push(format!("Suspicious {} connection: {}:{} -> {}:{}", 
                protocol, src_ip, src_port, dst_ip, dst_port));
        }
        
        // Check for high port numbers (potential backdoors)
        if dst_port > 40000 {
            anomalies.push(format!("High port connection: {}:{} -> {}:{}", 
                src_ip, src_port, dst_ip, dst_port));
        }
    }
    
    Ok(anomalies)
}

/// Detect port scanning activities
#[pyfunction]
fn detect_port_scan(connections: Vec<(String, String, u16)>) -> PyResult<Vec<String>> {
    let mut scan_alerts = Vec::new();
    
    // Count connections per source IP
    let mut ip_connections = std::collections::HashMap::new();
    
    for (src_ip, dst_ip, dst_port) in connections {
        let entry = ip_connections.entry(src_ip.clone()).or_insert(Vec::new());
        entry.push((dst_ip, dst_port));
    }
    
    // Check for port scanning patterns
    for (src_ip, connections) in ip_connections {
        if connections.len() > 10 {
            let unique_ports: std::collections::HashSet<u16> = 
                connections.iter().map(|(_, port)| *port).collect();
            
            if unique_ports.len() > 5 {
                scan_alerts.push(format!("Port scan detected from {}: {} unique ports scanned", 
                    src_ip, unique_ports.len()));
            }
        }
    }
    
    Ok(scan_alerts)
}

/// Detect network anomalies
#[pyfunction]
fn detect_network_anomalies(traffic_data: Vec<(String, String, u32, String)>) -> PyResult<Vec<String>> {
    let mut anomalies = Vec::new();
    
    // Analyze traffic patterns
    let mut ip_traffic = std::collections::HashMap::new();
    
    for (src_ip, dst_ip, bytes, protocol) in traffic_data {
        let entry = ip_traffic.entry(src_ip.clone()).or_insert((0u32, Vec::new()));
        entry.0 += bytes;
        entry.1.push((dst_ip, protocol));
    }
    
    // Check for data exfiltration patterns
    for (src_ip, (total_bytes, connections)) in ip_traffic {
        if total_bytes > 100_000_000 { // More than 100MB
            anomalies.push(format!("Large data transfer from {}: {} bytes", src_ip, total_bytes));
        }
        
        if connections.len() > 50 {
            anomalies.push(format!("High connection count from {}: {} connections", src_ip, connections.len()));
        }
    }
    
    Ok(anomalies)
}

/// Check if a port is suspicious
#[pyfunction]
fn is_suspicious_port(port: u16) -> PyResult<bool> {
    let suspicious_ports = vec![
        22, 23, 135, 139, 445, 1433, 1521, 3389, 5432, 5900, 6379, 27017
    ];
    
    Ok(suspicious_ports.contains(&port) || port > 40000)
}

/// Check if an IP address is suspicious
#[pyfunction]
fn is_suspicious_ip(ip: String) -> PyResult<bool> {
    // Simple checks for obviously suspicious IPs
    let suspicious_patterns = vec![
        "0.0.0.0",
        "127.0.0.1", 
        "255.255.255.255",
        "169.254.", // Link-local addresses
        "224.", // Multicast
        "239.", // Multicast
    ];
    
    for pattern in suspicious_patterns {
        if ip.starts_with(pattern) {
            return Ok(true);
        }
    }
    
    Ok(false)
}

/// Python module definition
#[pymodule]
fn rustml(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(analyze_packet_flows, m)?)?;
    m.add_function(wrap_pyfunction!(detect_port_scan, m)?)?;
    m.add_function(wrap_pyfunction!(detect_network_anomalies, m)?)?;
    m.add_function(wrap_pyfunction!(is_suspicious_port, m)?)?;
    m.add_function(wrap_pyfunction!(is_suspicious_ip, m)?)?;
    m.add_function(wrap_pyfunction!(extract_pcap_features, m)?)?;
    Ok(())
}
