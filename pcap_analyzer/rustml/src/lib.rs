use pyo3::prelude::*;

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
    Ok(())
}
