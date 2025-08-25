use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;

#[derive(Debug, Clone)]
#[pyclass]
pub struct PacketFeatures {
    #[pyo3(get, set)]
    pub src_ip: String,
    #[pyo3(get, set)]
    pub dst_ip: String,
    #[pyo3(get, set)]
    pub src_port: u16,
    #[pyo3(get, set)]
    pub dst_port: u16,
    #[pyo3(get, set)]
    pub protocol: String,
    #[pyo3(get, set)]
    pub packet_size: u32,
    #[pyo3(get, set)]
    pub flags: Vec<String>,
    #[pyo3(get, set)]
    pub timestamp: f64,
}

#[pymethods]
impl PacketFeatures {
    #[new]
    fn new(
        src_ip: String,
        dst_ip: String,
        src_port: u16,
        dst_port: u16,
        protocol: String,
        packet_size: u32,
        flags: Vec<String>,
        timestamp: f64,
    ) -> Self {
        PacketFeatures {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            packet_size,
            flags,
            timestamp,
        }
    }
}

#[derive(Debug, Clone)]
#[pyclass]
pub struct SuspiciousActivity {
    #[pyo3(get, set)]
    pub activity_type: String,
    #[pyo3(get, set)]
    pub severity: f32,
    #[pyo3(get, set)]
    pub description: String,
    #[pyo3(get, set)]
    pub evidence: Vec<String>,
    #[pyo3(get, set)]
    pub timestamp: f64,
}

#[pymethods]
impl SuspiciousActivity {
    #[new]
    fn new(
        activity_type: String,
        severity: f32,
        description: String,
        evidence: Vec<String>,
        timestamp: f64,
    ) -> Self {
        SuspiciousActivity {
            activity_type,
            severity,
            description,
            evidence,
            timestamp,
        }
    }
}

/// Anomaly Detection Engine
pub struct AnomalyDetector {
    port_baseline: HashMap<u16, u32>,
    ip_baseline: HashMap<String, u32>,
    protocol_baseline: HashMap<String, u32>,
    packet_size_stats: Vec<f64>,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        AnomalyDetector {
            port_baseline: HashMap::new(),
            ip_baseline: HashMap::new(),
            protocol_baseline: HashMap::new(),
            packet_size_stats: Vec::new(),
        }
    }

    pub fn train(&mut self, packets: &[PacketFeatures]) {
        // Build baseline from training data
        for packet in packets {
            *self.port_baseline.entry(packet.dst_port).or_insert(0) += 1;
            *self.ip_baseline.entry(packet.dst_ip.clone()).or_insert(0) += 1;
            *self.protocol_baseline.entry(packet.protocol.clone()).or_insert(0) += 1;
            self.packet_size_stats.push(packet.packet_size as f64);
        }
    }

    pub fn detect_anomalies(&self, packets: &[PacketFeatures]) -> Vec<SuspiciousActivity> {
        let mut suspicious_activities = Vec::new();

        for packet in packets {
            // Port scan detection
            if self.is_port_scan(packet) {
                suspicious_activities.push(SuspiciousActivity::new(
                    "Port Scan".to_string(),
                    0.8,
                    format!("Unusual port access: {}", packet.dst_port),
                    vec![format!("{}:{} -> {}:{}", packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)],
                    packet.timestamp,
                ));
            }

            // DDoS detection (simplified)
            if self.is_ddos_pattern(packet) {
                suspicious_activities.push(SuspiciousActivity::new(
                    "DDoS".to_string(),
                    0.9,
                    "Potential DDoS traffic pattern detected".to_string(),
                    vec![format!("High frequency traffic from {}", packet.src_ip)],
                    packet.timestamp,
                ));
            }

            // Unusual protocol detection
            if self.is_unusual_protocol(packet) {
                suspicious_activities.push(SuspiciousActivity::new(
                    "Unusual Protocol".to_string(),
                    0.6,
                    format!("Uncommon protocol usage: {}", packet.protocol),
                    vec![format!("Protocol {} from {}", packet.protocol, packet.src_ip)],
                    packet.timestamp,
                ));
            }

            // Data exfiltration detection (large packet sizes)
            if self.is_data_exfiltration(packet) {
                suspicious_activities.push(SuspiciousActivity::new(
                    "Data Exfiltration".to_string(),
                    0.7,
                    "Unusually large packet size detected".to_string(),
                    vec![format!("Large packet ({} bytes) to {}", packet.packet_size, packet.dst_ip)],
                    packet.timestamp,
                ));
            }

            // Malformed packet detection
            if self.is_malformed_packet(packet) {
                suspicious_activities.push(SuspiciousActivity::new(
                    "Malformed Packet".to_string(),
                    0.8,
                    "Potentially malformed packet detected".to_string(),
                    vec![format!("Suspicious flags: {:?}", packet.flags)],
                    packet.timestamp,
                ));
            }
        }

        suspicious_activities
    }

    fn is_port_scan(&self, packet: &PacketFeatures) -> bool {
        // Flag ports that are rarely used in baseline
        match self.port_baseline.get(&packet.dst_port) {
            Some(count) => *count < 2, // Rare ports
            None => packet.dst_port > 1024 && packet.dst_port != 8080 && packet.dst_port != 3389
        }
    }

    fn is_ddos_pattern(&self, packet: &PacketFeatures) -> bool {
        // Simplified: flag high-frequency IPs (in real implementation, track over time window)
        match self.ip_baseline.get(&packet.src_ip) {
            Some(count) => *count > 100, // High frequency IP
            None => false,
        }
    }

    fn is_unusual_protocol(&self, packet: &PacketFeatures) -> bool {
        // Flag rare protocols
        match self.protocol_baseline.get(&packet.protocol) {
            Some(count) => *count < 5,
            None => !["TCP", "UDP", "ICMP", "HTTP", "HTTPS"].contains(&packet.protocol.as_str()),
        }
    }

    fn is_data_exfiltration(&self, packet: &PacketFeatures) -> bool {
        // Flag unusually large packets
        if self.packet_size_stats.is_empty() {
            return packet.packet_size > 1500; // Standard MTU
        }

        let mean = self.packet_size_stats.iter().sum::<f64>() / self.packet_size_stats.len() as f64;
        let variance = self.packet_size_stats.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / self.packet_size_stats.len() as f64;
        let std_dev = variance.sqrt();

        (packet.packet_size as f64) > mean + 2.0 * std_dev
    }

    fn is_malformed_packet(&self, packet: &PacketFeatures) -> bool {
        // Check for suspicious flag combinations
        packet.flags.contains(&"URG".to_string()) && packet.flags.contains(&"PSH".to_string()) ||
        packet.flags.len() > 5 || // Too many flags
        (packet.protocol == "TCP" && packet.flags.is_empty()) // TCP without flags
    }
}

/// Advanced ML-based anomaly detection using simple statistical methods
#[pyfunction]
fn detect_network_anomalies(packets_data: &PyList) -> PyResult<Vec<SuspiciousActivity>> {
    let mut packets = Vec::new();
    
    // Parse Python data into Rust structs
    for item in packets_data {
        let dict = item.downcast::<PyDict>()?;
        let packet = PacketFeatures::new(
            dict.get_item("src_ip")?.unwrap().extract::<String>()?,
            dict.get_item("dst_ip")?.unwrap().extract::<String>()?,
            dict.get_item("src_port")?.unwrap().extract::<u16>()?,
            dict.get_item("dst_port")?.unwrap().extract::<u16>()?,
            dict.get_item("protocol")?.unwrap().extract::<String>()?,
            dict.get_item("packet_size")?.unwrap().extract::<u32>()?,
            dict.get_item("flags")?.unwrap().extract::<Vec<String>>()?,
            dict.get_item("timestamp")?.unwrap().extract::<f64>()?,
        );
        packets.push(packet);
    }

    // Create and train anomaly detector
    let mut detector = AnomalyDetector::new();
    
    // Use first half for training, second half for detection
    let split_point = packets.len() / 2;
    if split_point > 0 {
        detector.train(&packets[..split_point]);
        Ok(detector.detect_anomalies(&packets[split_point..]))
    } else {
        // If too few packets, use simple heuristics
        Ok(detector.detect_anomalies(&packets))
    }
}

/// Simple statistical analysis of packet flows
#[pyfunction]
fn analyze_packet_flows(packets_data: &PyList) -> PyResult<HashMap<String, f64>> {
    let mut flow_stats = HashMap::new();
    let mut total_packets = 0;
    let mut total_bytes = 0;
    let mut protocols = HashMap::new();
    let mut ports = HashMap::new();

    for item in packets_data {
        let dict = item.downcast::<PyDict>()?;
        let protocol = dict.get_item("protocol")?.unwrap().extract::<String>()?;
        let packet_size = dict.get_item("packet_size")?.unwrap().extract::<u32>()?;
        let dst_port = dict.get_item("dst_port")?.unwrap().extract::<u16>()?;

        total_packets += 1;
        total_bytes += packet_size;
        *protocols.entry(protocol).or_insert(0) += 1;
        *ports.entry(dst_port).or_insert(0) += 1;
    }

    flow_stats.insert("total_packets".to_string(), total_packets as f64);
    flow_stats.insert("total_bytes".to_string(), total_bytes as f64);
    flow_stats.insert("avg_packet_size".to_string(), 
                     if total_packets > 0 { total_bytes as f64 / total_packets as f64 } else { 0.0 });
    flow_stats.insert("unique_protocols".to_string(), protocols.len() as f64);
    flow_stats.insert("unique_ports".to_string(), ports.len() as f64);

    Ok(flow_stats)
}

/// Returns True if the port is considered suspicious (enhanced logic)
#[pyfunction]
fn is_suspicious_port(port: u16) -> bool {
    // Well-known suspicious ports or unusual high ports
    matches!(port,
        // Common attack ports
        1433 | 1434 | 3389 | 5900 | 5901 | 6667 | 6697 | 1234 | 12345 | 54321
    ) || 
    // Or very high ports that might indicate backdoors
    port > 50000 ||
    // Ports in suspicious ranges
    (port > 1024 && port < 5000 && ![3389, 8080, 8443, 3000].contains(&port))
}

/// Check for suspicious IP patterns
#[pyfunction]
fn is_suspicious_ip(ip: &str) -> bool {
    // Check for private IPs communicating on unusual ports, or known bad patterns
    ip.starts_with("169.254") || // Link-local
    ip.starts_with("224.") || // Multicast
    ip.starts_with("240.") || // Reserved
    ip == "0.0.0.0" || ip == "255.255.255.255"
}

/// Detect potential port scanning behavior with detailed source information
#[pyfunction]
fn detect_port_scan(packets_data: &PyList, threshold: u16) -> PyResult<Vec<PyObject>> {
    let py = packets_data.py();
    let mut ip_port_targets: HashMap<String, (std::collections::HashSet<u16>, std::collections::HashSet<String>)> = HashMap::new();
    let mut results = Vec::new();

    for item in packets_data {
        let dict = item.downcast::<PyDict>()?;
        let src_ip = dict.get_item("src_ip")?.unwrap().extract::<String>()?;
        let dst_ip = dict.get_item("dst_ip")?.unwrap().extract::<String>()?;
        let dst_port = dict.get_item("dst_port")?.unwrap().extract::<u16>()?;

        let entry = ip_port_targets.entry(src_ip.clone()).or_insert_with(|| {
            (std::collections::HashSet::new(), std::collections::HashSet::new())
        });
        entry.0.insert(dst_port);
        entry.1.insert(dst_ip);
    }

    for (src_ip, (ports, targets)) in ip_port_targets {
        if ports.len() >= threshold as usize {
            let result_dict = PyDict::new(py);
            result_dict.set_item("source", src_ip.clone())?;
            result_dict.set_item("ports_scanned", ports.len())?;
            result_dict.set_item("targets_count", targets.len())?;
            result_dict.set_item("ports_list", ports.iter().cloned().collect::<Vec<u16>>())?;
            result_dict.set_item("targets_list", targets.iter().cloned().collect::<Vec<String>>())?;
            result_dict.set_item("scan_intensity", ports.len() as f64 / targets.len() as f64)?;
            
            results.push(result_dict.into());
        }
    }

    Ok(results)
}

/// Detect network reconnaissance/sweeps with detailed source information
#[pyfunction]
fn detect_network_sweep(packets_data: &PyList, min_targets: u16) -> PyResult<Vec<PyObject>> {
    let py = packets_data.py();
    let mut ip_targets: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    let mut results = Vec::new();

    for item in packets_data {
        let dict = item.downcast::<PyDict>()?;
        let src_ip = dict.get_item("src_ip")?.unwrap().extract::<String>()?;
        let dst_ip = dict.get_item("dst_ip")?.unwrap().extract::<String>()?;

        ip_targets.entry(src_ip.clone())
            .or_insert_with(std::collections::HashSet::new)
            .insert(dst_ip);
    }

    for (src_ip, targets) in ip_targets {
        if targets.len() >= min_targets as usize {
            let result_dict = PyDict::new(py);
            result_dict.set_item("scanner", src_ip.clone())?;
            result_dict.set_item("targets_count", targets.len())?;
            result_dict.set_item("targets_list", targets.iter().cloned().collect::<Vec<String>>())?;
            
            // Determine network range being scanned
            let network_ranges = analyze_network_ranges(&targets);
            result_dict.set_item("network_ranges", network_ranges)?;
            
            results.push(result_dict.into());
        }
    }

    Ok(results)
}

/// Analyze network ranges from target IPs
fn analyze_network_ranges(targets: &std::collections::HashSet<String>) -> Vec<String> {
    let mut ranges = std::collections::HashMap::new();
    
    for target in targets {
        let parts: Vec<&str> = target.split('.').collect();
        if parts.len() == 4 {
            // Group by /24 network
            let network = format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]);
            *ranges.entry(network).or_insert(0) += 1;
        }
    }
    
    ranges.into_iter()
        .filter(|(_, count)| *count >= 3) // At least 3 IPs in same network
        .map(|(network, _)| network)
        .collect()
}

#[pymodule]
fn rustml(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(is_suspicious_port, m)?)?;
    m.add_function(wrap_pyfunction!(is_suspicious_ip, m)?)?;
    m.add_function(wrap_pyfunction!(detect_port_scan, m)?)?;
    m.add_function(wrap_pyfunction!(detect_network_sweep, m)?)?;
    m.add_function(wrap_pyfunction!(detect_network_anomalies, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_packet_flows, m)?)?;
    m.add_class::<PacketFeatures>()?;
    m.add_class::<SuspiciousActivity>()?;
    Ok(())
}
