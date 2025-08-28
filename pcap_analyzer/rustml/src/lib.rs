use pyo3::prelude::*;
use serde::{Serialize, Deserialize};
use serde_json;
use std::collections::{HashMap, HashSet};
use pcap_parser::*;
use std::fs::File;
use std::io::Read;
use ndarray::Array2;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[pyclass]
struct PacketFeature {
    #[pyo3(get, set)]
    src_ip: String,
    #[pyo3(get, set)]
    dst_ip: String,
    #[pyo3(get, set)]
    src_port: u16,
    #[pyo3(get, set)]
    dst_port: u16,
    #[pyo3(get, set)]
    protocol: String,
    #[pyo3(get, set)]
    packet_size: usize,
    #[pyo3(get, set)]
    timestamp: f64,
}

#[pymethods]
impl PacketFeature {
    #[new]
    fn new() -> Self {
        PacketFeature {
            src_ip: String::new(),
            dst_ip: String::new(),
            src_port: 0,
            dst_port: 0,
            protocol: String::new(),
            packet_size: 0,
            timestamp: 0.0,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PcapSummary {
    total_packets: usize,
    unique_src_ips: usize,
    unique_dst_ips: usize,
    top_ports: Vec<(u16, usize)>,
    packets: Vec<PacketFeature>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AnomalyModel {
    normal_centroid: Vec<f64>,      // Centroid of normal traffic cluster
    normal_std: Vec<f64>,           // Standard deviation of normal traffic
    threshold_multiplier: f64,      // Multiplier for anomaly threshold
    feature_names: Vec<String>,     // Names of features used
    scaler_mean: Vec<f64>,          // Mean for feature scaling
    scaler_std: Vec<f64>,           // Std for feature scaling
}

impl Default for AnomalyModel {
    fn default() -> Self {
        Self {
            normal_centroid: Vec::new(),
            normal_std: Vec::new(),
            threshold_multiplier: 3.0, // 3-sigma rule
            feature_names: vec![
                "packet_size".to_string(),
                "src_port".to_string(),
                "dst_port".to_string(),
                "protocol_numeric".to_string(),
            ],
            scaler_mean: Vec::new(),
            scaler_std: Vec::new(),
        }
    }
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

/// Train anomaly detection model using clustering
#[pyfunction]
fn train_anomaly_model(packets: Vec<PacketFeature>, model_path: &str) -> PyResult<String> {
    if packets.len() < 10 {
        return Err(pyo3::exceptions::PyValueError::new_err("Not enough data for training"));
    }

    // Extract features for clustering
    let mut features = Vec::new();
    for packet in &packets {
        let protocol_numeric = match packet.protocol.as_str() {
            "TCP" => 1.0,
            "UDP" => 2.0,
            "ICMP" => 3.0,
            _ => 0.0,
        };

        features.push(vec![
            packet.packet_size as f64,
            packet.src_port as f64,
            packet.dst_port as f64,
            protocol_numeric,
        ]);
    }

    // Convert to ndarray
    let n_samples = features.len();
    let n_features = features[0].len();
    let mut feature_matrix = Array2::<f64>::zeros((n_samples, n_features));

    for (i, feature_vec) in features.iter().enumerate() {
        for (j, &value) in feature_vec.iter().enumerate() {
            feature_matrix[[i, j]] = value;
        }
    }

    // Standardize features manually for DBSCAN
    let mut scaled_features = feature_matrix.clone();
    for j in 0..n_features {
        let col_mean = feature_matrix.column(j).mean().unwrap();
        let col_std = feature_matrix.column(j).std(0.0);
        if col_std > 0.0 {
            for i in 0..n_samples {
                scaled_features[[i, j]] = (feature_matrix[[i, j]] - col_mean) / col_std;
            }
        }
    }

    // Use simple statistical clustering (distance-based)
    let mut distances = Vec::new();
    let centroid = calculate_centroid(&scaled_features);

    for i in 0..n_samples {
        let distance = euclidean_distance(&scaled_features.row(i), &centroid);
        distances.push((i, distance));
    }

    // Sort by distance and find natural clusters
    distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    // Use statistical method to find outliers (points beyond 2 standard deviations)
    let distance_values: Vec<f64> = distances.iter().map(|(_, d)| *d).collect();
    let mean_distance = distance_values.iter().sum::<f64>() / distance_values.len() as f64;
    let variance = distance_values.iter().map(|d| (d - mean_distance).powi(2)).sum::<f64>() / distance_values.len() as f64;
    let std_distance = variance.sqrt();

    // Points beyond 2 standard deviations are anomalies
    let threshold = mean_distance + 2.0 * std_distance;

    let mut cluster_labels = vec![-1i32; n_samples]; // -1 for noise/anomalies
    let mut cluster_id = 0;

    for (i, (original_idx, distance)) in distances.iter().enumerate() {
        if *distance <= threshold {
            cluster_labels[*original_idx] = cluster_id;
        }
        // Every 10th point starts a new cluster (simple clustering)
        if i > 0 && i % 10 == 0 && cluster_id < 5 {
            cluster_id += 1;
        }
    }

    // Find the largest cluster (assumed to be normal traffic)
    let mut cluster_counts = HashMap::new();
    for &label in cluster_labels.iter() {
        if label >= 0 {  // Ignore noise points (label = -1)
            *cluster_counts.entry(label).or_insert(0) += 1;
        }
    }

    if cluster_counts.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("No valid clusters found"));
    }

    let normal_cluster = cluster_counts.iter()
        .max_by_key(|&(_, count)| count)
        .map(|(&label, _)| label)
        .unwrap();

    // Calculate centroid and standard deviation of normal cluster
    let mut normal_features = Vec::new();
    for (i, &label) in cluster_labels.iter().enumerate() {
        if label == normal_cluster {
            let mut row = Vec::new();
            for j in 0..n_features {
                row.push(feature_matrix[[i, j]]);
            }
            normal_features.push(row);
        }
    }

    if normal_features.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("No normal traffic samples found"));
    }

    // Calculate centroid and std of normal cluster
    let mut centroid = vec![0.0; n_features];
    for feature_vec in &normal_features {
        for (j, &value) in feature_vec.iter().enumerate() {
            centroid[j] += value;
        }
    }
    for value in &mut centroid {
        *value /= normal_features.len() as f64;
    }

    let mut std_dev = vec![0.0; n_features];
    for feature_vec in &normal_features {
        for (j, &value) in feature_vec.iter().enumerate() {
            let diff = value - centroid[j];
            std_dev[j] += diff * diff;
        }
    }
    for value in &mut std_dev {
        *value = (*value / normal_features.len() as f64).sqrt();
    }

    // Standardize features manually
    let mut means = vec![0.0; n_features];
    let mut stds = vec![0.0; n_features];
    
    // Calculate means
    for feature_vec in &normal_features {
        for (j, &value) in feature_vec.iter().enumerate() {
            means[j] += value;
        }
    }
    for mean in &mut means {
        *mean /= normal_features.len() as f64;
    }
    
    // Calculate standard deviations
    for feature_vec in &normal_features {
        for (j, &value) in feature_vec.iter().enumerate() {
            let diff = value - means[j];
            stds[j] += diff * diff;
        }
    }
    for std in &mut stds {
        *std = (*std / normal_features.len() as f64).sqrt();
        if *std == 0.0 {
            *std = 1.0; // Avoid division by zero
        }
    }

    let model = AnomalyModel {
        normal_centroid: centroid,
        normal_std: std_dev,
        threshold_multiplier: 3.0,
        feature_names: vec![
            "packet_size".to_string(),
            "src_port".to_string(),
            "dst_port".to_string(),
            "protocol_numeric".to_string(),
        ],
        scaler_mean: means,
        scaler_std: stds,
    };

    // Save model to file
    let json = serde_json::to_string(&model)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize model: {}", e)))?;
    std::fs::write(model_path, json)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Failed to save model: {}", e)))?;

    Ok(format!("Model trained with {} normal samples from cluster {}", normal_features.len(), normal_cluster))
}

/// Detect anomalies using trained model
#[pyfunction]
fn detect_anomalies_with_model(packets: Vec<PacketFeature>, model_path: &str) -> PyResult<Vec<String>> {
    // Load model
    let model_json = std::fs::read_to_string(model_path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Failed to load model: {}", e)))?;
    let model: AnomalyModel = serde_json::from_str(&model_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Failed to deserialize model: {}", e)))?;

    let mut anomalies = Vec::new();

    for packet in packets {
        let protocol_numeric = match packet.protocol.as_str() {
            "TCP" => 1.0,
            "UDP" => 2.0,
            "ICMP" => 3.0,
            _ => 0.0,
        };

        let features = vec![
            packet.packet_size as f64,
            packet.src_port as f64,
            packet.dst_port as f64,
            protocol_numeric,
        ];

        // Standardize features using model's scaler parameters
        let mut scaled_features = vec![0.0; features.len()];
        for i in 0..features.len() {
            if i < model.scaler_std.len() && model.scaler_std[i] > 0.0 {
                scaled_features[i] = (features[i] - model.scaler_mean[i]) / model.scaler_std[i];
            } else {
                scaled_features[i] = features[i];
            }
        }

        // Calculate Mahalanobis distance to normal cluster centroid
        let mut distance = 0.0;
        for i in 0..features.len() {
            if i < model.normal_std.len() && model.normal_std[i] > 0.0 {
                let diff = features[i] - model.normal_centroid[i];
                distance += (diff / model.normal_std[i]).powi(2);
            }
        }
        distance = distance.sqrt();

        // Check if distance exceeds threshold
        if distance > model.threshold_multiplier {
            anomalies.push(format!(
                "Anomalous packet: {}:{} -> {}:{} (protocol: {}, size: {}, distance: {:.2})",
                packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port,
                packet.protocol, packet.packet_size, distance
            ));
        }
    }

    Ok(anomalies)
}

/// Train model and detect anomalies in one step
#[pyfunction]
fn train_and_detect_anomalies(packets: Vec<PacketFeature>, contamination_rate: f64) -> PyResult<Vec<String>> {
    if packets.len() < 10 {
        return Err(pyo3::exceptions::PyValueError::new_err("Not enough data for analysis"));
    }

    // Extract features
    let mut features = Vec::new();
    for packet in &packets {
        let protocol_numeric = match packet.protocol.as_str() {
            "TCP" => 1.0,
            "UDP" => 2.0,
            "ICMP" => 3.0,
            _ => 0.0,
        };

        features.push(vec![
            packet.packet_size as f64,
            packet.src_port as f64,
            packet.dst_port as f64,
            protocol_numeric,
        ]);
    }

    // Convert to ndarray
    let n_samples = features.len();
    let n_features = features[0].len();
    let mut feature_matrix = Array2::<f64>::zeros((n_samples, n_features));

    for (i, feature_vec) in features.iter().enumerate() {
        for (j, &value) in feature_vec.iter().enumerate() {
            feature_matrix[[i, j]] = value;
        }
    }

    // Standardize features manually for DBSCAN
    let mut scaled_features = feature_matrix.clone();
    for j in 0..n_features {
        let col_mean = feature_matrix.column(j).mean().unwrap();
        let col_std = feature_matrix.column(j).std(0.0);
        if col_std > 0.0 {
            for i in 0..n_samples {
                scaled_features[[i, j]] = (feature_matrix[[i, j]] - col_mean) / col_std;
            }
        }
    }

    // Use simple statistical clustering for anomaly detection
    let mut distances = Vec::new();
    let centroid = calculate_centroid(&scaled_features);

    for i in 0..n_samples {
        let distance = euclidean_distance(&scaled_features.row(i), &centroid);
        distances.push((i, distance));
    }

    // Sort by distance and find natural clusters
    distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    // Use statistical method to find outliers
    let distance_values: Vec<f64> = distances.iter().map(|(_, d)| *d).collect();
    let mean_distance = distance_values.iter().sum::<f64>() / distance_values.len() as f64;
    let variance = distance_values.iter().map(|d| (d - mean_distance).powi(2)).sum::<f64>() / distance_values.len() as f64;
    let std_distance = variance.sqrt();

    // Points beyond threshold are anomalies
    let threshold = mean_distance + contamination_rate * 3.0 * std_distance;

    let mut cluster_labels = vec![-1i32; n_samples]; // -1 for noise/anomalies
    let mut cluster_id = 0;

    for (i, (original_idx, distance)) in distances.iter().enumerate() {
        if *distance <= threshold {
            cluster_labels[*original_idx] = cluster_id;
        }
        // Every 10th point starts a new cluster (simple clustering)
        if i > 0 && i % 10 == 0 && cluster_id < 5 {
            cluster_id += 1;
        }
    }

    // Identify anomalies (noise points and small clusters)
    let mut cluster_counts = HashMap::new();
    for &label in cluster_labels.iter() {
        if label >= 0 {
            *cluster_counts.entry(label).or_insert(0) += 1;
        }
    }

    // Find small clusters (potential anomalies)
    let total_samples = packets.len();
    let min_cluster_size = (total_samples as f64 * (1.0 - contamination_rate)).floor() as usize;

    let mut normal_clusters = HashSet::new();
    for (&label, &count) in &cluster_counts {
        if count >= min_cluster_size {
            normal_clusters.insert(label);
        }
    }

    let mut anomalies = Vec::new();
    for (i, packet) in packets.iter().enumerate() {
        let label = cluster_labels[i];
        if label == -1 || !normal_clusters.contains(&label) {
            anomalies.push(format!(
                "Anomalous packet: {}:{} -> {}:{} (protocol: {}, size: {}, cluster: {})",
                packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port,
                packet.protocol, packet.packet_size, label
            ));
        }
    }

    Ok(anomalies)
}

/// Python module definition
#[pymodule]
fn rustml(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PacketFeature>()?;
    m.add_function(wrap_pyfunction!(analyze_packet_flows, m)?)?;
    m.add_function(wrap_pyfunction!(detect_port_scan, m)?)?;
    m.add_function(wrap_pyfunction!(detect_network_anomalies, m)?)?;
    m.add_function(wrap_pyfunction!(is_suspicious_port, m)?)?;
    m.add_function(wrap_pyfunction!(is_suspicious_ip, m)?)?;
    m.add_function(wrap_pyfunction!(extract_pcap_features, m)?)?;
    m.add_function(wrap_pyfunction!(train_anomaly_model, m)?)?;
    m.add_function(wrap_pyfunction!(detect_anomalies_with_model, m)?)?;
    m.add_function(wrap_pyfunction!(train_and_detect_anomalies, m)?)?;
    Ok(())
}

// Helper functions for statistical clustering
fn calculate_centroid(matrix: &Array2<f64>) -> Array2<f64> {
    let n_samples = matrix.nrows();
    let n_features = matrix.ncols();
    let mut centroid = Array2::<f64>::zeros((1, n_features));

    for j in 0..n_features {
        let mut sum = 0.0;
        for i in 0..n_samples {
            sum += matrix[[i, j]];
        }
        centroid[[0, j]] = sum / n_samples as f64;
    }

    centroid
}

fn euclidean_distance(a: &ndarray::ArrayView1<f64>, b: &Array2<f64>) -> f64 {
    let mut sum = 0.0;
    for i in 0..a.len() {
        let diff = a[i] - b[[0, i]];
        sum += diff * diff;
    }
    sum.sqrt()
}
