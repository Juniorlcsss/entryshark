# 🦈 EntryShark - AI-Powered Network Security Analysis Tool

An advanced AI-powered network traffic analyzer that combines PCAP file analysis with artificial intelligence to detect suspicious network activity. Features a desktop GUI, command-line interfaces, and advanced threat detection capabilities using Rust ML backend with AI vision integration.

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Git (for cloning the repository)
- Windows/Linux/macOS

### Installation & Setup

1. **Clone the repository:**

```bash
git clone https://github.com/Juniorlcsss/entryshark.git
cd entryshark
```

2. **Install Python dependencies:**

```bash
cd pcap_analyzer
pip install -r requirements.txt
```


### Running EntryShark

#### Option 1: Desktop GUI Application (Recommended)

```bash
cd pcap_analyzer
python entryshark_gui.py
```

#### Option 2: Command Line Analysis

```bash
cd pcap_analyzer
python enhanced_analyzer.py your_network_topology.png your_capture.pcap
```

#### Option 3: Simple Analysis (No AI Vision)

```bash
cd pcap_analyzer
python simple_analyzer.py your_capture.pcap
```

## 📋 Usage Instructions

### 1. Desktop GUI Application (Recommended)

- Launch the GUI application: `python entryshark_gui.py`
- Click "Select PCAP Files" to load your network capture files
- Optionally add a network topology image for enhanced AI analysis
- Click "Enhanced Analysis" for comprehensive threat detection
- View results in the generated reports (JSON, CSV, and readable text formats)

### 2. Command Line Analysis with AI Vision

For advanced analysis with network topology understanding:

- Prepare a network topology diagram (PNG, JPG, etc.)
- Run: `python enhanced_analyzer.py topology.png capture.pcap`
- Results will be saved with timestamp in the filename

### 3. Simple PCAP Analysis

For basic threat detection without AI enhancements:

- Run: `python simple_analyzer.py capture.pcap`
- View console output for immediate results

## 📊 Output Files

EntryShark generates multiple output formats:

- **JSON Report**: Detailed machine-readable analysis results
- **CSV Export**: Structured data for spreadsheet analysis
- **Text Report**: Human-readable executive summary with recommendations
- **Console Output**: Real-time analysis progress and summary

## 🛠️ Features

- **AI-Powered Analysis**: Uses Mistral Pixtral for network topology understanding
- **Advanced Threat Detection**: Detects port scans, lateral movement, data exfiltration, and more
- **RustML Backend**: High-performance machine learning threat detection
- **False Positive Reduction**: Intelligent filtering and confidence scoring
- **Professional Reporting**: Executive summaries with actionable insights
- **Multi-Format Output**: JSON, CSV, and readable text reports

## 📋 Requirements

- Python 3.8+
- Network capture files (PCAP format)
- Optional: Network topology diagrams for enhanced analysis
- Optional: Mistral API key for AI vision features (set in `.env` file)

## 🔧 Troubleshooting

**Issue**: Missing dependencies
**Solution**: Run `pip install -r pcap_analyzer/requirements.txt`

**Issue**: GUI doesn't start
**Solution**: Ensure tkinter is installed: `pip install tkinter`

**Issue**: PCAP files not loading
**Solution**: Verify files are valid PCAP format and not corrupted
