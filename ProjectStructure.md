# Dynamic Tunnel Manager (DTM)

## 🚀 GitHub Repository

**Title:** Dynamic-Tunnel-Manager

**Description:**
A powerful Python-based security tool that provides automated, AI-driven management of dynamic SSL/TLS tunnels for network applications. Features real-time port rotation, intelligent traffic analysis, and advanced security monitoring.

**Summary:**
The Dynamic Tunnel Manager (DTM) revolutionizes application security by automatically creating and managing secure tunnels with dynamic port rotation. Leveraging GPT-4 for real-time security analysis, DTM provides intelligent traffic monitoring, automatic threat detection, and seamless tunnel management. Perfect for security professionals, developers, and system administrators who need robust, automated security for their network applications.

**Key Features:**
- 🔒 Automated SSL/TLS tunnel creation and management
- 🔄 Dynamic port rotation every 10 seconds
- 🤖 AI-driven security analysis using GPT-4
- 🔍 Real-time application discovery and monitoring
- 📊 Rich CLI interface with live updates
- 📝 JSON-structured logging for analysis
- 🛡️ Traffic isolation and security enforcement

**Tech Stack:**
- Python 3.9+
- OpenAI GPT-4 API
- Rich CLI Framework
- AsyncIO
- SSL/TLS Encryption
- JSON Logging

**Status:** Active Development

---

## Directory Structure
```
.
├── app/
│   ├── __init__.py              # Package initialization with version info
│   ├── ai_analysis.py           # AI-driven security analysis using GPT-4
│   ├── cli_ui.py               # Rich-based CLI user interface
│   ├── discovery.py            # Application discovery and monitoring
│   ├── logging_manager.py      # JSON-based logging configuration
│   ├── port_nuker.py          # Dynamic port management
│   └── tunnel_manager.py       # Secure tunnel management
├── config/
│   ├── certificates/           # SSL/TLS certificates directory
│   └── config.json            # Unified configuration file
├── logs/
│   └── dtm.json               # JSON-formatted application logs
├── tests/
│   ├── __init__.py            # Test package initialization
│   ├── test_ai_analysis.py    # AI analyzer tests
│   ├── test_discovery.py      # Application discovery tests
│   ├── test_port_nuker.py     # Port management tests
│   └── test_tunnel.py         # Tunnel management tests
├── venv/                      # Python virtual environment
├── main.py                    # Application entry point
├── requirements.txt           # Project dependencies
└── ProjectStructure.md        # This documentation file

## Core Features

### 1. Application Discovery
- Real-time monitoring of network-connected applications
- Process information tracking (PID, ports, connections)
- Automatic detection of new applications

### 2. Dynamic Port Management
- Automatic port assignment and rotation
- Configurable port range and rotation interval
- Port conflict resolution

### 3. Secure Tunneling
- SSL/TLS encrypted tunnels
- Dynamic tunnel creation and management
- Automatic tunnel cleanup for terminated applications

### 4. AI Security Analysis (GPT-4)
- Real-time application behavior analysis
- Security risk assessment
- Tunneling recommendations
- Structured JSON response format
- Configurable analysis parameters

### 5. Rich CLI Interface
- Real-time process monitoring
- Interactive controls:
  - Toggle auto-tunneling (T)
  - Toggle AI analysis (A)
  - Process analysis (P)
  - Force port rotation (R)
  - Quit (Q)
- Scrollable process list (↑/↓)
- AI analysis results display
- Color-coded status indicators
- PID input with visual feedback

### 6. Logging System
- JSON-structured logging
- Detailed error tracking
- Analysis history
- Performance metrics

## Configuration

### Main Configuration (config.json)
- OpenAI API settings
- Port range configuration
- Rotation intervals
- AI analysis parameters
- UI preferences
- Logging settings

## Recent Updates

### AI Analysis Improvements
- Upgraded to GPT-4 model
- Enhanced JSON response validation
- Improved error handling
- Better security analysis context

### UI Enhancements
- Added scrolling functionality
- Improved PID input feedback
- Enhanced AI analysis display
- Dynamic terminal size adaptation

### General Improvements
- Unified configuration structure
- Enhanced error handling
- Improved logging format
- Better shutdown handling

## Changelog

### [2024-01-07]
- Initial project structure created

### [2024-01-08]
- Added core modules and basic functionality
- Implemented testing framework

### [2024-01-09]
- Enhanced UI with Rich library
- Added AI analysis capabilities

### [2024-01-10]
- Upgraded to GPT-4 for analysis
- Improved UI responsiveness
- Added scrolling functionality
- Enhanced PID input system
- Unified configuration structure 