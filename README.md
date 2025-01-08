# Dynamic Tunnel Manager (DTM)

A secure and automated system for managing dynamic, encrypted tunnels for network applications with AI-driven optimization.

## Features

- **Application Discovery**: Automatically detect and monitor network-enabled applications
- **Secure Tunnels**: SSL/TLS encrypted tunnels for secure communication
- **Dynamic Port Nuking**: Automatic port rotation every 10 seconds
- **AI Analysis**: Real-time traffic analysis and security recommendations
- **Traffic Isolation**: Secure encapsulation of application traffic

## Requirements

- Python 3.9+
- OpenAI API key (for AI analysis features)
- Required Python packages (see `requirements.txt`)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/dynamic-tunnel-manager.git
cd dynamic-tunnel-manager
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure OpenAI API:
Create `config/ai_config.json` with your OpenAI API key:
```json
{
    "api_key": "your-api-key-here"
}
```

## Usage

1. Start the Dynamic Tunnel Manager:
```bash
python main.py
```

2. The system will automatically:
   - Discover network-enabled applications
   - Create secure tunnels
   - Rotate ports every 10 seconds
   - Provide AI-driven analysis and recommendations

## Architecture

### Core Components

1. **Application Discovery** (`app/discovery.py`)
   - Detects running applications
   - Monitors network connections
   - Tracks application metadata

2. **Tunnel Manager** (`app/tunnel_manager.py`)
   - Creates and manages SSL/TLS tunnels
   - Handles secure connections
   - Manages certificates

3. **Port Nuker** (`app/port_nuker.py`)
   - Manages dynamic port assignment
   - Implements port rotation
   - Ensures seamless transitions

4. **AI Analysis** (`app/ai_analysis.py`)
   - Analyzes traffic patterns
   - Provides security recommendations
   - Optimizes performance

### Security Features

- SSL/TLS encryption for all tunnels
- Dynamic port rotation
- Traffic isolation
- AI-driven security analysis
- Self-signed certificate generation

## Configuration

### Port Range

Default port range for tunnel assignments is 5000-6000. Modify in `port_nuker.py`:
```python
port_range = (5000, 6000)
```

### Rotation Interval

Default port rotation interval is 10 seconds. Adjust in `port_nuker.py`:
```python
rotation_interval = 10
```

### SSL/TLS Certificates

Certificates are automatically generated in `config/certificates/`:
- `cert.pem`: SSL certificate
- `key.pem`: Private key

## Development

### Running Tests

```bash
pytest tests/
```

### Adding New Features

1. Create feature branch:
```bash
git checkout -b feature/your-feature-name
```

2. Implement changes
3. Add tests
4. Submit pull request

## Logging

Logs are stored in the `logs` directory:
- Application logs: `logs/dtm.log`
- Rich console output for real-time monitoring

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create pull request

## License

MIT License - see LICENSE file for details

## Support

For support, please:
1. Check documentation
2. Search existing issues
3. Create new issue if needed

## Authors

Your Name - Initial work

## Acknowledgments

- OpenAI for AI capabilities
- Python asyncio community
- Security researchers and contributors 