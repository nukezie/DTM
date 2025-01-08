# Dynamic Tunnel Manager (DTM)

## Creator's Note
I created the Dynamic Tunnel Manager (DTM) out of a personal need to protect applications from local tampering. While I'm not a cybersecurity researcher, I noticed a significant gap in how traditional tunnelling solutions handle local application security. Most existing solutions use static configurations that can be easily predicted and manipulated.

The idea for DTM came from a simple question: "What if the target kept moving?" By implementing continuous port rotation and adding AI-powered analysis, I aimed to create a system where potential threats would face a constantly changing landscape. While I've successfully implemented the core tunnelling and port rotation features, I'm actively seeking collaboration from the community, especially in:

1. **AI Integration**: The GPT-4 integration needs improvement to provide a better security analysis
2. **State Security**: The PGP-based security system requires expertise to implement properly
3. **Performance Optimization**: Ensuring smooth operation with minimal resource usage

I believe in open collaboration and welcome contributions from security experts, developers, and enthusiasts who share the vision of making application security more dynamic and resilient. If you're interested in contributing, especially in the areas marked as TODO, please reach out!

## Current Development Context

### Immediate Implementation Needs

#### 1. GPT-4 Analysis Integration
The AI analysis system currently faces implementation challenges:
```python
# Current implementation issue in ai_analysis.py
async def _get_ai_recommendations(self, context: Dict[str, Any]) -> Dict[str, Any]:
    try:
        response = await self.client.chat.completions.create(
            model="gpt-4",
            messages=[...],
            temperature=0.2,
            max_tokens=1000
        )
        # Response handling needs improvement
```

**Help Needed:**
- Proper implementation of the OpenAI API client
- Structured JSON response handling
- Retry mechanism for API failures
- Rate limiting implementation
- Response validation and error handling

#### 2. State Security Integration
The `state_security.py` module provides robust security features but needs integration:

```python
# Need to integrate with main application
class SecureStateManager:
    """State manager with PGP encryption and verification."""
    def __init__(self, pgp: PGPStateEncryption, progress: Optional[Progress] = None):
        self.pgp = pgp
        self.state_dirs = {
            'state': Path("~/.dtm/state").expanduser(),
            'backups': Path("~/.dtm/backups").expanduser(),
            'certificates': Path("~/.dtm/certificates").expanduser()
        }
```

**Integration Points Needed:**
1. **Certificate Management**
   - Integration with TunnelManager for secure certificate handling
   - Implementation of certificate rotation
   - Secure cleanup procedures

2. **State Management**
   - Integration with the main application state
   - Secure configuration storage
   - Runtime state protection

3. **Memory Security**
   - Implementation of secure memory allocation
   - Platform-specific memory protection
   - Anti-dumping mechanisms

### Current Priorities

1. **AI Analysis**
   ```python
   # Example of desired AI analysis implementation
   async def analyze_application(self, app_info: ApplicationInfo) -> Dict[str, Any]:
       """
       Needed: Proper implementation of application analysis
       - Structured context creation
       - Reliable API communication
       - Error handling and retries
       - Response validation
       """
       pass
   ```

2. **State Security**
   ```python
   # Example of needed state security integration
   class DTMApplication:
       async def initialize(self):
           """
           Need to implement:
           - Secure state initialization
           - Certificate management
           - Memory protection
           - State backup/recovery
           """
           self.state_manager = SecureStateManager(...)
           await self.state_manager.initialize()
   ```

### How to Contribute

If you have expertise in:
1. OpenAI API integration
2. Memory security implementation
3. PGP-based encryption systems
4. Python async programming

Please consider contributing to these critical areas. The core functionality works, but these security enhancements will make the application more robust and secure.

## 🚨 TODO: Critical Updates Required

### 1. AI Analysis Integration Fix
- Update OpenAI API implementation to the latest standards
- Implement proper JSON response handling
- Add a retry mechanism for API failures
- Enhance analysis context with more detailed application metrics
- Implement rate limiting and error handling
- Add caching for repeated analysis requests

### 2. State Security Integration
- Integrate PGP-based state encryption system
- Implement secure memory management for keys
- Add certificate rotation and verification
- Setup secure backup and recovery mechanisms
- Implement runtime security verification
- Add state integrity checking

## Overview

A secure and automated system for managing dynamic, encrypted tunnels for network applications with AI-driven optimization and state-based security.

## Core Features

### Application Security
- **SSL/TLS Tunneling**: Automated tunnel creation with certificate management
- **Dynamic Port Rotation**: Automatic port changes every 10 seconds
- **Traffic Isolation**: Secure encapsulation of application traffic
- **State Security**: PGP-based encryption for all state data

### AI-Driven Analysis
- Real-time traffic pattern analysis
- Security risk assessment
- Behavioral anomaly detection
- Automatic threat response
- Performance optimization recommendations

### Process Management
- Automatic application discovery
- Real-time connection monitoring
- Process state tracking
- Dynamic resource allocation

### User Interface
- Rich CLI interface with live updates
- Process status visualization
- Security metrics display
- Interactive controls
- Scrollable process list
- AI analysis results in view

## State Security System

### Overview
The state security system provides multiple layers of protection:

1. **PGP Encryption Layer**
   - Runtime key generation
   - Secure key storage
   - State encryption/decryption
   - Certificate management

2. **Memory Protection**
   - Secure memory allocation
   - Runtime memory locking
   - Key isolation
   - Anti-dumping mechanisms

3. **State Verification**
   - Hash-based integrity checking
   - State backup management
   - Atomic state updates
   - Recovery mechanisms

4. **Certificate Management**
   - Automatic certificate rotation
   - Secure storage
   - Verification chains
   - Backup management

### Security Features
- Runtime memory protection
- State integrity verification
- Secure key management
- Atomic state operations
- Automatic backup creation
- Platform-specific security
- Certificate rotation
- Secure cleanup procedures

## Requirements

- Python 3.9+
- OpenAI API key (for AI analysis)
- GnuPG (for state security)
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
Create `config/config.json` with your OpenAI API key:
```json
{
    "openai_api_key": "your-api-key-here"
}
```

## Usage

1. Start the Dynamic Tunnel Manager:
```bash
python main.py
```

2. Interactive Controls:
- `↑/↓`: Scroll through processes
- `T`: Toggle auto-tunneling
- `A`: Toggle AI analysis
- `P`: Analyze specific PID
- `R`: Force port rotation
- `Q`: Quit

## Configuration

### Port Configuration
- Default port range: 5000-6000
- Rotation interval: 10 seconds
- Configurable in `config/config.json`

### Security Configuration
- Certificate directory: `config/certificates/`
- State directory: `~/.dtm/state/`
- Backup directory: `~/.dtm/backups/`

### AI Analysis Settings
- Model: GPT-4
- Analysis interval: 60 seconds
- Security threshold: 0.7
- Configurable in `config/config.json`

## Development

### Running Tests
```bash
pytest tests/
```

### Security Guidelines
1. Never store sensitive data in plaintext
2. Use atomic operations for state changes
3. Implement proper cleanup procedures
4. Follow secure coding practices
5. Regular security audits

## Logging

- Application logs: `logs/dtm.json`
- Structured JSON format
- Security event tracking
- Performance metrics
- Error tracking

## Contributing

1. Fork the repository
2. Create feature branch
3. Implement changes
4. Add tests
5. Submit pull request

## License

MIT License - see LICENSE file for details

## Support

For support:
1. Check documentation
2. Search existing issues
3. Create new issue

## Security Notice

This tool handles sensitive security operations. Always:
1. Keep your API keys secure
2. Regularly update dependencies
3. Monitor security advisories
4. Follow security best practices
5. Regularly rotate certificates 

## State Security System Deep Dive

### Zero-Trust Architecture

The state security system implements a zero-trust architecture where no data is permanently stored on disk in its original form. All state data, including certificates and configurations, exists only in secure, isolated memory during runtime.

### Secure Memory Management

#### Runtime Key Initialization
1. **Secure Memory Allocation**
   - Platform-specific secure memory pages are allocated
   - Memory is locked to prevent swapping to disk
   - Anti-dumping mechanisms prevent memory extraction

2. **Runtime Password Generation**
   ```python
   # Example of runtime password generation
   password = [
       random(uppercase),
       random(lowercase),
       random(digits),
       random(special)
   ] + random(all_chars, length=28)
   shuffle(password)  # Cryptographically secure shuffle
   ```

3. **Key Isolation**
   - Private keys are generated in isolated memory blocks
   - Keys never touch disk storage
   - Memory is protected from other processes
   - Automatic cleanup on process termination

### State Encryption Flow

1. **Initial State**
   ```
   Runtime Start
   ├── Generate Runtime ID (32 bytes random)
   ├── Create Secure Memory Store
   └── Initialize PGP State Encryption
   ```

2. **Memory Protection**
   ```
   Secure Memory
   ├── Platform Detection
   │   ├── Windows: Basic Memory Mapping
   │   └── Unix: MAP_PRIVATE | MAP_ANONYMOUS
   ├── Memory Locking
   │   ├── mlock() on Unix
   │   └── VirtualLock() on Windows
   └── Anti-Dumping Mechanisms
   ```

3. **Key Management**
   ```
   Key Lifecycle
   ├── Runtime Password Generation
   ├── Private Key Generation in Memory
   ├── Public Key Derivation
   └── Secure Key Storage in Memory
   ```

### State Data Protection

#### Memory-Only Storage
- All sensitive data exists only in memory
- No sensitive data is written to disk
- Encrypted backups use different keys
- Automatic memory wiping on exit

#### Double Encryption
1. **Memory Layer**
   - Fernet symmetric encryption
   - Runtime-generated keys
   - Memory-only key storage

2. **State Layer**
   - PGP asymmetric encryption
   - Runtime-generated keypair
   - Zero-disk-exposure

### Certificate Management

#### Secure Certificate Handling
```
Certificate Lifecycle
├── Generation
│   ├── In-Memory Generation
│   ├── Runtime Encryption
│   └── Encrypted Storage
├── Usage
│   ├── Decrypt in Secure Memory
│   ├── Use for Tunneling
│   └── Immediate Cleanup
└── Rotation
    ├── New Certificate Generation
    ├── Atomic Replacement
    └── Old Certificate Cleanup
```

### Backup and Recovery

#### Secure Backup System
- Backups are always encrypted
- Different encryption keys than runtime
- Atomic write operations
- Secure cleanup of old backups

#### Recovery Process
```
Recovery Flow
├── Backup Verification
├── Secure Memory Allocation
├── Encrypted State Loading
└── State Verification
``` 

## 🔐 Security Analysis: Current State vs. Enhanced Protection

### Current Security Vulnerabilities

#### 1. Certificate Exposure 🚨
```plaintext
Current Implementation:
config/certificates/
├── cert.pem  # Unencrypted, vulnerable to tampering
└── key.pem   # Sensitive key material exposed on disk
```
The current system stores SSL/TLS certificates and private keys in plaintext, making them vulnerable to:
- Direct file manipulation
- Key extraction
- Certificate tampering
- Unauthorized copying

#### 2. State Management Risks 📛
```plaintext
Current State Storage:
- Configuration stored in plaintext JSON
- No runtime state protection
- Predictable file locations
- No integrity verification
```

#### 3. Memory Security Gaps 💭
```plaintext
Current Memory Handling:
- Keys loaded directly into process memory
- No protection against memory dumps
- Swappable memory pages
- No secure cleanup procedures
```

### 🛡️ Enhanced Security with state_security.py

#### 1. Zero-Trust Certificate Management
```python
class CertificateManager:
    async def store_certificate(self, cert_id: str, cert_data: bytes, metadata: Dict[str, Any]):
        # Double encryption for certificates
        fernet = Fernet(Fernet.generate_key())
        memory_encrypted = fernet.encrypt(cert_data)
        
        # PGP encryption for storage
        encrypted_cert = await self.state_manager.encrypt_state({
            "data": b64encode(memory_encrypted).decode(),
            "hash": cert_hash,
            "encrypted": True
        })
```
- ✅ Certificates never exist unencrypted on disk
- ✅ Double-encryption protection
- ✅ Runtime-only key access
- ✅ Automatic rotation and cleanup

#### 2. Secure Memory Architecture
```python
class SecureMemoryStore:
    def __init__(self):
        if platform.system() == 'Windows':
            self._secure_memory = mmap.mmap(-1, 4096)
        else:
            self._secure_memory = mmap.mmap(
                -1, 4096,
                flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                prot=mmap.PROT_READ | mmap.PROT_WRITE
            )
```
- ✅ Platform-specific memory protection
- ✅ Anti-dumping mechanisms
- ✅ Memory page locking
- ✅ Secure key isolation

#### 3. State Protection System
```python
class SecureStateManager:
    async def save_state(self, state_data: Dict, filename: str):
        # Encrypt state data
        encrypted_data = await self.encrypt_state(state_data)
        
        # Atomic write with backup
        temp_file = self.state_dirs['state'] / f"{filename}.{os.urandom(8).hex()}.tmp"
        target_file = self.state_dirs['state'] / filename
```
- ✅ All state data encrypted
- ✅ Atomic file operations
- ✅ Automatic backups
- ✅ Integrity verification

### 🔄 Runtime Security Flow

```plaintext
Application Start
├── Generate Runtime ID (32 bytes random)
├── Initialize Secure Memory
│   ├── Allocate Protected Pages
│   └── Lock Memory (prevent swapping)
├── Generate Runtime Keys
│   ├── Create PGP Keypair
│   └── Store in Secure Memory
└── Initialize State Manager
    ├── Load Encrypted State
    ├── Verify Integrity
    └── Setup Certificate Manager
```

### 🛡️ Security Improvements

1. **Certificate Protection**
   - Before: Plaintext files on disk
   - After: Double-encrypted, memory-only access

2. **Memory Security**
   - Before: Standard process memory
   - After: Protected pages, anti-dumping

3. **State Management**
   - Before: Plaintext JSON files
   - After: PGP-encrypted, integrity-verified

4. **Key Management**
   - Before: Static keys on disk
   - After: Runtime-generated, memory-only

### 🔍 Security Guarantees

1. **Zero Disk Exposure**
   - No sensitive data written unencrypted
   - All state changes atomic and verified
   - Secure backup management

2. **Memory Protection**
   - Platform-specific security
   - Memory page locking
   - Anti-dumping mechanisms
   - Secure cleanup

3. **Runtime Security**
   - Dynamic key generation
   - Continuous verification
   - Automatic rotation
   - Secure cleanup

### ⚠️ Integration Requirements

To fully implement these security features:
1. Replace current certificate handling
2. Integrate secure memory store
3. Implement state manager
4. Add runtime security checks
5. Update backup procedures

### 🔒 Advanced Security Considerations

#### Memory Attack Vectors
- Memory dumping attempts
- Cold boot attacks
- DMA attacks
- Swap file analysis
- Process memory inspection

#### Mitigations
1. **Memory Protection**
   - Secure memory allocation
   - Page locking
   - Memory wiping
   - Anti-dumping techniques

2. **Runtime Protection**
   - Process isolation
   - Privilege separation
   - Resource cleanup
   - Signal handling

### 🛠️ Development Guidelines

#### Code Quality
- Type hints required
- Docstrings mandatory
- Unit tests for all features
- Integration tests for security features

#### Security Practices
- Regular dependency updates
- Code review requirements
- Security audit logging
- Performance monitoring

### 📚 Documentation Standards

#### Code Documentation
- Function documentation
- Security considerations
- Implementation notes
- Usage examples

#### Security Documentation
- Threat models
- Security assumptions
- Implementation details
- Recovery procedures

### 🤝 Community Guidelines

#### Contributing
- Security-first approach
- Code review process
- Testing requirements
- Documentation updates

#### Issue Reporting
- Security issue template
- Bug report format
- Feature request format
- Pull request guidelines

### 🔄 Version Control

#### Branch Strategy
- `main`: Stable releases
- `develop`: Development
- `feature/*`: New features
- `security/*`: Security updates
- `hotfix/*`: Critical fixes

#### Release Process
1. Security audit
2. Integration testing
3. Documentation update
4. Version tagging
5. Release notes

### 📋 Project Roadmap

#### Short Term
- GPT-4 integration fixes
- State security implementation
- Memory protection enhancements
- Certificate management updates

#### Long Term
- Additional AI models support
- Enhanced threat detection
- Performance optimizations
- Extended platform support

### 🎯 Future Enhancements

#### Planned Features
1. **Enhanced AI Analysis**
   - Multiple AI model support
   - Custom model training
   - Behavioral learning
   - Pattern recognition

2. **Advanced Security**
   - Hardware security module support
   - TPM integration
   - Secure enclave usage
   - Enhanced memory protection

3. **Performance Optimization**
   - Resource usage reduction
   - Startup time improvement
   - Memory footprint reduction
   - Operation speed increase

4. **User Experience**
   - Web interface option
   - Mobile monitoring
   - Remote management
   - Custom dashboards

### 📊 Performance Metrics

#### Monitoring
- CPU usage tracking
- Memory utilization
- Network performance
- Security overhead

#### Benchmarks
- Port rotation speed
- Encryption performance
- Memory protection impact
- Overall system load

### 🌐 Network Considerations

#### Firewall Configuration
- Required ports
- Protocol requirements
- Security rules
- Network isolation

#### Traffic Management
- Bandwidth control
- Connection limits
- Traffic prioritization
- Load balancing

### 💻 System Requirements

#### Minimum Requirements
- CPU: Dual-core
- RAM: 4GB
- Storage: 1GB
- Python 3.9+

#### Recommended
- CPU: Quad-core
- RAM: 8GB
- Storage: 5GB
- SSD recommended

### 🔧 Troubleshooting

#### Common Issues
1. **Certificate Problems**
   - Generation failures
   - Rotation issues
   - Permission errors
   - Storage problems

2. **Memory Issues**
   - Allocation failures
   - Protection errors
   - Cleanup problems
   - Resource leaks

3. **State Management**
   - Encryption errors
   - Backup failures
   - Recovery issues
   - Integrity problems

---

## License

MIT License - See LICENSE file for details.

## Acknowledgments

- OpenAI for GPT-4 API
- Python Cryptography Community
- Security Researchers
- Open Source Contributors
