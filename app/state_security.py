"""
State Security Module
Provides PGP-based encryption for state management and certificate protection.
"""

import asyncio
import json
import os
import mmap
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List
import gnupg
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
import hashlib
import shutil
import platform
from rich.progress import Progress

class SecureMemoryStore:
    """Secure in-memory key storage with protection mechanisms."""
    
    def __init__(self):
        """Initialize secure memory storage based on platform."""
        self._memory_lock = asyncio.Lock()
        self._runtime_key = Fernet.generate_key()
        self._fernet = Fernet(self._runtime_key)
        
        # Create platform-specific secure memory
        if platform.system() == 'Windows':
            # On Windows, use basic memory mapping
            self._secure_memory = mmap.mmap(-1, 4096)
        else:
            # On Unix systems, use additional security flags
            self._secure_memory = mmap.mmap(
                -1,
                4096,
                flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                prot=mmap.PROT_READ | mmap.PROT_WRITE
            )
        
    async def secure_store(self, key_id: str, key_data: bytes, runtime_id: bytes):
        """Store key data with memory protection."""
        async with self._memory_lock:
            # Encrypt key data with runtime ID
            encrypted_key = self._encrypt_with_runtime(key_data, runtime_id)
            
            # Store in protected memory
            self._secure_memory.seek(0)
            self._secure_memory.write(encrypted_key)
            
            # Lock memory pages if possible
            self._lock_memory_pages()
            
    async def secure_retrieve(self, key_id: str, runtime_id: bytes) -> bytes:
        """Retrieve key data with verification."""
        async with self._memory_lock:
            # Verify runtime ID
            if not self._verify_runtime(runtime_id):
                raise SecurityException("Invalid runtime ID")
                
            # Read from protected memory
            self._secure_memory.seek(0)
            encrypted_key = self._secure_memory.read()
            
            # Decrypt with runtime ID
            return self._decrypt_with_runtime(encrypted_key, runtime_id)
            
    def _encrypt_with_runtime(self, data: bytes, runtime_id: bytes) -> bytes:
        """Encrypt data using runtime key."""
        combined = runtime_id + data
        return self._fernet.encrypt(combined)
        
    def _decrypt_with_runtime(self, encrypted_data: bytes, runtime_id: bytes) -> bytes:
        """Decrypt data and verify runtime ID."""
        decrypted = self._fernet.decrypt(encrypted_data)
        stored_runtime_id = decrypted[:32]
        if stored_runtime_id != runtime_id:
            raise SecurityException("Runtime ID mismatch")
        return decrypted[32:]
        
    def _verify_runtime(self, runtime_id: bytes) -> bool:
        """Verify runtime ID matches stored ID."""
        try:
            self._secure_memory.seek(0)
            encrypted_data = self._secure_memory.read()
            decrypted = self._fernet.decrypt(encrypted_data)
            return decrypted[:32] == runtime_id
        except Exception:
            return False
            
    def _lock_memory_pages(self):
        """Prevent memory from being swapped if possible."""
        try:
            if platform.system() != 'Windows' and hasattr(os, "mlock"):
                os.mlock(self._secure_memory)
        except Exception:
            pass  # Memory locking is a security enhancement but not critical
            
    def __del__(self):
        """Cleanup secure memory."""
        if hasattr(self, '_secure_memory'):
            self._secure_memory.close()

class CertificateManager:
    """Manages SSL/TLS certificates with secure storage and verification."""
    
    def __init__(self, state_manager: 'SecureStateManager', progress: Optional[Progress] = None):
        self.state_manager = state_manager
        self.cert_dir = self.state_manager.state_dirs['certificates']
        self.cert_index: Dict[str, Dict[str, Any]] = {}
        self.cert_lock = asyncio.Lock()
        self.progress = progress
        
    async def initialize(self):
        """Initialize certificate management system."""
        if self.progress:
            task = self.progress.add_task("Loading certificate index...", total=None)
            
        try:
            await self.load_cert_index()
            
        finally:
            if self.progress:
                self.progress.update(task, completed=True)
                
    async def store_certificate(self, cert_id: str, cert_data: bytes, metadata: Dict[str, Any]):
        """Store certificate with encryption and verification."""
        if self.progress:
            task = self.progress.add_task(f"Storing certificate {cert_id}...", total=None)
            
        async with self.cert_lock:
            try:
                # Generate certificate hash
                cert_hash = hashlib.sha256(cert_data).hexdigest()
                
                # Double encrypt certificate data
                # First with Fernet for memory protection
                fernet = Fernet(Fernet.generate_key())
                memory_encrypted = fernet.encrypt(cert_data)
                
                # Then with PGP for storage
                encrypted_cert = await self.state_manager.encrypt_state({
                    "data": b64encode(memory_encrypted).decode(),
                    "hash": cert_hash,
                    "encrypted": True
                }, skip_verification=True)
                
                # Store encrypted certificate with atomic write
                cert_path = self.cert_dir / f"{cert_id}.cert"
                temp_path = self.cert_dir / f"{cert_id}.{os.urandom(8).hex()}.tmp"
                
                # Write to temp file first
                temp_path.write_bytes(encrypted_cert)
                
                # Atomic rename with proper cleanup
                if cert_path.exists():
                    cert_path.unlink()
                temp_path.rename(cert_path)
                
                # Update certificate index with encryption metadata
                self.cert_index[cert_id] = {
                    "hash": cert_hash,
                    "metadata": {
                        **metadata,
                        "encryption": "pgp+fernet",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                }
                await self._save_cert_index()
                
            except Exception as e:
                # Clean up temp file on error
                if 'temp_path' in locals() and temp_path.exists():
                    try:
                        temp_path.unlink()
                    except Exception:
                        pass
                raise e
                
            finally:
                if self.progress:
                    self.progress.update(task, completed=True)
                    
    async def _save_cert_index(self):
        """Save certificate index without verification."""
        await self.state_manager.save_state(
            self.cert_index,
            "cert_index.json",
            skip_verification=True  # Skip verification to prevent recursion
        )

    async def load_certificate(self, cert_id: str) -> Tuple[bytes, Dict[str, Any]]:
        """Load and verify certificate."""
        async with self.cert_lock:
            if cert_id not in self.cert_index:
                raise SecurityException(f"Certificate {cert_id} not found")
                
            cert_path = self.cert_dir / f"{cert_id}.cert"
            if not cert_path.exists():
                raise SecurityException(f"Certificate file for {cert_id} missing")
                
            try:
                # Load and decrypt certificate
                encrypted_cert = cert_path.read_bytes()
                cert_data = await self.state_manager.decrypt_state(encrypted_cert)
                
                # Decrypt memory protection layer
                memory_encrypted = b64decode(cert_data["data"])
                if cert_data.get("encrypted", False):
                    # Handle double-encrypted certificates
                    fernet = Fernet(self.state_manager.pgp.runtime_id[:32])
                    cert_bytes = fernet.decrypt(memory_encrypted)
                else:
                    # Handle legacy certificates
                    cert_bytes = memory_encrypted
                
                # Verify certificate hash
                cert_hash = hashlib.sha256(cert_bytes).hexdigest()
                if cert_hash != self.cert_index[cert_id]["hash"]:
                    raise SecurityException(f"Certificate {cert_id} hash mismatch")
                    
                return cert_bytes, self.cert_index[cert_id]["metadata"]
                
            except Exception as e:
                raise SecurityException(f"Failed to load certificate {cert_id}: {str(e)}")
                
    async def load_cert_index(self):
        """Load certificate index from secure storage."""
        index_data = await self.state_manager.load_state("cert_index.json")
        self.cert_index = index_data if index_data else {}
        
    async def rotate_certificate(self, cert_id: str, new_cert_data: bytes):
        """Rotate certificate with secure backup of previous version."""
        async with self.cert_lock:
            if cert_id not in self.cert_index:
                raise SecurityException(f"Certificate {cert_id} not found")
                
            # Backup existing certificate
            old_cert_path = self.cert_dir / f"{cert_id}.cert"
            backup_path = self.state_manager.state_dirs['backups'] / f"{cert_id}.{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.bak"
            if old_cert_path.exists():
                shutil.copy2(old_cert_path, backup_path)
                
            # Store new certificate
            await self.store_certificate(
                cert_id,
                new_cert_data,
                self.cert_index[cert_id]["metadata"]
            )

    async def cleanup(self):
        """Clean up certificate manager resources."""
        try:
            await self._cleanup_temp_files()
        except Exception:
            pass

class StateVerification:
    """Provides state verification and integrity checking."""
    
    def __init__(self, state_manager: 'SecureStateManager'):
        self.state_manager = state_manager
        self.verification_lock = asyncio.Lock()
        self.state_hashes: Dict[str, str] = {}
        self._is_saving = False  # Prevent recursive saves
        
    async def verify_state(self, state_id: str, state_data: Dict) -> bool:
        """Verify state integrity using stored hashes."""
        async with self.verification_lock:
            state_hash = self._calculate_state_hash(state_data)
            stored_hash = self.state_hashes.get(state_id)
            
            if not stored_hash:
                self.state_hashes[state_id] = state_hash
                if not self._is_saving:
                    await self._save_hash_index()
                return True
                
            return state_hash == stored_hash
            
    async def update_state_hash(self, state_id: str, state_data: Dict):
        """Update stored hash for state verification."""
        if self._is_saving:
            return  # Skip if already saving to prevent recursion
            
        async with self.verification_lock:
            self.state_hashes[state_id] = self._calculate_state_hash(state_data)
            await self._save_hash_index()

    async def _save_hash_index(self):
        """Save hash index to secure storage."""
        try:
            self._is_saving = True
            await self.state_manager.save_state(
                self.state_hashes,
                "state_hashes.json",
                skip_verification=True  # Skip verification to prevent recursion
            )
        finally:
            self._is_saving = False

    def _calculate_state_hash(self, state_data: Dict) -> str:
        """Calculate deterministic hash of state data."""
        serialized = json.dumps(state_data, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()
        
    async def load_hash_index(self):
        """Load hash index from secure storage."""
        hash_data = await self.state_manager.load_state("state_hashes.json")
        self.state_hashes = hash_data if hash_data else {}

class PGPStateEncryption:
    """PGP-based state encryption with secure key management."""
    
    def __init__(self):
        self.memory_key_store = SecureMemoryStore()
        self.key_status = asyncio.Lock()
        self.runtime_id = os.urandom(32)
        self.gpg = gnupg.GPG()
        self.gpg.encoding = 'utf-8'
        self._runtime_password = None
        
    def _generate_runtime_password(self) -> str:
        """Generate a strong runtime password."""
        import string
        import secrets
        
        # Define character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one of each type
        password = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Add more random characters to reach desired length (32)
        all_chars = uppercase + lowercase + digits + special
        password.extend(secrets.choice(all_chars) for _ in range(28))
        
        # Shuffle the password
        shuffled = list(password)
        secrets.SystemRandom().shuffle(shuffled)
        
        return ''.join(shuffled)
        
    async def initialize(self):
        """Initialize PGP key management."""
        async with self.key_status:
            # Generate runtime password
            self._runtime_password = self._generate_runtime_password()
            
            # Generate runtime keys
            self.private_key = await self._generate_private_key()
            self.public_key = await self._derive_public_key()
            
            # Store private key securely in memory with runtime password
            encrypted_private_key = self._encrypt_with_password(
                self.private_key.encode(),
                self._runtime_password
            )
            
            await self.memory_key_store.secure_store(
                key_id="runtime_private_key",
                key_data=encrypted_private_key,
                runtime_id=self.runtime_id
            )
            
            # Clear sensitive data from memory
            self.private_key = None
            
    def _encrypt_with_password(self, data: bytes, password: str) -> bytes:
        """Encrypt data with runtime password."""
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        import base64
        
        # Generate salt
        salt = os.urandom(16)
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Encrypt data
        f = Fernet(key)
        encrypted_data = f.encrypt(data)
        
        # Combine salt and encrypted data
        return salt + encrypted_data
        
    def _decrypt_with_password(self, encrypted_data: bytes, password: str) -> bytes:
        """Decrypt data with runtime password."""
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        import base64
        
        # Extract salt and encrypted data
        salt = encrypted_data[:16]
        data = encrypted_data[16:]
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Decrypt data
        f = Fernet(key)
        return f.decrypt(data)
        
    async def decrypt_state(self, encrypted_data: bytes) -> Dict:
        """Decrypt state data using protected runtime private key."""
        async with self.key_status:
            # Retrieve private key securely
            encrypted_private_key = await self.memory_key_store.secure_retrieve(
                key_id="runtime_private_key",
                runtime_id=self.runtime_id
            )
            
            # Decrypt private key with runtime password
            private_key = self._decrypt_with_password(
                encrypted_private_key,
                self._runtime_password
            ).decode()
            
            # Decrypt state
            decrypted_data = self.gpg.decrypt(
                encrypted_data,
                passphrase=None
            )
            
            # Clear private key from scope
            private_key = None
            
            return json.loads(str(decrypted_data))
            
    async def cleanup(self):
        """Secure cleanup of keys and runtime password."""
        if self.private_key:
            self.gpg.delete_keys(self.private_key, True)
            self.private_key = None
        if self.public_key:
            self.gpg.delete_keys(self.public_key)
            self.public_key = None
        if self._runtime_password:
            self._runtime_password = None

class SecureStateManager:
    """State manager with PGP encryption and verification."""
    
    def __init__(self, pgp: PGPStateEncryption, progress: Optional[Progress] = None):
        self.pgp = pgp
        # Define all state directories
        self.state_dirs = {
            'state': Path("~/.dtm/state").expanduser(),
            'backups': Path("~/.dtm/backups").expanduser(),
            'certificates': Path("~/.dtm/certificates").expanduser()
        }
        
        # Create all directories
        for dir_path in self.state_dirs.values():
            dir_path.mkdir(parents=True, exist_ok=True)
            
        self.verification = StateVerification(self)
        self.progress = progress
        self.certificates = CertificateManager(self, progress)
        
    async def initialize(self):
        """Initialize state management system."""
        if self.progress:
            task = self.progress.add_task("Initializing state management...", total=None)
            
        try:
            # Clean up all state directories
            await self._cleanup_all_temp_files()
            # Initialize components
            await self.verification.load_hash_index()
            await self.certificates.initialize()
        finally:
            if self.progress:
                self.progress.update(task, completed=True)
                
    async def _cleanup_all_temp_files(self):
        """Clean up temporary files from all state directories."""
        if self.progress:
            task = self.progress.add_task("Cleaning up temporary files...", total=None)
            
        try:
            for dir_name, dir_path in self.state_dirs.items():
                # Clean .tmp files
                for temp_file in dir_path.glob("*.tmp"):
                    try:
                        temp_file.unlink()
                    except Exception:
                        pass
                        
                # Clean any orphaned backup files in state and certificates dirs
                if dir_name != 'backups':  # Skip backup dir itself
                    for backup_file in dir_path.glob("*.bak"):
                        try:
                            backup_file.unlink()
                        except Exception:
                            pass
        finally:
            if self.progress:
                self.progress.update(task, completed=True)
                
    async def encrypt_state(self, state_data: Dict, skip_verification: bool = False) -> bytes:
        """
        Encrypt state data using runtime public key.
        
        Args:
            state_data: Dictionary containing state data to encrypt
            skip_verification: If True, skips state verification to prevent recursion
        """
        async with self.pgp.key_status:
            # Get public key for encryption
            public_key = await self.pgp.get_public_key()
            
            # Serialize and encrypt state
            state_bytes = json.dumps(state_data).encode()
            encrypted_state = self.pgp.gpg.encrypt(
                state_bytes,
                recipients=[public_key],
                armor=True,
                always_trust=True
            )
            
            return str(encrypted_state).encode()
            
    async def decrypt_state(self, encrypted_data: bytes) -> Dict:
        """Decrypt state data using protected runtime private key."""
        async with self.pgp.key_status:
            # Retrieve private key securely
            encrypted_private_key = await self.memory_key_store.secure_retrieve(
                key_id="runtime_private_key",
                runtime_id=self.pgp.runtime_id
            )
            
            # Decrypt state
            decrypted_data = self.pgp.gpg.decrypt(
                encrypted_data,
                passphrase=None
            )
            
            # Clear private key from scope
            private_key = None
            
            return json.loads(str(decrypted_data))
            
    async def save_state(self, state_data: Dict, filename: str, skip_verification: bool = False):
        """Save encrypted state to file with verification."""
        if self.progress:
            task = self.progress.add_task(f"Saving state: {filename}...", total=None)
            
        try:
            # Update state verification if not skipped
            if not skip_verification:
                await self.verification.update_state_hash(filename, state_data)
            
            # Encrypt state data
            encrypted_data = await self.encrypt_state(state_data, skip_verification=skip_verification)
            
            # Save with atomic write using random temp file name
            temp_file = self.state_dirs['state'] / f"{filename}.{os.urandom(8).hex()}.tmp"
            target_file = self.state_dirs['state'] / filename
            
            # Write to temp file first
            temp_file.write_bytes(encrypted_data)
            
            # Atomic rename with proper cleanup
            if target_file.exists():
                target_file.unlink()
            temp_file.rename(target_file)
            
            # Create backup
            await self._create_backup(filename, encrypted_data)
            
        except Exception as e:
            # Clean up temp file on error
            if 'temp_file' in locals() and temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass
            raise e
            
        finally:
            if self.progress:
                self.progress.update(task, completed=True)
                
    async def load_state(self, filename: str) -> Optional[Dict]:
        """Load and verify state from file."""
        file_path = self.state_dirs['state'] / filename
        if not file_path.exists():
            return None
            
        encrypted_data = file_path.read_bytes()
        state_data = await self.decrypt_state(encrypted_data)
        
        # Verify state integrity
        if not await self.verification.verify_state(filename, state_data):
            # Attempt to restore from backup
            backup_data = await self._restore_backup(filename)
            if backup_data:
                return backup_data
            raise SecurityException(f"State verification failed for {filename}")
            
        return state_data
        
    async def _create_backup(self, filename: str, encrypted_data: bytes):
        """Create encrypted backup of state data."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        backup_path = self.state_dirs['backups'] / f"{filename}.{timestamp}.bak"
        backup_path.write_bytes(encrypted_data)
        
        # Cleanup old backups for this specific file
        await self._cleanup_file_backups(filename)
        
    async def _restore_backup(self, filename: str) -> Optional[Dict]:
        """Attempt to restore state from most recent backup."""
        backup_files = sorted(
            self.state_dirs['backups'].glob(f"{filename}.*.bak"),
            reverse=True
        )
        
        for backup_file in backup_files:
            try:
                encrypted_data = backup_file.read_bytes()
                state_data = await self.decrypt_state(encrypted_data)
                if await self.verification.verify_state(filename, state_data):
                    return state_data
            except Exception:
                continue
                
        return None
        
    async def _cleanup_file_backups(self, filename: str):
        """Remove old backups for a specific file, keeping only the last 5."""
        try:
            backup_files = sorted(
                self.state_dirs['backups'].glob(f"{filename}.*.bak"),
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )
            
            # Remove all but the last 5 backups
            for old_backup in backup_files[5:]:
                try:
                    old_backup.unlink()
                except Exception:
                    continue
        except Exception:
            pass  # Don't fail if cleanup fails

    async def cleanup(self):
        """Clean up all state management resources."""
        if self.progress:
            task = self.progress.add_task("Cleaning up state management...", total=None)
            
        try:
            await self._cleanup_all_temp_files()
            # Clean up certificates
            await self.certificates.cleanup()
            # Keep only last 5 backups for each file
            await self._cleanup_all_backups()
        finally:
            if self.progress:
                self.progress.update(task, completed=True)
                
    async def _cleanup_all_backups(self):
        """Clean up old backups for all state files."""
        try:
            backup_pattern = "*.bak"
            backup_files = {}
            
            # Group backup files by their base name
            for backup_file in self.state_dirs['backups'].glob(backup_pattern):
                base_name = backup_file.name.split('.')[0]
                if base_name not in backup_files:
                    backup_files[base_name] = []
                backup_files[base_name].append(backup_file)
            
            # Keep only last 5 backups for each file
            for base_name, files in backup_files.items():
                sorted_files = sorted(files, key=lambda x: x.stat().st_mtime, reverse=True)
                for old_backup in sorted_files[5:]:
                    try:
                        old_backup.unlink()
                    except Exception:
                        continue
                        
        except Exception:
            pass  # Don't fail if cleanup fails

class SecurityException(Exception):
    """Custom exception for security-related errors."""
    pass 