"""
Tunnel Manager Module
Handles creation and management of secure tunnels for applications.
"""

import asyncio
import logging
import ssl
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

@dataclass
class TunnelInfo:
    """Data class to store tunnel information."""
    pid: int
    local_port: int
    remote_port: int
    remote_host: str
    created_at: datetime
    ssl_context: ssl.SSLContext

class TunnelManager:
    """Manages secure tunnels for applications."""

    def __init__(self):
        """Initialize the Tunnel Manager."""
        self.logger = logging.getLogger(__name__)
        self.tunnels: Dict[int, TunnelInfo] = {}
        self.servers: Dict[int, asyncio.Server] = {}
        self._ssl_context: Optional[ssl.SSLContext] = None

    async def initialize(self):
        """Initialize the tunnel manager and SSL context."""
        try:
            self._ssl_context = self._create_ssl_context()
            self.logger.info("Tunnel Manager initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize Tunnel Manager: {str(e)}", exc_info=True)
            raise

    async def shutdown(self):
        """Shutdown all active tunnels and cleanup resources."""
        for pid in list(self.tunnels.keys()):
            await self.remove_tunnel(pid)
        self.logger.info("Tunnel Manager shutdown complete")

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for secure tunnels."""
        try:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            cert_path = Path("config/certificates/cert.pem")
            key_path = Path("config/certificates/key.pem")

            # Create self-signed certificate if not exists
            if not cert_path.exists() or not key_path.exists():
                self._generate_self_signed_cert()

            context.load_cert_chain(cert_path, key_path)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # For self-signed certificates
            return context
        except Exception as e:
            self.logger.error(f"Failed to create SSL context: {str(e)}", exc_info=True)
            raise

    def _generate_self_signed_cert(self):
        """Generate self-signed certificate for development use."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime

        # Generate key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost")
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        # Save certificate and private key
        cert_path = Path("config/certificates")
        cert_path.mkdir(parents=True, exist_ok=True)

        with open(cert_path / "cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(cert_path / "key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    async def create_tunnel(self, pid: int, local_port: int, remote_host: str, remote_port: int) -> TunnelInfo:
        """
        Create a new secure tunnel for an application.

        Args:
            pid: Process ID of the application
            local_port: Local port to listen on
            remote_host: Remote host to connect to
            remote_port: Remote port to connect to

        Returns:
            TunnelInfo object containing tunnel details
        """
        if pid in self.tunnels:
            await self.remove_tunnel(pid)

        tunnel_info = TunnelInfo(
            pid=pid,
            local_port=local_port,
            remote_port=remote_port,
            remote_host=remote_host,
            created_at=datetime.now(),
            ssl_context=self._ssl_context
        )

        try:
            server = await asyncio.start_server(
                lambda r, w: self._handle_connection(r, w, tunnel_info),
                '127.0.0.1',
                local_port,
                ssl=self._ssl_context
            )

            self.tunnels[pid] = tunnel_info
            self.servers[pid] = server
            self.logger.info(f"Created tunnel for PID {pid} on port {local_port}")
            return tunnel_info

        except Exception as e:
            self.logger.error(f"Failed to create tunnel for PID {pid}: {str(e)}", exc_info=True)
            raise

    async def remove_tunnel(self, pid: int):
        """
        Remove a tunnel for an application.

        Args:
            pid: Process ID of the application
        """
        if pid in self.servers:
            server = self.servers.pop(pid)
            server.close()
            await server.wait_closed()

        if pid in self.tunnels:
            tunnel = self.tunnels.pop(pid)
            self.logger.info(f"Removed tunnel for PID {pid} from port {tunnel.local_port}")

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tunnel: TunnelInfo):
        """Handle incoming connections to the tunnel."""
        try:
            remote_reader, remote_writer = await asyncio.open_connection(
                tunnel.remote_host,
                tunnel.remote_port,
                ssl=tunnel.ssl_context
            )

            # Create bidirectional proxy
            await asyncio.gather(
                self._proxy_data(reader, remote_writer, "client -> remote"),
                self._proxy_data(remote_reader, writer, "remote -> client")
            )

        except Exception as e:
            self.logger.error(f"Error in tunnel connection: {str(e)}", exc_info=True)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _proxy_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str):
        """Proxy data between connections."""
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception as e:
            self.logger.error(f"Error in {direction} proxy: {str(e)}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass 