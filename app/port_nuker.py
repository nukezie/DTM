"""
Port Nuker Module
Handles dynamic port assignment and rotation for application tunnels.
"""

import asyncio
import logging
import random
from typing import Set, Dict, Optional
from datetime import datetime, timedelta

class PortNuker:
    """Manages dynamic port assignment and rotation."""

    def __init__(self, 
                 port_range: tuple[int, int] = (5000, 6000),
                 rotation_interval: int = 10):
        """
        Initialize the Port Nuker.

        Args:
            port_range: Tuple of (min_port, max_port) for port assignment
            rotation_interval: Seconds between port rotations
        """
        self.logger = logging.getLogger(__name__)
        self.min_port, self.max_port = port_range
        self.rotation_interval = rotation_interval
        self.running = False
        self.used_ports: Set[int] = set()
        self.port_assignments: Dict[int, int] = {}  # pid -> port
        self.last_rotation: Optional[datetime] = None
        self._rotation_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the port rotation service."""
        if self.running:
            return

        self.running = True
        self.last_rotation = datetime.now()
        self._rotation_task = asyncio.create_task(self._rotation_loop())
        self.logger.info("Port Nuker service started")

    async def stop(self):
        """Stop the port rotation service."""
        if not self.running:
            return

        self.running = False
        if self._rotation_task:
            self._rotation_task.cancel()
            try:
                await self._rotation_task
            except asyncio.CancelledError:
                pass
        self.logger.info("Port Nuker service stopped")

    def assign_port(self, pid: int) -> int:
        """
        Assign a new port to an application.

        Args:
            pid: Process ID of the application

        Returns:
            Assigned port number
        """
        if pid in self.port_assignments:
            return self.port_assignments[pid]

        available_ports = set(range(self.min_port, self.max_port + 1)) - self.used_ports
        if not available_ports:
            raise RuntimeError("No available ports in the specified range")

        port = random.choice(list(available_ports))
        self.used_ports.add(port)
        self.port_assignments[pid] = port
        self.logger.info(f"Assigned port {port} to PID {pid}")
        return port

    def release_port(self, pid: int):
        """
        Release a port assigned to an application.

        Args:
            pid: Process ID of the application
        """
        if pid in self.port_assignments:
            port = self.port_assignments.pop(pid)
            self.used_ports.remove(port)
            self.logger.info(f"Released port {port} from PID {pid}")

    async def _rotation_loop(self):
        """Main loop for port rotation."""
        while self.running:
            try:
                now = datetime.now()
                if self.last_rotation and (now - self.last_rotation).seconds >= self.rotation_interval:
                    await self._rotate_ports()
                    self.last_rotation = now
                await asyncio.sleep(1)
            except Exception as e:
                self.logger.error(f"Error in rotation loop: {str(e)}", exc_info=True)

    async def _rotate_ports(self):
        """Rotate ports for all active applications."""
        if not self.port_assignments:
            return

        self.logger.info("Starting port rotation")
        new_assignments: Dict[int, int] = {}

        # Create new port assignments
        for pid in self.port_assignments.keys():
            try:
                old_port = self.port_assignments[pid]
                new_port = self.assign_port_atomic(pid, exclude={old_port})
                new_assignments[pid] = new_port
                self.logger.info(f"Rotating PID {pid} from port {old_port} to {new_port}")
            except Exception as e:
                self.logger.error(f"Failed to rotate port for PID {pid}: {str(e)}")

        # Update assignments
        self.port_assignments = new_assignments
        self.logger.info("Port rotation completed")

    def assign_port_atomic(self, pid: int, exclude: Set[int]) -> int:
        """
        Atomically assign a new port, excluding specific ports.

        Args:
            pid: Process ID of the application
            exclude: Set of ports to exclude from assignment

        Returns:
            Newly assigned port number
        """
        available_ports = set(range(self.min_port, self.max_port + 1)) - self.used_ports - exclude
        if not available_ports:
            raise RuntimeError("No available ports for rotation")

        port = random.choice(list(available_ports))
        self.used_ports.add(port)
        return port

    def get_port(self, pid: int) -> Optional[int]:
        """
        Get the currently assigned port for a PID.

        Args:
            pid: Process ID of the application

        Returns:
            Assigned port number or None if not assigned
        """
        return self.port_assignments.get(pid) 