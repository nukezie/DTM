"""
Application Discovery Module
Responsible for detecting and monitoring running applications with network connections.
"""

import asyncio
import logging
import psutil
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ApplicationInfo:
    """Data class to store application information."""
    pid: int
    name: str
    local_port: int
    remote_host: str
    remote_port: int
    created_at: datetime
    last_seen: datetime

class ApplicationDiscovery:
    """Handles discovery and monitoring of network-enabled applications."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.applications: Dict[int, ApplicationInfo] = {}
        self._monitor_task: Optional[asyncio.Task] = None

    async def start_monitoring(self):
        """Start the application discovery monitoring process."""
        if self.running:
            return
        
        self.running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self.logger.info("Application discovery monitoring started")

    async def stop(self):
        """Stop the application discovery monitoring process."""
        if not self.running:
            return
        
        self.running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        self.logger.info("Application discovery monitoring stopped")

    async def _monitor_loop(self):
        """Main monitoring loop to discover applications."""
        while self.running:
            try:
                await self._scan_applications()
                await asyncio.sleep(1)  # Scan every second
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {str(e)}", exc_info=True)

    async def _scan_applications(self):
        """Scan for applications with network connections."""
        current_time = datetime.now()
        seen_pids = set()

        for conn in psutil.net_connections(kind='inet'):
            try:
                if not conn.pid or not conn.laddr:
                    continue

                # Get process information
                process = psutil.Process(conn.pid)
                local_port = conn.laddr.port
                remote_host = conn.raddr.ip if conn.raddr else ''
                remote_port = conn.raddr.port if conn.raddr else 0

                app_info = ApplicationInfo(
                    pid=conn.pid,
                    name=process.name(),
                    local_port=local_port,
                    remote_host=remote_host,
                    remote_port=remote_port,
                    created_at=current_time,
                    last_seen=current_time
                )

                if conn.pid in self.applications:
                    # Update existing application
                    self.applications[conn.pid].last_seen = current_time
                else:
                    # New application discovered
                    self.applications[conn.pid] = app_info
                    self.logger.info(f"New application discovered: {app_info.name} (PID: {app_info.pid})")

                seen_pids.add(conn.pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Remove stale applications
        stale_pids = set(self.applications.keys()) - seen_pids
        for pid in stale_pids:
            app = self.applications.pop(pid)
            self.logger.info(f"Application removed: {app.name} (PID: {app.pid})")

    def get_active_applications(self) -> List[ApplicationInfo]:
        """Get a list of currently active applications."""
        return list(self.applications.values()) 