#!/usr/bin/env python3
"""
Dynamic Tunnel Manager (DTM) - Main Application
This is the entry point for the Dynamic Tunnel Manager application.
"""

import asyncio
import logging
import sys
import json
from pathlib import Path
from datetime import datetime
import keyboard
from rich.logging import RichHandler
from app.discovery import ApplicationDiscovery
from app.tunnel_manager import TunnelManager
from app.port_nuker import PortNuker
from app.ai_analysis import AIAnalyzer
from app.logging_manager import setup_logging
from app.cli_ui import DTMUI

# Configure base directory
BASE_DIR = Path(__file__).resolve().parent

class DTMApplication:
    """Main application class for Dynamic Tunnel Manager."""

    def __init__(self):
        """Initialize the application components."""
        # Set up logging first
        setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize components
        self.app_discovery = ApplicationDiscovery()
        self.tunnel_manager = TunnelManager()
        self.port_nuker = PortNuker()
        self.ai_analyzer = AIAnalyzer(api_key=self.config.get("openai_api_key", ""))
        self.ui = DTMUI(config=self.config)
        
        # Internal state
        self.running = False
        self._monitor_task = None
        
    def _load_config(self) -> dict:
        """Load application configuration."""
        try:
            config_path = Path("config/config.json")
            if not config_path.exists():
                # Create default configuration if it doesn't exist
                config = {
                    "openai_api_key": "",  # User needs to set this
                    "port_range": [5000, 6000],
                    "rotation_interval": 10,
                    "auto_tunnel": True,
                    "ai_analysis": {
                        "enabled": True,
                        "model": "gpt-3.5-turbo",
                        "temperature": 0.3,
                        "max_tokens": 500,
                        "security_threshold": 0.7,
                        "scan_interval": 60
                    },
                    "logging": {
                        "level": "INFO",
                        "format": "JSON",
                        "file": "logs/dtm.json"
                    },
                    "ui": {
                        "refresh_rate": 4,
                        "items_per_page": 10,
                        "colors": {
                            "header": "blue",
                            "table": "cyan",
                            "analysis": "magenta"
                        }
                    }
                }
                config_path.parent.mkdir(exist_ok=True)
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=4)
                self.logger.info("Created default configuration file")
                return config
            
            with open(config_path) as f:
                config = json.load(f)
                if not config.get("openai_api_key"):
                    self.logger.warning("OpenAI API key not set in config/config.json")
                return config
                
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {str(e)}", exc_info=True)
            return {
                "openai_api_key": "",
                "port_range": [5000, 6000],
                "rotation_interval": 10,
                "auto_tunnel": True,
                "ai_analysis": {
                    "enabled": True,
                    "model": "gpt-3.5-turbo",
                    "temperature": 0.3,
                    "max_tokens": 500,
                    "security_threshold": 0.7,
                    "scan_interval": 60
                },
                "logging": {
                    "level": "INFO",
                    "format": "JSON",
                    "file": "logs/dtm.json"
                },
                "ui": {
                    "refresh_rate": 4,
                    "items_per_page": 10,
                    "colors": {
                        "header": "blue",
                        "table": "cyan",
                        "analysis": "magenta"
                    }
                }
            }

    async def initialize(self):
        """Initialize all components."""
        try:
            # Initialize components
            await self.app_discovery.start_monitoring()
            await self.tunnel_manager.initialize()
            await self.port_nuker.start()
            await self.ai_analyzer.initialize()
            self.running = True
            self.logger.info("All components initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize: {str(e)}", exc_info=True)
            raise

    async def shutdown(self):
        """Shutdown all components."""
        self.running = False
        await self.app_discovery.stop()
        await self.tunnel_manager.shutdown()
        await self.port_nuker.stop()
        await self.ai_analyzer.shutdown()
        self.logger.info("Application shutdown complete")

    async def _handle_new_application(self, app_info):
        """Handle newly discovered application."""
        if not self.ui.config["auto_tunnel"]:
            return

        try:
            # Get port from port nuker
            tunnel_port = self.port_nuker.assign_port(app_info.pid)
            
            # Create tunnel
            await self.tunnel_manager.create_tunnel(
                pid=app_info.pid,
                local_port=tunnel_port,
                remote_host=app_info.remote_host or "localhost",
                remote_port=app_info.local_port
            )

            # Analyze with AI if enabled
            if self.ui.config["ai_analysis"]:
                analysis = await self.ai_analyzer.analyze_application(app_info)
                self.logger.info(f"AI Analysis for {app_info.name}: {analysis}")

        except Exception as e:
            self.logger.error(f"Failed to handle application {app_info.name}: {str(e)}")

    async def _update_ui(self):
        """Update UI with current state."""
        self.ui.update(
            apps=self.app_discovery.applications,
            tunnels=self.tunnel_manager.tunnels,
            ports=self.port_nuker.port_assignments,
            last_rotation=self.port_nuker.last_rotation
        )

    async def _handle_input(self):
        """Handle keyboard input."""
        while self.running:
            try:
                if keyboard.is_pressed('q'):
                    self.running = False
                elif keyboard.is_pressed('t'):
                    self.ui.handle_input('t')
                elif keyboard.is_pressed('a'):
                    self.ui.handle_input('a')
                elif keyboard.is_pressed('r'):
                    self.ui.handle_input('r')
                elif keyboard.is_pressed('p'):
                    self.ui.handle_input('p')
                elif keyboard.is_pressed('escape'):
                    self.ui.handle_input('escape')
                elif keyboard.is_pressed('up'):
                    self.ui.handle_input('up')
                elif keyboard.is_pressed('down'):
                    self.ui.handle_input('down')
                elif keyboard.is_pressed('backspace'):
                    self.ui.handle_input('backspace')
                elif keyboard.is_pressed('enter'):
                    self.ui.handle_input('enter')
                    if self.ui.selected_pid is not None:
                        await self._perform_ai_analysis(self.ui.selected_pid)
                # Handle number keys for PID selection
                for num in range(10):
                    if keyboard.is_pressed(str(num)):
                        self.ui.handle_input(str(num))
                        if self.ui.selected_pid is not None:
                            await self._perform_ai_analysis(self.ui.selected_pid)
                await asyncio.sleep(0.1)
            except Exception as e:
                self.logger.error(f"Error handling input: {str(e)}")

    async def _perform_ai_analysis(self, pid: int):
        """Perform AI analysis on a specific process."""
        try:
            if pid not in self.app_discovery.applications:
                self.logger.warning(f"PID {pid} not found in active applications")
                return

            app_info = self.app_discovery.applications[pid]
            analysis = await self.ai_analyzer.analyze_application(app_info)
            self.ui.add_analysis_result(pid, analysis)
            
        except Exception as e:
            self.logger.error(f"Failed to perform AI analysis on PID {pid}: {str(e)}")
            self.ui.add_analysis_result(pid, {
                "error": str(e),
                "recommendations": {
                    "risk_level": "unknown",
                    "concerns": ["Analysis failed"],
                    "recommendations": [f"Error: {str(e)}"],
                    "tunnel_policy": {
                        "should_tunnel": False,
                        "reason": "Analysis failed"
                    }
                }
            })

    async def _monitor_applications(self):
        """Monitor applications and create tunnels."""
        while self.running:
            try:
                # Get current applications
                current_apps = set(self.app_discovery.applications.keys())
                current_tunnels = set(self.tunnel_manager.tunnels.keys())

                # Handle new applications
                for pid in current_apps - current_tunnels:
                    if pid in self.app_discovery.applications:
                        await self._handle_new_application(self.app_discovery.applications[pid])

                # Remove stale tunnels
                for pid in current_tunnels - current_apps:
                    await self.tunnel_manager.remove_tunnel(pid)
                    self.port_nuker.release_port(pid)

                await asyncio.sleep(1)
            except Exception as e:
                self.logger.error(f"Error in application monitor: {str(e)}")

    async def run(self):
        """Run the main application loop."""
        try:
            await self.initialize()
            
            # Start all async tasks
            tasks = [
                asyncio.create_task(self._monitor_applications()),
                asyncio.create_task(self._handle_input()),
                asyncio.create_task(self.ui.run())
            ]

            # Wait for application to exit
            while self.running:
                await self._update_ui()
                await asyncio.sleep(0.25)

        except KeyboardInterrupt:
            self.logger.info("Received shutdown signal")
        except Exception as e:
            self.logger.error(f"Fatal error: {str(e)}", exc_info=True)
        finally:
            self.running = False
            await self.shutdown()
            for task in tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

async def main():
    """Main entry point."""
    # Setup logging
    setup_logging()
    
    # Create and run application
    app = DTMApplication()
    await app.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nApplication terminated by user") 