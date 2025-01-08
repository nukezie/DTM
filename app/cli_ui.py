"""
CLI UI Module
Provides a rich terminal user interface for the Dynamic Tunnel Manager.
"""

import asyncio
from typing import Dict, List, Optional
from datetime import datetime
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Console, Group
from rich.text import Text
from rich import box
from rich.align import Align
from app.discovery import ApplicationInfo
from app.tunnel_manager import TunnelInfo

class DTMUI:
    """Dynamic Tunnel Manager UI."""

    def __init__(self, config: dict):
        """
        Initialize the UI components.
        
        Args:
            config: Application configuration dictionary
        """
        self.console = Console()
        
        # Store configuration
        self.config = config
        
        # Initialize state variables
        self.active_apps: Dict[int, ApplicationInfo] = {}
        self.active_tunnels: Dict[int, TunnelInfo] = {}
        self.port_assignments: Dict[int, int] = {}
        self.last_rotation: Optional[datetime] = None
        
        # Scrolling state
        self.scroll_position = 0
        self.items_per_page = config["ui"]["items_per_page"]
        self.total_items = 0
        
        # AI Analysis state
        self.ai_analyses: Dict[int, Dict] = {}  # Store analysis results by PID
        self.selected_pid: Optional[int] = None  # Currently selected PID for analysis
        self.analysis_mode = False  # Whether we're in PID selection mode
        
        # Add PID input state
        self.pid_input = ""  # Store the PID as it's being typed
        
        # Initialize layout last
        self.layout = Layout()
        self._setup_layout()

    def _setup_layout(self):
        """Setup the layout structure."""
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=4),
            Layout(name="ai_section", size=12 if self.config["ai_analysis"]["enabled"] else 0)
        )

    def _generate_ai_section(self) -> Panel:
        """Generate the AI analysis section."""
        if not self.config["ai_analysis"]["enabled"]:
            return Panel("")  # Return empty panel if AI analysis is disabled
            
        # Create the analysis table
        table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED,
            expand=True,
            title="AI Security Analysis",
            title_style="bold magenta"
        )
        
        # Add columns
        table.add_column("PID", justify="right", style="cyan", width=8)
        table.add_column("Application", style="green", width=20)
        table.add_column("Risk Level", style="yellow", width=10)
        table.add_column("Concerns", width=30)
        table.add_column("Recommendations", width=30)
        table.add_column("Tunnel Policy", width=20)
        
        # Add analysis results
        for pid, analysis in self.ai_analyses.items():
            if pid in self.active_apps:
                app = self.active_apps[pid]
                recommendations = analysis.get("recommendations", {})
                
                # Format concerns and recommendations as bullet points
                concerns = "\n".join(f"• {c}" for c in recommendations.get("concerns", []))
                recs = "\n".join(f"• {r}" for r in recommendations.get("recommendations", []))
                
                tunnel_policy = recommendations.get("tunnel_policy", {})
                policy_text = f"{'✓' if tunnel_policy.get('should_tunnel') else '✗'} {tunnel_policy.get('reason', 'N/A')}"
                
                risk_level = recommendations.get("risk_level", "unknown")
                risk_style = {
                    "low": "green",
                    "medium": "yellow",
                    "high": "red"
                }.get(risk_level.lower(), "white")
                
                table.add_row(
                    str(pid),
                    app.name[:20],
                    Text(risk_level.upper(), style=risk_style),
                    concerns or "No concerns",
                    recs or "No recommendations",
                    Text(policy_text, style="cyan")
                )
        
        # Add instructions for analysis
        instructions = Text()
        if self.analysis_mode:
            instructions.append("\n[bold yellow]Enter PID to analyze (or ESC to cancel):[/]")
            if self.pid_input:
                instructions.append(f" [cyan]{self.pid_input}[/]")
            elif self.selected_pid:
                instructions.append(f" Analyzing PID {self.selected_pid}...")
        else:
            instructions.append("\n[bold cyan]Press [P] to analyze a specific process[/]")
            
        # Combine table and instructions in a panel
        return Panel(
            Group(table, instructions),
            title="AI Security Analysis",
            border_style="magenta",
            padding=(1, 2)
        )

    def _generate_header(self) -> Panel:
        """Generate the header panel."""
        title = Align.center(
            Group(
                Text("Dynamic Tunnel Manager", style="bold blue", justify="center"),
                Text("Secure Application Tunneling with Dynamic Port Rotation", 
                     style="italic cyan", justify="center")
            )
        )
        return Panel(title, box=box.ROUNDED, style="blue", padding=(0, 2))

    def _generate_apps_table(self) -> Table:
        """Generate the applications table."""
        # Get terminal dimensions
        term_height = self.console.height
        # Adjust items per page based on terminal height (accounting for headers and footers)
        self.items_per_page = max(5, term_height - 12)  # Minimum 5 items

        table = Table(
            show_header=True,
            header_style="bold cyan",
            box=box.ROUNDED,
            expand=True,
            row_styles=["none", "dim"],
            title="Active Applications",
            title_style="bold cyan",
            min_width=100
        )
        
        # Add columns
        table.add_column("PID", justify="right", style="cyan", width=8)
        table.add_column("Application", style="green", width=20)
        table.add_column("Original Port", justify="right", width=12)
        table.add_column("Tunnel Port", justify="right", style="magenta", width=12)
        table.add_column("Remote Host", width=15)
        table.add_column("Remote Port", justify="right", width=12)
        table.add_column("Status", width=12)
        table.add_column("Action", width=15)

        # Sort applications by PID for consistent display
        sorted_apps = sorted(self.active_apps.items(), key=lambda x: x[0])
        self.total_items = len(sorted_apps)

        # Calculate visible range
        start_idx = self.scroll_position
        end_idx = min(start_idx + self.items_per_page, len(sorted_apps))
        visible_apps = sorted_apps[start_idx:end_idx]

        for pid, app in visible_apps:
            tunnel_port = self.port_assignments.get(pid, "N/A")
            tunnel_active = pid in self.active_tunnels
            
            status_style = "green" if tunnel_active else "red"
            status = "🔒 Active" if tunnel_active else "⚪ Inactive"
            
            # Determine current action
            action = "None"
            action_style = "dim"
            if tunnel_active:
                if self.last_rotation and (datetime.now() - self.last_rotation).seconds < 1:
                    action = "🔄 Rotating"
                    action_style = "yellow"
                else:
                    action = "✓ Tunneled"
                    action_style = "green"
            elif self.config["auto_tunnel"]:
                action = "⏳ Pending"
                action_style = "yellow"

            table.add_row(
                str(pid),
                app.name[:20],  # Truncate long names
                str(app.local_port),
                str(tunnel_port),
                app.remote_host[:15] or "localhost",  # Truncate long hosts
                str(app.remote_port or "N/A"),
                Text(status, style=status_style),
                Text(action, style=action_style)
            )

        return table

    def _generate_footer(self) -> Panel:
        """Generate the footer panel with controls and scroll indicator."""
        controls = [
            ("↑/↓", "Scroll"),
            ("T", "Toggle Auto-Tunnel"),
            ("A", "Toggle AI Analysis"),
            ("P", "Analyze PID") if self.config["ai_analysis"]["enabled"] else None,
            ("R", "Force Port Rotation"),
            ("Q", "Quit")
        ]
        
        footer_text = Text()
        for control in controls:
            if control:  # Skip None values
                key, desc = control
                footer_text.append(f" [{key}] ", style="bold cyan")
                footer_text.append(f"{desc} ", style="dim")
                footer_text.append("|", style="dim")
        
        # Add scroll indicator
        if self.total_items > self.items_per_page:
            current_page = (self.scroll_position // self.items_per_page) + 1
            total_pages = (self.total_items + self.items_per_page - 1) // self.items_per_page
            footer_text.append(f"\nPage {current_page}/{total_pages} ", style="cyan")
            footer_text.append(f"(Showing {self.scroll_position + 1}-{min(self.scroll_position + self.items_per_page, self.total_items)} of {self.total_items})", style="dim")
        
        return Panel(
            Align.center(footer_text),
            box=box.ROUNDED,
            style="blue",
            padding=(0, 2)
        )

    def update(
        self,
        apps: Dict[int, ApplicationInfo],
        tunnels: Dict[int, TunnelInfo],
        ports: Dict[int, int],
        last_rotation: Optional[datetime]
    ):
        """Update the UI with new data."""
        self.active_apps = apps
        self.active_tunnels = tunnels
        self.port_assignments = ports
        self.last_rotation = last_rotation
        
        # Adjust scroll position if needed
        max_scroll = max(0, len(apps) - self.items_per_page)
        self.scroll_position = min(self.scroll_position, max_scroll)
        
        # Adjust layout based on AI analysis state
        self.layout["ai_section"].size = 12 if self.config["ai_analysis"]["enabled"] else 0
        self.layout["ai_section"].visible = self.config["ai_analysis"]["enabled"]

    def add_analysis_result(self, pid: int, analysis: Dict):
        """Add or update an AI analysis result."""
        self.ai_analyses[pid] = analysis
        self.selected_pid = None  # Reset selection
        self.analysis_mode = False  # Exit analysis mode

    def handle_input(self, key: str) -> bool:
        """
        Handle user input.

        Args:
            key: The key pressed by the user

        Returns:
            bool: True if the application should continue, False to quit
        """
        key = key.lower()
        
        # Handle PID selection mode
        if self.analysis_mode:
            if key == 'escape':
                self.analysis_mode = False
                self.selected_pid = None
                self.pid_input = ""  # Clear input
                return True
            
            if key.isdigit():
                self.pid_input += key
                if len(self.pid_input) >= 5:  # Reasonable max PID length
                    self.selected_pid = int(self.pid_input)
                    self.pid_input = ""  # Clear input
                return True
            
            if key == 'backspace' and self.pid_input:
                self.pid_input = self.pid_input[:-1]  # Remove last character
                return True
            
            if key == 'enter' and self.pid_input:
                self.selected_pid = int(self.pid_input)
                self.pid_input = ""  # Clear input
                return True
                
        # Normal input handling
        if key == 'q':
            return False
        elif key == 't':
            self.config["auto_tunnel"] = not self.config["auto_tunnel"]
        elif key == 'a':
            self.config["ai_analysis"]["enabled"] = not self.config["ai_analysis"]["enabled"]
            self.layout["ai_section"].size = 12 if self.config["ai_analysis"]["enabled"] else 0
            self.layout["ai_section"].visible = self.config["ai_analysis"]["enabled"]
        elif key == 'p' and self.config["ai_analysis"]["enabled"]:
            self.analysis_mode = True
            self.selected_pid = None
        elif key == 'r':
            self.last_rotation = None
        elif key == 'up':
            self.scroll_position = max(0, self.scroll_position - 1)
        elif key == 'down':
            max_scroll = max(0, self.total_items - self.items_per_page)
            self.scroll_position = min(max_scroll, self.scroll_position + 1)
        
        return True

    async def run(self):
        """Run the UI update loop."""
        with Live(
            self.layout,
            refresh_per_second=4,
            screen=True,
            console=self.console,
            auto_refresh=True
        ) as live:
            try:
                while True:
                    # Update layout components
                    self.layout["header"].update(self._generate_header())
                    self.layout["main"].update(self._generate_apps_table())
                    self.layout["footer"].update(self._generate_footer())
                    self.layout["ai_section"].update(self._generate_ai_section())
                    
                    await asyncio.sleep(0.25)
            except Exception as e:
                self.console.print(f"[red]Error in UI: {str(e)}[/red]") 