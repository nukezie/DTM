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
        
        # Set AI analysis to disabled by default
        self.config["ai_analysis"]["enabled"] = False
        
        # Initialize state variables
        self.active_apps: Dict[int, ApplicationInfo] = {}
        self.active_tunnels: Dict[int, TunnelInfo] = {}
        self.port_assignments: Dict[int, int] = {}
        self.last_rotation: Optional[datetime] = None
        
        # Scrolling state for main process list
        self.scroll_position = 0
        self.items_per_page = config["ui"]["items_per_page"]
        self.total_items = 0
        
        # AI Analysis state
        self.ai_analyses: Dict[int, Dict] = {}
        self.selected_pid: Optional[int] = None
        self.related_pids: List[int] = []  # Store related PIDs for group analysis
        self.analysis_mode = False
        self.pid_input = ""
        self.input_error = ""
        
        # Adjust AI section size and scrolling
        self.ai_section_size = 15
        self.ai_scroll_position = 0
        self.ai_items_per_page = 4
        self.focus_ai_section = False
        
        # Initialize layout
        self.layout = Layout()
        self._setup_layout()
        
        # Add view state
        self.current_view = "main"  # "main" or "ai"
        
        # PID selection state
        self.available_pids = []
        self.pid_selection_index = 0

    def _setup_layout(self):
        """Setup the layout structure."""
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=4)
        )

    def _generate_ai_section(self) -> Panel:
        """Generate the AI analysis section."""
        # Create the analysis table
        table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED,
            expand=True,
            title="AI Security Analysis",
            title_style="bold magenta",
            show_lines=True,
            padding=(0, 1),
            width=None  # Allow table to expand
        )
        
        # Add columns with adjusted widths
        table.add_column("PID(s)", justify="right", style="cyan", width=12)  # Increased width for multiple PIDs
        table.add_column("Application", style="green", width=15)
        table.add_column("Risk Level", style="yellow", width=8)
        table.add_column("Concerns", width=None, ratio=2, overflow="fold")
        table.add_column("Recommendations", width=None, ratio=2, overflow="fold")
        table.add_column("Tunnel Policy", width=None, ratio=1, overflow="fold")
        
        # Group analyses by application name
        app_analyses = {}
        for pid, analysis in self.ai_analyses.items():
            if pid in self.active_apps:
                app_name = self.active_apps[pid].name
                if app_name not in app_analyses:
                    app_analyses[app_name] = {"pids": [], "analysis": analysis}
                app_analyses[app_name]["pids"].append(pid)
        
        # Sort by application name
        sorted_analyses = sorted(app_analyses.items(), key=lambda x: x[0])
        
        # Ensure scroll position is within bounds
        max_scroll = max(0, len(sorted_analyses) - self.ai_items_per_page)
        self.ai_scroll_position = min(max_scroll, self.ai_scroll_position)
        
        # Calculate visible range for AI analysis
        start_idx = self.ai_scroll_position
        end_idx = min(start_idx + self.ai_items_per_page, len(sorted_analyses))
        visible_analyses = sorted_analyses[start_idx:end_idx]
        
        if not sorted_analyses:
            table.add_row(
                "",
                "No analyses yet",
                "",
                "Press P to analyze a process",
                "",
                ""
            )
        else:
            # Add analysis results
            for app_name, data in visible_analyses:
                pids = data["pids"]
                analysis = data["analysis"]
                recommendations = analysis.get("recommendations", {})
                
                # Format PIDs as comma-separated list
                pid_text = ", ".join(str(pid) for pid in sorted(pids))
                
                # Format concerns and recommendations as bullet points with proper wrapping
                concerns = "\n".join(
                    "• " + c.strip().replace("\n", " ")
                    for c in recommendations.get("concerns", [])
                )
                
                recs = "\n".join(
                    "• " + r.strip().replace("\n", " ")
                    for r in recommendations.get("recommendations", [])
                )
                
                tunnel_policy = recommendations.get("tunnel_policy", {})
                policy_text = (
                    f"{'✓' if tunnel_policy.get('should_tunnel') else '✗'} "
                    f"{tunnel_policy.get('reason', 'N/A')}"
                ).replace("\n", " ")
                
                risk_level = recommendations.get("risk_level", "unknown")
                risk_style = {
                    "low": "green",
                    "medium": "yellow",
                    "high": "red"
                }.get(risk_level.lower(), "white")
                
                table.add_row(
                    pid_text,
                    app_name[:15],
                    Text(risk_level.upper(), style=risk_style),
                    Text(concerns or "No concerns"),
                    Text(recs or "No recommendations"),
                    Text(policy_text, style="cyan")
                )
        
        # Add scroll indicator and controls
        controls = Text()
        if len(sorted_analyses) > self.ai_items_per_page:
            current_page = (self.ai_scroll_position // self.ai_items_per_page) + 1
            total_pages = (len(sorted_analyses) + self.ai_items_per_page - 1) // self.ai_items_per_page
            
            # Add scroll position indicator
            scroll_indicator = "↑ " if self.ai_scroll_position > 0 else "  "
            scroll_indicator += "↓" if self.ai_scroll_position < max_scroll else " "
            
            controls.append(f"{scroll_indicator} ", style="bold cyan")
            controls.append(f"Page {current_page}/{total_pages} ", style="cyan")
            controls.append(f"(Showing {start_idx + 1}-{end_idx} of {len(sorted_analyses)})", style="dim")
        
        # Add instructions
        instructions = Text("\nPress [P] to analyze a process", style="cyan bold")
        
        return Panel(
            Group(
                table,
                Align.center(controls),
                Align.center(instructions)
            ),
            title="AI Security Analysis",
            border_style="magenta",
            padding=(0, 1),
            height=self.ai_section_size
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

        # Add focus indicator to the title
        focus_indicator = "" if self.focus_ai_section else "[bold cyan]▶[/] "
        table.title = f"{focus_indicator}Active Applications"

        return table

    def _generate_footer(self) -> Panel:
        """Generate the footer panel with controls and scroll indicator."""
        if self.current_view == "main":
            controls = [
                ("↑/↓", "Scroll"),
                ("T", "Toggle Auto-Tunnel"),
                ("→", "Switch to AI Analysis"),
                ("R", "Force Port Rotation"),
                ("Q", "Quit")
            ]
        else:  # AI Analysis view
            controls = [
                ("↑/↓", "Scroll Analysis"),
                ("←", "Switch to Main View"),
                ("P", "Analyze PID"),
                ("ESC", "Cancel Input"),
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
        if self.current_view == "main" and self.total_items > self.items_per_page:
            current_page = (self.scroll_position // self.items_per_page) + 1
            total_pages = (self.total_items + self.items_per_page - 1) // self.items_per_page
            footer_text.append(f"\nPage {current_page}/{total_pages} ", style="cyan")
            footer_text.append(f"(Showing {self.scroll_position + 1}-{min(self.scroll_position + self.items_per_page, self.total_items)} of {self.total_items})", style="dim")
        elif self.current_view == "ai" and len(self.ai_analyses) > self.ai_items_per_page:
            current_page = (self.ai_scroll_position // self.ai_items_per_page) + 1
            total_pages = (len(self.ai_analyses) + self.ai_items_per_page - 1) // self.ai_items_per_page
            footer_text.append(f"\nPage {current_page}/{total_pages} ", style="cyan")
            footer_text.append(f"(Showing {self.ai_scroll_position + 1}-{min(self.ai_scroll_position + self.ai_items_per_page, len(self.ai_analyses))} of {len(self.ai_analyses)})", style="dim")
        
        return Panel(
            Align.center(footer_text),
            box=box.ROUNDED,
            style="blue",
            padding=(0, 2)
        )

    def _generate_pid_selection(self) -> Panel:
        """Generate the PID selection panel."""
        table = Table(
            show_header=True,
            header_style="bold cyan",
            box=box.ROUNDED,
            expand=True,
            title="Available Processes",
            show_lines=True
        )
        
        table.add_column("PID", justify="right", style="cyan", width=8)
        table.add_column("Application", style="green", width=30)
        table.add_column("Port", justify="right", width=10)
        table.add_column("Status", width=15)
        
        # Sort processes by PID
        sorted_apps = sorted(
            [(pid, app) for pid, app in self.active_apps.items()],
            key=lambda x: x[0]
        )
        self.available_pids = [pid for pid, _ in sorted_apps]
        
        # Calculate pagination
        items_per_page = 11  # Number of items to show per page
        total_pages = (len(sorted_apps) + items_per_page - 1) // items_per_page
        current_page = self.pid_selection_index // items_per_page
        
        # Calculate visible range for current page
        start_idx = current_page * items_per_page
        end_idx = min(start_idx + items_per_page, len(sorted_apps))
        visible_apps = sorted_apps[start_idx:end_idx]
        
        # Calculate relative selection index within current page
        relative_index = self.pid_selection_index % items_per_page
        
        for i, (pid, app) in enumerate(visible_apps):
            is_selected = i == relative_index
            row_style = "bold magenta" if is_selected else None
            
            table.add_row(
                Text(str(pid), style=row_style),
                Text(app.name[:30], style=row_style),
                Text(str(app.local_port), style=row_style),
                Text("Analyzed" if pid in self.ai_analyses else "Not Analyzed", style=row_style)
            )
        
        # Add page indicator
        page_info = Text()
        if total_pages > 1:
            page_info.append(f"\nPage {current_page + 1}/{total_pages} ", style="cyan")
            page_info.append(f"(Showing {start_idx + 1}-{end_idx} of {len(sorted_apps)})", style="dim")
        
        instructions = Text()
        instructions.append("\n↑/↓ to select, ENTER to confirm, ESC to cancel", style="cyan")
        
        return Panel(
            Group(
                table,
                Align.center(page_info),
                Align.center(instructions)
            ),
            title="Select Process for Analysis",
            border_style="magenta",
            padding=(1, 2)
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
        self.total_items = len(apps)  # Update total items count
        
        # Adjust scroll positions if needed
        if not self.focus_ai_section:
            max_scroll = max(0, self.total_items - self.items_per_page)
            self.scroll_position = min(self.scroll_position, max_scroll)
        else:
            max_ai_scroll = max(0, len(self.ai_analyses) - self.ai_items_per_page)
            self.ai_scroll_position = min(self.ai_scroll_position, max_ai_scroll)

    def add_analysis_result(self, pid: int, analysis: Dict):
        """
        Add or update AI analysis results.
        
        Args:
            pid: The primary PID that was analyzed
            analysis: The analysis results to store
        """
        # Store the analysis for the primary PID
        self.ai_analyses[pid] = analysis
        
        # If there are related PIDs, store the same analysis for them
        if hasattr(self, 'related_pids') and self.related_pids:
            for related_pid in self.related_pids:
                if related_pid != pid:  # Skip the primary PID as it's already stored
                    self.ai_analyses[related_pid] = analysis
            
        self.selected_pid = None  # Reset selection
        self.related_pids = []    # Reset related PIDs
        self.analysis_mode = False  # Exit analysis mode

    def handle_input(self, key: str) -> bool:
        """Handle keyboard input."""
        if self.analysis_mode:
            items_per_page = 11
            total_items = len(self.available_pids)
            
            if key == 'escape':
                self.analysis_mode = False
                self.pid_input = ""
                self.input_error = ""
                self.pid_selection_index = 0
                return True
            
            if key == 'up':
                if self.pid_selection_index > 0:
                    self.pid_selection_index -= 1
                return True
            
            if key == 'down':
                if self.pid_selection_index < total_items - 1:
                    self.pid_selection_index += 1
                    # If we've moved past the current page, the _generate_pid_selection
                    # method will automatically adjust the view
                return True
            
            if key == 'enter' and self.available_pids:
                selected_pid = self.available_pids[self.pid_selection_index]
                selected_app_name = self.active_apps[selected_pid].name
                # Find all PIDs with the same application name
                self.selected_pid = selected_pid  # Store the primary PID
                self.related_pids = [  # Store related PIDs separately
                    pid for pid, app in self.active_apps.items()
                    if app.name == selected_app_name
                ]
                self.analysis_mode = False
                return True
                
        else:
            if key == 'q':
                return False
            elif key == 't' and self.current_view == "main":
                self.config["auto_tunnel"] = not self.config["auto_tunnel"]
            elif key == 'right':  # Right arrow to go to AI view
                if self.current_view == "main":
                    self.current_view = "ai"
                    self.ai_scroll_position = 0  # Reset scroll position when switching views
            elif key == 'left':  # Left arrow to go back to main view
                if self.current_view == "ai":
                    self.current_view = "main"
                    self.scroll_position = 0  # Reset scroll position when switching views
            elif key == 'p' and self.current_view == "ai":
                self.analysis_mode = True
                self.selected_pid = None
                self.related_pids = []
                self.pid_selection_index = 0
            elif key == 'r' and self.current_view == "main":
                self.last_rotation = None
            elif key == 'up':
                if self.current_view == "main":
                    if self.scroll_position > 0:
                        self.scroll_position -= 1
                else:  # AI view
                    if self.ai_scroll_position > 0:
                        self.ai_scroll_position -= 1
            elif key == 'down':
                if self.current_view == "main":
                    max_scroll = max(0, self.total_items - self.items_per_page)
                    if self.scroll_position < max_scroll:
                        self.scroll_position += 1
                else:  # AI view
                    max_scroll = max(0, len(self.ai_analyses) - self.ai_items_per_page)
                    if self.ai_scroll_position < max_scroll:
                        self.ai_scroll_position += 1
        
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
                    
                    if self.current_view == "main":
                        self.layout["main"].update(self._generate_apps_table())
                    else:  # AI view
                        if self.analysis_mode:
                            self.layout["main"].update(self._generate_pid_selection())
                        else:
                            self.layout["main"].update(self._generate_ai_section())
                    
                    self.layout["footer"].update(self._generate_footer())
                    
                    await asyncio.sleep(0.25)
            except Exception as e:
                self.console.print(f"[red]Error in UI: {str(e)}[/red]") 
