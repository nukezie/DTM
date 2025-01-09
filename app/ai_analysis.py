"""
AI Analysis Module
Provides AI-driven analysis and recommendations for application behavior.
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
import httpx
from app.discovery import ApplicationInfo

class AIAnalyzer:
    """AI-driven application analyzer."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the AI analyzer.
        
        Args:
            config: Application configuration dictionary containing OpenRouter settings
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.api_key = config["openrouter"]["api_key"]
        self.base_url = config["openrouter"]["base_url"]
        self.model = config["openrouter"]["model"]
        self.fallback_model = config["openrouter"]["fallback_model"]
        
        # Initialize HTTP client with OpenRouter headers
        self.http_client = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {self.api_key}",
                **config["ai_analysis"]["headers"]
            },
            timeout=30.0  # Set default timeout
        )
        self.running = False
        
    async def initialize(self):
        """Initialize the AI analyzer."""
        try:
            self.running = True
            self.logger.info(f"AI Analyzer initialized with OpenRouter using model: {self.model}")
        except Exception as e:
            self.logger.error(f"Failed to initialize AI Analyzer: {str(e)}", exc_info=True)
            raise
            
    async def shutdown(self):
        """Shutdown the AI analyzer."""
        try:
            self.running = False
            await self.http_client.aclose()
            self.logger.info("AI Analyzer shutdown complete")
        except Exception as e:
            self.logger.error(f"Failed to shutdown AI Analyzer: {str(e)}", exc_info=True)
        
    async def analyze_application(self, app_info: ApplicationInfo) -> Dict[str, Any]:
        """
        Analyze an application using AI.
        
        Args:
            app_info: Application information to analyze
            
        Returns:
            Dict containing analysis results
        """
        if not self.running:
            self.logger.warning("AI Analyzer not initialized")
            return {
                "analysis_timestamp": datetime.now().isoformat(),
                "app_info": self._create_analysis_context(app_info),
                "recommendations": {},
                "error": "AI Analyzer not initialized"
            }
            
        try:
            context = self._create_analysis_context(app_info)
            recommendations = await self._get_ai_recommendations(context)
            
            analysis = {
                "analysis_timestamp": datetime.now().isoformat(),
                "app_info": context,
                "recommendations": recommendations
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Failed to analyze application: {str(e)}", exc_info=True)
            return {
                "analysis_timestamp": datetime.now().isoformat(),
                "app_info": self._create_analysis_context(app_info),
                "recommendations": {},
                "error": str(e)
            }
    
    def _create_analysis_context(self, app_info: ApplicationInfo) -> Dict[str, Any]:
        """Create context dictionary for AI analysis."""
        # Get DTM state information
        dtm_state = getattr(app_info, 'dtm_state', {})
        is_tunneled = dtm_state.get('is_tunneled', False)
        tunnel_port = dtm_state.get('tunnel_port')
        auto_tunnel = dtm_state.get('auto_tunnel', False)
        last_rotation = dtm_state.get('last_rotation')
        
        return {
            "app_name": app_info.name,
            "pid": app_info.pid,
            "local_port": app_info.local_port,
            "remote_host": app_info.remote_host,
            "remote_port": app_info.remote_port,
            "created_at": app_info.created_at.isoformat() if hasattr(app_info, 'created_at') else None,
            "process_info": {
                "name": app_info.name,
                "pid": app_info.pid,
                "status": "running",
                "is_system_process": app_info.name.lower() in ["system", "services.exe", "svchost.exe"],
                "is_known_process": self._is_known_process(app_info.name)
            },
            "dtm_state": {
                "is_tunneled": is_tunneled,
                "tunnel_port": tunnel_port,
                "auto_tunnel_enabled": auto_tunnel,
                "last_rotation": last_rotation.isoformat() if last_rotation else None,
                "tunnel_status": "active" if is_tunneled else "inactive"
            }
        }
        
    def _is_known_process(self, process_name: str) -> bool:
        """Check if the process is a known application."""
        known_processes = {
            # Web Servers
            "nginx.exe", "apache.exe", "httpd.exe", "tomcat.exe", "iis.exe",
            # Databases
            "mysqld.exe", "postgres.exe", "oracle.exe", "mongodb.exe", "redis-server.exe",
            # Development
            "node.exe", "python.exe", "java.exe", "ruby.exe", "php.exe",
            # Applications
            "chrome.exe", "firefox.exe", "msedge.exe", "outlook.exe", "teams.exe",
            # Game Servers
            "srcds.exe", "bedrock_server.exe", "java.exe",  # Minecraft uses java
            # Common Services
            "services.exe", "svchost.exe", "lsass.exe",
            # Remote Access
            "mstsc.exe", "rdpclip.exe", "ssh.exe", "putty.exe"
        }
        return process_name.lower() in known_processes
        
    async def _get_ai_recommendations(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get AI recommendations for the application."""
        try:
            prompt = self._create_analysis_prompt(context)
            
            # Use OpenRouter API with configured model
            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": """You are a security-focused application analyzer for the Dynamic Tunnel Manager (DTM).

DTM Context:
- DTM is a security tool that creates dynamic SSL/TLS tunnels for applications
- It automatically detects applications that need secure tunneling
- The goal is to protect sensitive network traffic by encrypting it through secure tunnels
- When an application is detected, DTM can create an encrypted tunnel to protect its traffic
- DTM uses port rotation and dynamic assignment for enhanced security
- Local connections (localhost) are NORMAL when a tunnel is active, as traffic is being routed through DTM

Your Role:
- Analyze network connections and provide security recommendations
- Determine if an application needs tunnel protection based on its network behavior
- Consider both security risks and the benefits of tunneling
- Provide specific, actionable recommendations for secure tunneling
- Focus on potential security risks and best practices

Key Analysis Points:
1. If an application is already tunneled, focus on monitoring and optimization
2. For untunneled applications, evaluate the need for protection
3. Consider the application type (system process, known application, or unknown)
4. Evaluate the security implications of the current connection state
5. Provide specific recommendations based on the application's role
6. Consider port rotation strategies for enhanced security

You must respond with ONLY a valid JSON object with no additional text, using this exact structure:
{
    "risk_level": "low|medium|high",
    "concerns": [
        "Detailed list of security concerns",
        "Include specific vulnerabilities",
        "Network security risks"
    ],
    "recommendations": [
        "Specific security recommendations",
        "Best practices for tunneling",
        "Detailed mitigation strategies"
    ],
    "tunnel_policy": {
        "should_tunnel": true|false,
        "reason": "Detailed explanation of tunneling decision, considering current state"
    }
}"""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": self.config["ai_analysis"]["temperature"],
                "max_tokens": self.config["ai_analysis"]["max_tokens"]
            }
            
            try:
                response = await self.http_client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload
                )
                response.raise_for_status()
                response_data = response.json()
            except httpx.ReadTimeout:
                self.logger.warning(f"Timeout with primary model {self.model}, falling back to {self.fallback_model}")
                payload["model"] = self.fallback_model
                response = await self.http_client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload
                )
                response.raise_for_status()
                response_data = response.json()
            
            # Extract recommendations from response
            if response_data and "choices" in response_data and response_data["choices"]:
                try:
                    # Parse the JSON response
                    recommendations = json.loads(response_data["choices"][0]["message"]["content"])
                    
                    # Validate response structure
                    required_keys = ["risk_level", "concerns", "recommendations", "tunnel_policy"]
                    if not all(key in recommendations for key in required_keys):
                        raise ValueError("Missing required fields in AI response")
                    
                    if not isinstance(recommendations["concerns"], list):
                        recommendations["concerns"] = [recommendations["concerns"]]
                    
                    if not isinstance(recommendations["recommendations"], list):
                        recommendations["recommendations"] = [recommendations["recommendations"]]
                    
                    if not isinstance(recommendations["tunnel_policy"], dict):
                        raise ValueError("Invalid tunnel_policy format in AI response")
                    
                    return recommendations
                    
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse AI response: {str(e)}")
                    return {
                        "risk_level": "unknown",
                        "concerns": ["Failed to parse AI response"],
                        "recommendations": ["Error: Invalid response format"],
                        "tunnel_policy": {
                            "should_tunnel": False,
                            "reason": "Analysis failed - invalid response format"
                        }
                    }
            else:
                self.logger.error("No valid response content from AI")
                return {
                    "risk_level": "unknown",
                    "concerns": ["No response from AI"],
                    "recommendations": ["Error: No analysis available"],
                    "tunnel_policy": {
                        "should_tunnel": False,
                        "reason": "Analysis failed - no response"
                    }
                }
            
        except Exception as e:
            self.logger.error(f"Failed to get AI recommendations: {str(e)}", exc_info=True)
            return {
                "risk_level": "unknown",
                "concerns": [f"Analysis error: {str(e)}"],
                "recommendations": ["Error: Analysis failed"],
                "tunnel_policy": {
                    "should_tunnel": False,
                    "reason": f"Analysis failed: {str(e)}"
                }
            }
            
    def _create_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """Create the analysis prompt for the AI."""
        dtm_state = context["dtm_state"]
        tunnel_status = "ACTIVE" if dtm_state["is_tunneled"] else "INACTIVE"
        process_type = (
            "System Process" if context["process_info"]["is_system_process"]
            else "Known Application" if context["process_info"]["is_known_process"]
            else "Unknown Application"
        )
        
        return f"""
        Analyze this application's network behavior and provide security recommendations in the context of DTM's tunneling capabilities.
        
        Application Details:
        - Name: {context['app_name']} ({process_type})
        - PID: {context['pid']}
        - Local Port: {context['local_port']}
        - Remote Host: {context['remote_host'] or 'localhost'}
        - Remote Port: {context['remote_port']}
        - Created At: {context.get('created_at', 'Unknown')}
        
        DTM Status:
        - Tunnel Status: {tunnel_status}
        - Tunnel Port: {dtm_state['tunnel_port'] or 'N/A'}
        - Auto-Tunnel: {'Enabled' if dtm_state['auto_tunnel_enabled'] else 'Disabled'}
        - Last Port Rotation: {dtm_state['last_rotation'] or 'Never'}
        
        Process Information:
        - Type: {process_type}
        - Status: {context['process_info']['status']}
        
        Consider:
        1. Current DTM Status: {tunnel_status}
           - If ACTIVE: Focus on monitoring, optimization, and current security state
           - If INACTIVE: Evaluate need for protection based on current traffic patterns
        
        2. Process Type: {process_type}
           - System Process: Consider critical system functionality and security implications
           - Known Application: Apply best practices for the specific application type
           - Unknown Application: Evaluate based on network behavior and security needs
        
        3. Connection Analysis:
           - Original Port: {context['local_port']} → {context['remote_port']}
           {f'- Tunneled Port: {dtm_state["tunnel_port"]}' if tunnel_status == "ACTIVE" else ''}
           - Remote Connection: {context['remote_host'] or 'localhost'}
           - Traffic Patterns and Security Implications
        
        4. Security Considerations:
           - Current Protection Status
           - Port Rotation Strategy
           - Tunnel Configuration Optimization
           - Monitoring Requirements
           - Risk Mitigation Strategies
        
        Provide a comprehensive security analysis that addresses:
        1. Current security state with DTM {'enabled' if tunnel_status == "ACTIVE" else 'disabled'}
        2. Specific recommendations based on the application type and current state
        3. Whether current tunnel configuration is optimal (if active)
        4. Additional security measures needed
        """ 
