"""
AI Analysis Module
Provides AI-driven analysis and recommendations for application behavior.
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
from openai import AsyncOpenAI
from app.discovery import ApplicationInfo

class AIAnalyzer:
    """AI-driven application analyzer."""
    
    def __init__(self, api_key: str):
        """
        Initialize the AI analyzer.
        
        Args:
            api_key: OpenAI API key
        """
        self.logger = logging.getLogger(__name__)
        self.client = AsyncOpenAI(api_key=api_key)
        self.running = False
        
    async def initialize(self):
        """Initialize the AI analyzer."""
        try:
            self.running = True
            self.logger.info("AI Analyzer initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize AI Analyzer: {str(e)}", exc_info=True)
            raise
            
    async def shutdown(self):
        """Shutdown the AI analyzer."""
        try:
            self.running = False
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
                "status": "running"
            }
        }
        
    async def _get_ai_recommendations(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get AI recommendations for the application."""
        try:
            prompt = self._create_analysis_prompt(context)
            
            # Use GPT-4 with the latest API format
            response = await self.client.chat.completions.create(
                model="gpt-4",  # Use GPT-4 instead of GPT-3.5
                messages=[
                    {
                        "role": "system",
                        "content": """You are a security-focused application analyzer specializing in network security.
                        Analyze network connections and provide detailed security recommendations.
                        Focus on potential security risks, network behavior patterns, and best practices for secure tunneling.
                        You must respond with ONLY a valid JSON object with no additional text, using this exact structure:
                        {
                            "risk_level": "low|medium|high",
                            "concerns": ["list", "of", "concerns"],
                            "recommendations": ["list", "of", "recommendations"],
                            "tunnel_policy": {
                                "should_tunnel": true|false,
                                "reason": "explanation"
                            }
                        }"""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,  # Lower temperature for more consistent responses
                max_tokens=1000   # Increased token limit for more detailed analysis
            )
            
            # Extract recommendations from response
            if response and hasattr(response.choices[0].message, 'content'):
                try:
                    # Parse the JSON response
                    recommendations = json.loads(response.choices[0].message.content)
                    
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
        return f"""
        Analyze this application's network behavior and provide security recommendations.
        
        Application Details:
        - Name: {context['app_name']}
        - PID: {context['pid']}
        - Local Port: {context['local_port']}
        - Remote Host: {context['remote_host'] or 'localhost'}
        - Remote Port: {context['remote_port']}
        - Created At: {context.get('created_at', 'Unknown')}
        
        Provide a comprehensive security analysis in the following JSON structure:
        {{
            "risk_level": "low|medium|high",
            "concerns": [
                "List of specific security concerns",
                "Include potential vulnerabilities",
                "Network security risks"
            ],
            "recommendations": [
                "Detailed security recommendations",
                "Best practices for tunneling",
                "Specific mitigation strategies"
            ],
            "tunnel_policy": {{
                "should_tunnel": true|false,
                "reason": "Detailed explanation of tunneling decision"
            }}
        }}
        
        Consider:
        1. Network exposure and potential risks
        2. Common attack vectors
        3. Best practices for secure tunneling
        4. Process behavior and security implications
        5. Port security considerations
        """ 