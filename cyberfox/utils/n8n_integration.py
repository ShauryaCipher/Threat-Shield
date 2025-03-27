"""
Integration with n8n.io for workflow automation.
"""
import json
import logging
import requests
from typing import Dict, Any, Optional

from cyberfox.config import CONFIG
from cyberfox.core.threats import (
    Threat, FileThreat, DarkWebThreat, DataBreachThreat, 
    BrowserThreat, ThreatType, ThreatLevel
)

logger = logging.getLogger(__name__)

class N8NIntegration:
    """Integration with n8n.io workflows."""
    
    def __init__(self):
        """Initialize the n8n integration."""
        self.config = CONFIG["n8n_integration"]
        
    def is_enabled(self) -> bool:
        """
        Check if n8n integration is enabled.
        
        Returns:
            Boolean indicating if integration is enabled
        """
        return self.config["enabled"] and self.config["url"] and self.config["workflow_id"]
        
    def get_webhook_url(self) -> str:
        """
        Get the webhook URL for n8n integration.
        
        Returns:
            Webhook URL
        """
        base_url = self.config["url"].rstrip("/")
        workflow_id = self.config["workflow_id"]
        
        # Check if URL already contains the workflow ID
        if workflow_id in base_url:
            return base_url
            
        # Otherwise, add the workflow ID to the URL
        return f"{base_url}/{workflow_id}"
        
    def serialize_threat(self, threat: Threat) -> Dict[str, Any]:
        """
        Serialize a threat object for sending to n8n.
        
        Args:
            threat: Threat object to serialize
            
        Returns:
            Dictionary representation of the threat
        """
        # Common fields for all threats
        result = {
            "type": threat.type.value,
            "level": threat.level.value,
            "description": threat.description,
            "timestamp": threat.timestamp.isoformat() if threat.timestamp else None,
            "source": threat.source,
            "details": threat.details,
        }
        
        # Add specific fields based on threat type
        if isinstance(threat, FileThreat):
            result["threat_category"] = "file"
            result["filepath"] = threat.filepath
            result["hash"] = threat.hash
            result["file_size"] = threat.file_size
            
        elif isinstance(threat, DarkWebThreat):
            result["threat_category"] = "darkweb"
            result["keywords"] = threat.keywords
            result["url"] = threat.url
            result["content_snippet"] = threat.content_snippet
            
        elif isinstance(threat, DataBreachThreat):
            result["threat_category"] = "databreach"
            result["email"] = threat.email
            result["breach_name"] = threat.breach_name
            result["breach_date"] = threat.breach_date.isoformat() if threat.breach_date else None
            result["pwned_data"] = threat.pwned_data
            
        elif isinstance(threat, BrowserThreat):
            result["threat_category"] = "browser"
            result["browser"] = threat.browser
            result["threat_source"] = threat.threat_source
            result["url"] = threat.url
            
        return result
        
    def send_threat(self, threat: Threat) -> bool:
        """
        Send a threat to n8n via webhook.
        
        Args:
            threat: Threat to send
            
        Returns:
            Boolean indicating success
        """
        if not self.is_enabled():
            logger.debug("n8n integration not enabled, skipping webhook")
            return False
            
        webhook_url = self.get_webhook_url()
        logger.debug(f"Sending threat to n8n webhook at: {webhook_url}")
        
        try:
            # Serialize the threat data
            threat_data = self.serialize_threat(threat)
            
            # Add metadata
            payload = {
                "event": "threat_detected",
                "application": "CyberFox",
                "version": __import__('cyberfox').config.APP_VERSION,
                "timestamp": __import__('datetime').datetime.now().isoformat(),
                "threat": threat_data
            }
            
            # Send the request
            response = requests.post(
                webhook_url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "CyberFox-ThreatDetection",
                    "X-CyberFox-Threat-Type": threat.type.value,
                    "X-CyberFox-Threat-Level": threat.level.value
                },
                timeout=10
            )
            
            if response.status_code < 400:
                logger.info(f"Successfully sent threat to n8n: {response.status_code}")
                # Try to parse any response data from n8n for additional processing
                try:
                    response_data = response.json()
                    if response_data and 'success' in response_data:
                        logger.debug(f"n8n workflow response: {response_data}")
                except Exception:
                    # Not all n8n workflows return JSON, so this is optional
                    pass
                return True
            else:
                logger.error(f"Failed to send threat to n8n. Status: {response.status_code}, Response: {response.text}")
                return False
                
        except requests.exceptions.ConnectTimeout:
            logger.error(f"Connection timeout when connecting to n8n webhook at {webhook_url}")
            return False
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error when connecting to n8n webhook at {webhook_url}")
            return False
        except Exception as e:
            logger.error(f"Error sending threat to n8n: {str(e)}")
            return False
            
    def test_connection(self) -> bool:
        """
        Test the connection to n8n.
        
        Returns:
            Boolean indicating if the test was successful
        """
        if not self.is_enabled():
            logger.warning("n8n integration not enabled")
            return False
            
        webhook_url = self.get_webhook_url()
        logger.debug(f"Testing connection to n8n webhook at: {webhook_url}")
        
        try:
            # Create a test payload
            payload = {
                "event": "connection_test",
                "application": "CyberFox",
                "version": __import__('cyberfox').config.APP_VERSION,
                "timestamp": __import__('datetime').datetime.now().isoformat(),
                "test_data": {
                    "source": "CyberFox Connection Test"
                }
            }
            
            # Send the request
            response = requests.post(
                webhook_url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "CyberFox-ThreatDetection",
                    "X-CyberFox-Test": "true"
                },
                timeout=10
            )
            
            success = response.status_code < 400
            if success:
                logger.info(f"Successfully connected to n8n webhook: {response.status_code}")
            else:
                logger.error(f"Failed to connect to n8n webhook. Status: {response.status_code}, Response: {response.text}")
            
            return success
            
        except requests.exceptions.ConnectTimeout:
            logger.error(f"Connection timeout when connecting to n8n webhook at {webhook_url}")
            return False
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error when connecting to n8n webhook at {webhook_url}")
            return False
        except Exception as e:
            logger.error(f"Error testing connection to n8n: {str(e)}")
            return False
