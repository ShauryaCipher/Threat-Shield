"""
Dark web monitoring module using Tor through the Stem library.
"""
import os
import time
import logging
import threading
import json
import re
import queue
import random
import requests
from typing import List, Dict, Set, Optional, Callable, Tuple
from datetime import datetime, timedelta

import stem
import stem.connection
import stem.process
from stem.control import Controller
import socks

from cyberfox.config import CONFIG
from cyberfox.core.threats import Threat, DarkWebThreat, ThreatType, ThreatLevel
from cyberfox.utils.web_scraper import get_website_text_content, search_text_for_keywords, extract_emails_from_text

# Initialize logger
logger = logging.getLogger(__name__)

# Configure SOCKS proxy for Tor
SOCKS_PORT = 9050

# Sample onion URLs for marketplaces (these are fictional examples)
# In a real application, these would be constantly updated from a threat intelligence feed
DARK_WEB_MARKETS = [
    "http://abcdefghijklmnopqrstuvwxyz1234567890.onion",  # Example marketplace
    "http://marketplace123abcdefghijklmnopqrst.onion",    # Example marketplace
    "http://forumexample123456abcdefghijklmno.onion",     # Example forum
    "http://pastebinexample123456abcdefghijk.onion",      # Example pastebin
]

class DarkWebMonitor:
    """Monitor dark web for potentially compromised data."""
    
    def __init__(self, callback: Optional[Callable[[DarkWebThreat], None]] = None):
        """
        Initialize the dark web monitor.
        
        Args:
            callback: Function to call when a threat is detected
        """
        self.callback = callback
        self.darkweb_config = CONFIG["darkweb_monitor"]
        self.tor_process = None
        self.controller = None
        self.is_running = False
        self.session = requests.Session()
        self.session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        self.stop_flag = threading.Event()
        self.monitor_thread = None
        self._monitoring_stats = {
            "last_scan": None,
            "next_scan": None,
            "sites_monitored": 0,
            "alerts_triggered": 0,
            "status": "inactive",
            "current_site": None
        }
        
    @property
    def monitoring_stats(self) -> Dict:
        """Return current monitoring statistics."""
        return self._monitoring_stats.copy()
        
    def start_tor(self) -> bool:
        """
        Start the Tor process and create a controller.
        
        Returns:
            Boolean indicating if Tor started successfully
        """
        if not self.darkweb_config["enable_tor"]:
            logger.info("Tor monitoring disabled in configuration")
            return False
            
        try:
            # Try to connect to an existing Tor instance first
            try:
                self.controller = Controller.from_port()
                self.controller.authenticate()
                logger.info("Connected to existing Tor instance")
                return True
            except stem.SocketError:
                # No running Tor instance, start our own
                logger.info("Starting Tor process...")
                
                self.tor_process = stem.process.launch_tor_with_config(
                    config={
                        'SocksPort': str(SOCKS_PORT),
                        'ControlPort': '9051',
                        'DataDirectory': os.path.join(os.path.expanduser('~'), '.cyberfox', 'tor'),
                        'ExitPolicy': 'reject *:*',  # Non-exit relay
                    },
                    init_msg_handler=lambda msg: logger.debug(f"Tor: {msg}")
                )
                
                # Connect to the controller
                self.controller = Controller.from_port(port=9051)
                self.controller.authenticate()
                logger.info(f"Tor started successfully. Tor version: {self.controller.get_version()}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to start Tor: {e}")
            return False
            
    def stop_tor(self) -> None:
        """Stop the Tor process and controller."""
        try:
            if self.controller:
                self.controller.close()
                self.controller = None
                
            if self.tor_process:
                self.tor_process.terminate()
                self.tor_process.wait()
                self.tor_process = None
                
            logger.info("Tor stopped successfully")
        except Exception as e:
            logger.error(f"Error stopping Tor: {e}")
            
    def test_tor_connection(self) -> bool:
        """
        Test if the Tor connection is working.
        
        Returns:
            Boolean indicating if Tor connection is working
        """
        try:
            # Test connection to the Tor check service
            response = self.session.get("https://check.torproject.org/api/ip")
            data = response.json()
            is_tor = data.get("IsTor", False)
            
            if is_tor:
                logger.info(f"Tor connection working. IP: {data.get('IP')}")
                return True
            else:
                logger.warning("Connected to internet but not through Tor")
                return False
        except Exception as e:
            logger.error(f"Failed to test Tor connection: {e}")
            return False
            
    def search_data_in_content(self, content: str, keywords: List[str], emails: List[str]) -> List[str]:
        """
        Search for keywords and email addresses in content.
        
        Args:
            content: The content to search in
            keywords: List of keywords to search for
            emails: List of email addresses to search for
            
        Returns:
            List of found matches
        """
        matches = []
        
        # Convert content to lowercase for case-insensitive matching
        content_lower = content.lower()
        
        # Check for keywords
        for keyword in keywords:
            if keyword.lower() in content_lower:
                matches.append(keyword)
                
        # Check for emails with regex
        for email in emails:
            # Use word boundaries to avoid partial matches
            pattern = r'\b' + re.escape(email) + r'\b'
            if re.search(pattern, content, re.IGNORECASE):
                matches.append(email)
                
        return matches
        
    def fetch_and_analyze_site(self, url: str) -> Optional[DarkWebThreat]:
        """
        Fetch content from a dark web site and analyze it with enhanced detection capabilities.
        
        Args:
            url: The .onion URL to fetch
            
        Returns:
            DarkWebThreat if a threat is detected, None otherwise
        """
        self._monitoring_stats["current_site"] = url
        logger.info(f"Analyzing dark web site: {url}")
        
        try:
            # Import all enhanced scraper functions
            from cyberfox.utils.web_scraper import (
                get_website_text_content, 
                search_text_for_keywords, 
                extract_emails_from_text, 
                extract_sensitive_data,
                analyze_content_context,
                filter_darkweb_content,
                detect_language
            )
            
            # Get content using the improved scraper with the Tor session and enhanced options
            success, extracted_content, metadata = get_website_text_content(
                url, 
                timeout=45,  # Longer timeout for Tor connections
                session=self.session,  # Pass the Tor session
                retry_count=3,
                retry_delay=5,
                tor_mode=True,  # Enable Tor-specific handling
                save_raw_html=False,  # Don't save raw HTML for security/privacy
                circuit_isolation=True  # Use circuit isolation for additional security
            )
            
            # If we couldn't get any content, return None
            if not success or not extracted_content:
                logger.warning(f"Failed to extract content from {url}: {metadata.get('error', 'Unknown error')}")
                return None
                
            logger.debug(f"Successfully extracted {len(extracted_content)} bytes from {url} using {metadata.get('extraction_method', 'unknown method')}")
            
            # Get keywords and emails from config
            keywords = self.darkweb_config["keywords"]
            emails = self.darkweb_config["emails"]
            
            # Detect language of the content
            language = detect_language(extracted_content)
            logger.debug(f"Detected language: {language}")
            
            # Filter content for dark web-specific patterns
            darkweb_analysis = filter_darkweb_content(extracted_content)
            logger.debug(f"Dark web content analysis: {darkweb_analysis}")
            
            # Use the enhanced keyword search
            keyword_matches = search_text_for_keywords(extracted_content, keywords)
            
            # Get context around keywords for better understanding
            context_snippets = {}
            if keyword_matches:
                context_snippets = analyze_content_context(extracted_content, keyword_matches)
                logger.debug(f"Context around keywords: {str(context_snippets)[:200]}...")
            
            # Use the enhanced email extraction
            found_emails = extract_emails_from_text(extracted_content)
            monitored_email_matches = [email for email in found_emails if email in emails]
            
            # Extract all types of sensitive data
            sensitive_data = extract_sensitive_data(extracted_content)
            
            # Add findings by category
            additional_findings = []
            
            # Financial data
            if sensitive_data['credit_cards']:
                additional_findings.append(f"{len(sensitive_data['credit_cards'])} credit card numbers")
            
            # Cryptocurrency addresses
            crypto_count = len(sensitive_data['bitcoin_addresses']) + \
                          len(sensitive_data['ethereum_addresses']) + \
                          len(sensitive_data['monero_addresses'])
            if crypto_count > 0:
                additional_findings.append(f"{crypto_count} cryptocurrency addresses")
            
            # Personal identifiable information
            if sensitive_data['phone_numbers']:
                additional_findings.append(f"{len(sensitive_data['phone_numbers'])} phone numbers")
            if sensitive_data['ssn_numbers']:
                additional_findings.append(f"{len(sensitive_data['ssn_numbers'])} SSN numbers")
                
            # Authentication and access details
            if sensitive_data['api_keys']:
                additional_findings.append(f"{len(sensitive_data['api_keys'])} API keys")
            if sensitive_data['aws_keys']:
                additional_findings.append(f"{len(sensitive_data['aws_keys'])} AWS keys")
            if sensitive_data['private_keys']:
                additional_findings.append(f"{len(sensitive_data['private_keys'])} private keys")
                
            # Combine all matches and additional findings
            all_matches = keyword_matches + monitored_email_matches
            found_sensitive_data = additional_findings
            
            # Determine if we have a threat based on matches, sensitive data, or dark web content analysis
            is_threat = bool(all_matches) or bool(found_sensitive_data) or darkweb_analysis['is_suspicious']
            
            # If we've found some matches, sensitive data, or suspicious content
            if is_threat:
                # Try to get best context snippet
                snippet = None
                
                # First try to use context from our keyword analysis
                if keyword_matches and hasattr(context_snippets, 'values') and context_snippets.values():
                    for contexts in context_snippets.values():
                        if contexts:
                            snippet = contexts[0]
                            break
                
                # If no context snippet, try to create one around the match
                if not snippet and all_matches:
                    for match in all_matches:
                        idx = extracted_content.lower().find(match.lower())
                        if idx >= 0:
                            start = max(0, idx - 80)
                            end = min(len(extracted_content), idx + len(match) + 80)
                            snippet = extracted_content[start:end]
                            snippet = f"...{snippet}..."
                            break
                
                # If we didn't find a snippet for monitored items but found sensitive data,
                # try to create a snippet around the sensitive data
                if not snippet and sensitive_data:
                    # Try credit cards first
                    if sensitive_data['credit_cards']:
                        cc_num = sensitive_data['credit_cards'][0]
                        # Mask the credit card for security in snippet
                        masked_cc = cc_num[0:4] + "********" + cc_num[-4:]
                        snippet = f"...contains credit card number {masked_cc}..."
                    # Then try cryptocurrency addresses
                    elif sensitive_data['bitcoin_addresses']:
                        btc = sensitive_data['bitcoin_addresses'][0]
                        # Mask the Bitcoin address for snippet
                        masked_btc = btc[0:6] + "..." + btc[-6:]
                        snippet = f"...contains Bitcoin address {masked_btc}..."
                    elif sensitive_data['ethereum_addresses']:
                        eth = sensitive_data['ethereum_addresses'][0]
                        # Mask the Ethereum address for snippet
                        masked_eth = eth[0:6] + "..." + eth[-6:]
                        snippet = f"...contains Ethereum address {masked_eth}..."
                    elif sensitive_data['monero_addresses']:
                        xmr = sensitive_data['monero_addresses'][0]
                        # Mask the Monero address for snippet
                        masked_xmr = xmr[0:6] + "..." + xmr[-6:]
                        snippet = f"...contains Monero address {masked_xmr}..."
                
                # Determine threat level based on match types, sensitive data, and dark web analysis
                level = ThreatLevel.MEDIUM
                
                # Upgrade level based on different factors
                if any(email in all_matches for email in emails):
                    level = ThreatLevel.HIGH  # Email matches are higher severity
                
                # Sensitive data severity
                if sensitive_data['credit_cards'] or sensitive_data['ssn_numbers'] or sensitive_data['private_keys']:
                    level = ThreatLevel.CRITICAL  # Credit cards, SSNs, private keys are maximum severity
                elif (sensitive_data['bitcoin_addresses'] or 
                      sensitive_data['ethereum_addresses'] or 
                      sensitive_data['aws_keys']) and level != ThreatLevel.CRITICAL:
                    level = ThreatLevel.HIGH  # Crypto addresses, cloud keys are high severity
                
                # Dark web content analysis severity
                if darkweb_analysis['is_suspicious']:
                    # If we have high confidence and multiple categories, escalate severity
                    if darkweb_analysis['confidence'] > 0.7 and len(darkweb_analysis['categories']) >= 2:
                        level = ThreatLevel.CRITICAL
                    # Or if it's financial crime or weapons related, escalate as well
                    elif 'financial_crime' in darkweb_analysis['categories'] or 'weapons' in darkweb_analysis['categories']:
                        # Use conditional assignment instead of max() since enums don't support rich comparison
                        if level != ThreatLevel.CRITICAL:  # Only upgrade if not already critical
                            level = ThreatLevel.HIGH
                
                # Create a description with match information
                all_findings = all_matches.copy()
                
                # Add sensitive data type descriptions to findings
                all_findings.extend(found_sensitive_data)
                
                # Add dark web analysis results if suspicious
                if darkweb_analysis['is_suspicious'] and darkweb_analysis['categories']:
                    categories_str = ", ".join(darkweb_analysis['categories'])
                    all_findings.append(f"dark web content ({categories_str})")
                
                # Create the info string with the first few findings
                match_info = ", ".join(all_findings[:3])
                if len(all_findings) > 3:
                    match_info += f" and {len(all_findings) - 3} more"
                
                # Create description with additional information    
                description = f"Sensitive information found on dark web: {match_info}"
                if language and language != 'unknown':
                    description += f" (Content language: {language})"
                
                # Create and return the threat with enhanced metadata
                threat = DarkWebThreat(
                    type_=ThreatType.DARKWEB_MENTION,
                    level=level,
                    description=description,
                    keywords=all_matches,
                    url=url,
                    content_snippet=snippet,
                    sensitive_data=sensitive_data,
                    timestamp=datetime.now(),
                    details={
                        "language": language,
                        "darkweb_analysis": darkweb_analysis,
                        "context_snippets": context_snippets if keyword_matches else {},
                        "found_emails": found_emails,
                        "monitored_emails": monitored_email_matches
                    },
                    source="dark_web_monitor",
                    # Add new metadata from web scraper
                    site_metadata=metadata,
                    content_analysis={
                        "sentiment": darkweb_analysis.get("sentiment", None),
                        "context": context_snippets if keyword_matches else {},
                        "language": language,
                        "categories": darkweb_analysis.get("categories", []),
                        "confidence": darkweb_analysis.get("confidence", 0.0)
                    },
                    is_onion_site=metadata.get("is_onion", False),
                    extraction_method=metadata.get("extraction_method", "unknown")
                )
                
                self._monitoring_stats["alerts_triggered"] += 1
                logger.warning(f"Threat detected on {url} - matches: {all_matches}")
                
                if self.callback:
                    self.callback(threat)
                    
                return threat
            else:
                logger.debug(f"No threat detected on {url}")
                return None
            
        except Exception as e:
            logger.error(f"Error analyzing {url}: {e}")
            return None
            
    def monitor_dark_web(self) -> None:
        """Start dark web monitoring in a separate thread."""
        if self.is_running:
            logger.warning("Dark web monitoring is already running")
            return
            
        # Start Tor if not already running
        if not self.controller and not self.start_tor():
            logger.error("Failed to start Tor. Dark web monitoring not started.")
            return
            
        # Test Tor connection
        if not self.test_tor_connection():
            logger.error("Tor connection test failed. Dark web monitoring not started.")
            self.stop_tor()
            return
            
        self.is_running = True
        self.stop_flag.clear()
        
        self._monitoring_stats["status"] = "active"
        self._monitoring_stats["last_scan"] = datetime.now()
        self._monitoring_stats["next_scan"] = datetime.now() + timedelta(
            hours=self.darkweb_config["search_interval_hours"])
        
        self.monitor_thread = threading.Thread(
            target=self._monitor_thread,
            daemon=True
        )
        self.monitor_thread.start()
        
        logger.info("Dark web monitoring started")
        
    def _monitor_thread(self) -> None:
        """Thread function for dark web monitoring."""
        try:
            while not self.stop_flag.is_set():
                # Scan dark web marketplaces
                self._monitoring_stats["sites_monitored"] = len(DARK_WEB_MARKETS)
                
                for url in DARK_WEB_MARKETS:
                    if self.stop_flag.is_set():
                        break
                        
                    self.fetch_and_analyze_site(url)
                    
                    # Add some random delay between requests to avoid detection
                    time.sleep(random.uniform(5, 15))
                    
                # Update next scan time
                now = datetime.now()
                self._monitoring_stats["last_scan"] = now
                self._monitoring_stats["next_scan"] = now + timedelta(
                    hours=self.darkweb_config["search_interval_hours"])
                
                # Wait until next scheduled scan
                seconds_to_wait = self.darkweb_config["search_interval_hours"] * 3600
                # Wait in small increments to check stop_flag periodically
                for _ in range(int(seconds_to_wait / 10)):
                    if self.stop_flag.is_set():
                        break
                    time.sleep(10)
                    
        except Exception as e:
            logger.error(f"Error in dark web monitoring thread: {e}")
        finally:
            self._monitoring_stats["status"] = "inactive"
            self.is_running = False
            
    def stop_monitoring(self) -> None:
        """Stop dark web monitoring."""
        if not self.is_running:
            return
            
        logger.info("Stopping dark web monitoring...")
        self.stop_flag.set()
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=30)
            self.monitor_thread = None
            
        self.stop_tor()
        self.is_running = False
        self._monitoring_stats["status"] = "inactive"
        logger.info("Dark web monitoring stopped")
        
    def add_keyword(self, keyword: str) -> bool:
        """
        Add a keyword to monitor.
        
        Args:
            keyword: Keyword to add
            
        Returns:
            Boolean indicating success
        """
        if not keyword or keyword in self.darkweb_config["keywords"]:
            return False
            
        self.darkweb_config["keywords"].append(keyword)
        CONFIG["darkweb_monitor"] = self.darkweb_config
        
        # Save config
        from cyberfox.config import save_config
        save_config(CONFIG)
        
        return True
        
    def add_email(self, email: str) -> bool:
        """
        Add an email to monitor.
        
        Args:
            email: Email to add
            
        Returns:
            Boolean indicating success
        """
        if not email or email in self.darkweb_config["emails"]:
            return False
            
        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return False
            
        self.darkweb_config["emails"].append(email)
        CONFIG["darkweb_monitor"] = self.darkweb_config
        
        # Save config
        from cyberfox.config import save_config
        save_config(CONFIG)
        
        return True
        
    def remove_keyword(self, keyword: str) -> bool:
        """
        Remove a keyword from monitoring.
        
        Args:
            keyword: Keyword to remove
            
        Returns:
            Boolean indicating success
        """
        if keyword not in self.darkweb_config["keywords"]:
            return False
            
        self.darkweb_config["keywords"].remove(keyword)
        CONFIG["darkweb_monitor"] = self.darkweb_config
        
        # Save config
        from cyberfox.config import save_config
        save_config(CONFIG)
        
        return True
        
    def remove_email(self, email: str) -> bool:
        """
        Remove an email from monitoring.
        
        Args:
            email: Email to remove
            
        Returns:
            Boolean indicating success
        """
        if email not in self.darkweb_config["emails"]:
            return False
            
        self.darkweb_config["emails"].remove(email)
        CONFIG["darkweb_monitor"] = self.darkweb_config
        
        # Save config
        from cyberfox.config import save_config
        save_config(CONFIG)
        
        return True
