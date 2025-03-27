"""
Data breach checker using the Have I Been Pwned API.
"""
import os
import time
import json
import logging
import threading
import requests
import re
from typing import List, Dict, Set, Optional, Callable
from datetime import datetime, timedelta

from cyberfox.config import CONFIG, HIBP_API_KEY
from cyberfox.core.threats import Threat, DataBreachThreat, ThreatType, ThreatLevel

# Initialize logger
logger = logging.getLogger(__name__)

# Have I Been Pwned API endpoints
HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_BREACH_URL = f"{HIBP_API_BASE}/breachedaccount/"
HIBP_BREACHES_URL = f"{HIBP_API_BASE}/breaches"

class BreachChecker:
    """Check for data breaches using Have I Been Pwned API."""
    
    def __init__(self, callback: Callable[[DataBreachThreat], None] = None):
        """
        Initialize the breach checker.
        
        Args:
            callback: Function to call when a breach is detected
        """
        self.callback = callback
        self.breach_config = CONFIG["breach_check"]
        self.is_running = False
        self.stop_flag = threading.Event()
        self.checker_thread = None
        self._checker_stats = {
            "last_check": None,
            "next_check": None,
            "emails_checked": 0,
            "breaches_found": 0,
            "status": "inactive",
            "current_email": None
        }
        
        # Cache of known breaches to reduce API calls
        self.breach_cache = {}
        
    @property
    def checker_stats(self) -> Dict:
        """Return current breach checker statistics."""
        return self._checker_stats.copy()
        
    def check_api_key(self) -> bool:
        """
        Check if the HIBP API key is available.
        
        Returns:
            Boolean indicating if API key is available
        """
        return bool(HIBP_API_KEY)
        
    def get_all_breaches(self) -> List[Dict]:
        """
        Get a list of all breaches known to HIBP.
        
        Returns:
            List of breach objects
        """
        if not self.check_api_key():
            logger.error("Have I Been Pwned API key not available")
            return []
            
        # Check if we have a recent cache
        cache_file = os.path.join(os.path.expanduser('~'), '.cyberfox', 'hibp_breaches.json')
        try:
            if os.path.exists(cache_file):
                # Check if cache is less than 24 hours old
                mtime = os.path.getmtime(cache_file)
                if (time.time() - mtime) < 86400:  # 24 hours
                    with open(cache_file, 'r') as f:
                        return json.load(f)
        except Exception as e:
            logger.warning(f"Error reading breach cache: {e}")
            
        # Fetch from API
        try:
            headers = {
                'hibp-api-key': HIBP_API_KEY,
                'User-Agent': 'CyberFox-ThreatDetection'
            }
            
            response = requests.get(HIBP_BREACHES_URL, headers=headers)
            
            if response.status_code == 200:
                breaches = response.json()
                
                # Cache the response
                try:
                    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
                    with open(cache_file, 'w') as f:
                        json.dump(breaches, f)
                except Exception as e:
                    logger.warning(f"Error caching breaches: {e}")
                    
                return breaches
            else:
                logger.error(f"HIBP API returned status code {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching breaches: {e}")
            return []
            
    def check_email(self, email: str) -> List[Dict]:
        """
        Check if an email has been involved in any known data breaches.
        
        Args:
            email: Email address to check
            
        Returns:
            List of breach objects the email was found in
        """
        if not self.check_api_key():
            logger.error("Have I Been Pwned API key not available")
            return []
            
        self._checker_stats["current_email"] = email
        
        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            logger.warning(f"Invalid email format: {email}")
            return []
            
        # Check if in cache
        if email in self.breach_cache:
            return self.breach_cache[email]
            
        try:
            headers = {
                'hibp-api-key': HIBP_API_KEY,
                'User-Agent': 'CyberFox-ThreatDetection'
            }
            
            url = f"{HIBP_BREACH_URL}{email}"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                breaches = response.json()
                self.breach_cache[email] = breaches
                self._checker_stats["emails_checked"] += 1
                self._checker_stats["breaches_found"] += len(breaches)
                return breaches
            elif response.status_code == 404:
                # Email not found in any breaches
                self.breach_cache[email] = []
                self._checker_stats["emails_checked"] += 1
                return []
            else:
                logger.error(f"HIBP API returned status code {response.status_code} for {email}")
                # Rate limiting or other error
                time.sleep(2)  # Wait before retrying
                return []
                
        except Exception as e:
            logger.error(f"Error checking email {email}: {e}")
            return []
            
    def process_breach_results(self, email: str, breaches: List[Dict]) -> List[DataBreachThreat]:
        """
        Process breach results into threat objects with enhanced analysis.
        
        Args:
            email: Email that was checked
            breaches: List of breach objects
            
        Returns:
            List of DataBreachThreat objects
        """
        threats = []
        
        # Define data sensitivity categories for more precise analysis
        high_sensitivity_data = [
            'Passwords', 'Password hints', 'Credit cards', 'Security questions and answers',
            'Financial data', 'Payment histories', 'Payment info'
        ]
        
        critical_sensitivity_data = [
            'Social security numbers', 'Banking details', 'Government issued IDs',
            'Tax records', 'Healthcare records', 'Financial documents', 'Full credit card details',
            'Passport details', 'Biometric data'
        ]
        
        personal_identifiers = [
            'Names', 'Email addresses', 'Phone numbers', 'Physical addresses',
            'Dates of birth', 'Genders', 'Geographic locations'
        ]
        
        # Process each breach
        for breach in breaches:
            try:
                # Parse breach date
                breach_date = datetime.strptime(breach.get('BreachDate', '2000-01-01'), '%Y-%m-%d')
                
                # Get data classes affected
                pwned_data = breach.get('DataClasses', [])
                
                # Calculate recency of breach for risk assessment (newer breaches are higher risk)
                breach_age_days = (datetime.now() - breach_date).days
                is_recent = breach_age_days < 180  # Within last 6 months
                
                # Categorize compromised data for detailed analysis
                compromised_data_categories = {
                    "personal_identifiers": [item for item in pwned_data if item in personal_identifiers],
                    "high_sensitivity": [item for item in pwned_data if item in high_sensitivity_data],
                    "critical": [item for item in pwned_data if item in critical_sensitivity_data],
                    "other": [item for item in pwned_data if item not in personal_identifiers 
                             and item not in high_sensitivity_data 
                             and item not in critical_sensitivity_data]
                }
                
                # Calculate risk score based on breach factors
                risk_score = 0
                
                # Base score from data categories
                risk_score += len(compromised_data_categories["personal_identifiers"]) * 1
                risk_score += len(compromised_data_categories["high_sensitivity"]) * 3
                risk_score += len(compromised_data_categories["critical"]) * 5
                
                # Adjust for breach recency
                if is_recent:
                    risk_score *= 1.5
                
                # Adjust for breach verification
                if breach.get('IsVerified', False):
                    risk_score *= 1.2
                else:
                    risk_score *= 0.8
                
                # Adjust for breach size if available
                if breach.get('PwnCount'):
                    pwn_count = breach.get('PwnCount')
                    if pwn_count > 10000000:  # 10 million+
                        risk_score *= 1.3
                    elif pwn_count > 1000000:  # 1 million+
                        risk_score *= 1.2
                    elif pwn_count > 100000:  # 100k+
                        risk_score *= 1.1
                
                # Determine threat level based on sensitivity of breached data and risk score
                if len(compromised_data_categories["critical"]) > 0 or risk_score > 15:
                    level = ThreatLevel.CRITICAL
                elif len(compromised_data_categories["high_sensitivity"]) > 0 or risk_score > 8:
                    level = ThreatLevel.HIGH
                elif is_recent or risk_score > 4:
                    level = ThreatLevel.MEDIUM
                else:
                    level = ThreatLevel.LOW
                
                # Generate intelligent action recommendations based on compromised data
                action_recommendations = []
                
                if "Passwords" in pwned_data:
                    action_recommendations.append("Change your password on this site immediately.")
                    action_recommendations.append("Change passwords on any other sites where you used the same or similar password.")
                    
                if "Email addresses" in pwned_data:
                    action_recommendations.append("Be alert for phishing attempts targeting your email.")
                    
                if any(cc in pwned_data for cc in ["Credit cards", "Payment info", "Banking details"]):
                    action_recommendations.append("Monitor your financial statements for unauthorized transactions.")
                    action_recommendations.append("Consider requesting a new credit card if your card number was exposed.")
                    
                if "Security questions and answers" in pwned_data:
                    action_recommendations.append("Update security questions and answers on sensitive accounts.")
                    
                if is_recent:
                    action_recommendations.append("Enable two-factor authentication on all accounts that support it.")
                    
                # Generate detailed description based on analysis
                if level == ThreatLevel.CRITICAL:
                    description = f"CRITICAL: Your data was exposed in the {breach.get('Name')} breach. Immediate action required!"
                elif level == ThreatLevel.HIGH:
                    description = f"HIGH RISK: Your sensitive information was compromised in the {breach.get('Name')} breach."
                elif level == ThreatLevel.MEDIUM:
                    description = f"ALERT: Your data was involved in the {breach.get('Name')} breach."
                else:
                    description = f"Your email {email} appeared in the {breach.get('Name')} data breach."
                
                threat = DataBreachThreat(
                    type_=ThreatType.DATA_BREACH,
                    level=level,
                    description=description,
                    email=email,
                    breach_name=breach.get('Name', 'Unknown'),
                    breach_date=breach_date,
                    pwned_data=pwned_data,
                    details={
                        "domain": breach.get('Domain', 'Unknown'),
                        "description": breach.get('Description', 'Unknown'),
                        "breach_date": breach.get('BreachDate', 'Unknown'),
                        "added_date": breach.get('AddedDate', 'Unknown'),
                        "data_classes": pwned_data,
                        "is_verified": breach.get('IsVerified', False),
                        "is_sensitive": breach.get('IsSensitive', False),
                        "pwn_count": breach.get('PwnCount'),
                        "is_recent": is_recent,
                        "breach_age_days": breach_age_days,
                        "risk_score": risk_score,
                        "compromised_data_analysis": compromised_data_categories,
                        "action_recommendations": action_recommendations
                    },
                    source="hibp"
                )
                
                threats.append(threat)
                
                if self.callback:
                    self.callback(threat)
                    
            except Exception as e:
                logger.error(f"Error processing breach {breach.get('Name', 'Unknown')}: {e}")
                
        return threats
        
    def check_emails(self, emails: List[str]) -> List[DataBreachThreat]:
        """
        Check a list of emails for data breaches.
        
        Args:
            emails: List of email addresses to check
            
        Returns:
            List of DataBreachThreat objects
        """
        all_threats = []
        
        for email in emails:
            if self.stop_flag.is_set():
                break
                
            breaches = self.check_email(email)
            threats = self.process_breach_results(email, breaches)
            all_threats.extend(threats)
            
            # Wait to avoid rate limiting
            time.sleep(1.5)
            
        return all_threats
        
    def start_checker(self) -> bool:
        """
        Start the breach checker in a separate thread.
        
        Returns:
            Boolean indicating if checker was started
        """
        if self.is_running:
            logger.warning("Breach checker is already running")
            return False
            
        if not self.breach_config["enable_hibp"]:
            logger.info("Have I Been Pwned integration disabled in configuration")
            return False
            
        if not self.check_api_key():
            logger.error("Have I Been Pwned API key not available")
            return False
            
        self.is_running = True
        self.stop_flag.clear()
        
        self._checker_stats["status"] = "active"
        self._checker_stats["last_check"] = datetime.now()
        self._checker_stats["next_check"] = datetime.now() + timedelta(
            days=self.breach_config["check_interval_days"])
        
        self.checker_thread = threading.Thread(
            target=self._checker_thread,
            daemon=True
        )
        self.checker_thread.start()
        
        logger.info("Breach checker started")
        return True
        
    def _checker_thread(self) -> None:
        """Thread function for breach checking."""
        try:
            while not self.stop_flag.is_set():
                # Get emails to check from the dark web monitor config
                emails = CONFIG["darkweb_monitor"]["emails"]
                
                if emails:
                    self.check_emails(emails)
                    
                # Update next check time
                now = datetime.now()
                self._checker_stats["last_check"] = now
                self._checker_stats["next_check"] = now + timedelta(
                    days=self.breach_config["check_interval_days"])
                
                # Wait until next scheduled check
                seconds_to_wait = self.breach_config["check_interval_days"] * 86400
                # Wait in small increments to check stop_flag periodically
                for _ in range(int(seconds_to_wait / 60)):
                    if self.stop_flag.is_set():
                        break
                    time.sleep(60)
                    
        except Exception as e:
            logger.error(f"Error in breach checker thread: {e}")
        finally:
            self._checker_stats["status"] = "inactive"
            self.is_running = False
            
    def stop_checker(self) -> None:
        """Stop breach checker."""
        if not self.is_running:
            return
            
        logger.info("Stopping breach checker...")
        self.stop_flag.set()
        
        if self.checker_thread:
            self.checker_thread.join(timeout=30)
            self.checker_thread = None
            
        self.is_running = False
        self._checker_stats["status"] = "inactive"
        logger.info("Breach checker stopped")
        
    def manual_check(self, email: str) -> List[DataBreachThreat]:
        """
        Manually check a single email for breaches.
        
        Args:
            email: Email address to check
            
        Returns:
            List of DataBreachThreat objects
        """
        breaches = self.check_email(email)
        return self.process_breach_results(email, breaches)
