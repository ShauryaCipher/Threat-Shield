"""
Threat detection and classification models.
"""
from enum import Enum
from datetime import datetime
from typing import List, Dict, Any, Optional

class ThreatLevel(Enum):
    """Enumeration of threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType(Enum):
    """Enumeration of threat types."""
    MALWARE = "malware"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    VULNERABILITY = "vulnerability"
    DATA_BREACH = "data_breach"
    DARKWEB_MENTION = "darkweb_mention"
    COOKIE_TRACKING = "cookie_tracking"
    SUSPICIOUS_CONNECTION = "suspicious_connection"
    UNKNOWN = "unknown"

class Threat:
    """Base class for all threats."""
    
    def __init__(
        self, 
        type_: ThreatType, 
        level: ThreatLevel, 
        description: str, 
        timestamp: Optional[datetime] = None, 
        details: Optional[Dict[str, Any]] = None, 
        source: Optional[str] = None
    ):
        """
        Initialize a threat.
        
        Args:
            type_: Type of the threat
            level: Severity level of the threat
            description: Human-readable description of the threat
            timestamp: Time when the threat was detected
            details: Additional details about the threat
            source: Source of the threat detection
        """
        self.type = type_
        self.level = level
        self.description = description
        self.timestamp = timestamp or datetime.now()
        self.details = details or {}
        self.source = source

class FileThreat(Threat):
    """Threat detected in the file system."""
    
    def __init__(
        self, 
        type_: ThreatType, 
        level: ThreatLevel, 
        description: str, 
        filepath: str,
        hash_: Optional[str] = None,
        file_size: Optional[int] = None,
        timestamp: Optional[datetime] = None, 
        details: Optional[Dict[str, Any]] = None, 
        source: Optional[str] = None
    ):
        """
        Initialize a file threat.
        
        Args:
            type_: Type of the threat
            level: Severity level of the threat
            description: Human-readable description of the threat
            filepath: Path to the affected file
            hash_: Hash of the file
            file_size: Size of the file in bytes
            timestamp: Time when the threat was detected
            details: Additional details about the threat
            source: Source of the threat detection
        """
        super().__init__(type_, level, description, timestamp, details, source)
        self.filepath = filepath
        self.hash = hash_
        self.file_size = file_size

class DarkWebThreat(Threat):
    """Threat detected on the dark web with enhanced metadata for better threat intelligence."""
    
    def __init__(
        self, 
        type_: ThreatType, 
        level: ThreatLevel, 
        description: str, 
        keywords: List[str],
        url: Optional[str] = None,
        content_snippet: Optional[str] = None,
        sensitive_data: Optional[Dict[str, List[str]]] = None,
        timestamp: Optional[datetime] = None, 
        details: Optional[Dict[str, Any]] = None,
        source: Optional[str] = None,
        site_metadata: Optional[Dict[str, Any]] = None,
        content_analysis: Optional[Dict[str, Any]] = None,
        is_onion_site: bool = False,
        extraction_method: Optional[str] = None
    ):
        """
        Initialize a dark web threat with enhanced metadata for better threat intelligence.
        
        Args:
            type_: Type of the threat
            level: Severity level of the threat
            description: Human-readable description of the threat
            keywords: Keywords detected in the content
            url: URL where the content was found
            content_snippet: Snippet of the content
            sensitive_data: Dictionary containing different types of sensitive data found
                (credit cards, bitcoin addresses, phone numbers, etc.)
            timestamp: Time when the threat was detected
            details: Additional details about the threat
            source: Source of the threat detection
            site_metadata: Additional metadata about the site (status code, headers, etc.)
            content_analysis: Results of content analysis (sentiment, context, etc.)
            is_onion_site: Whether the site is a .onion site
            extraction_method: Method used to extract the content
        """
        super().__init__(type_, level, description, timestamp, details, source)
        self.keywords = keywords
        self.url = url
        self.content_snippet = content_snippet
        # Initialize empty dictionary for sensitive data if none provided
        self.sensitive_data = sensitive_data or {
            'credit_cards': [],
            'bitcoin_addresses': [],
            'ethereum_addresses': [],
            'monero_addresses': [],
            'phone_numbers': [],
            'ssn_numbers': [],
            'ip_addresses': [],
            'emails': [],
            'api_keys': [],
            'aws_keys': [],
            'private_keys': []
        }
        # Add new metadata fields
        self.site_metadata = site_metadata or {}
        self.content_analysis = content_analysis or {}
        self.is_onion_site = is_onion_site
        self.extraction_method = extraction_method

class DataBreachThreat(Threat):
    """Data breach threat from Have I Been Pwned or similar sources."""
    
    def __init__(
        self, 
        type_: ThreatType, 
        level: ThreatLevel, 
        description: str, 
        email: str,
        breach_name: str,
        breach_date: datetime,
        pwned_data: List[str],
        timestamp: Optional[datetime] = None, 
        details: Optional[Dict[str, Any]] = None, 
        source: Optional[str] = None
    ):
        """
        Initialize a data breach threat.
        
        Args:
            type_: Type of the threat
            level: Severity level of the threat
            description: Human-readable description of the threat
            email: Email address involved in the breach
            breach_name: Name of the breach
            breach_date: Date when the breach occurred
            pwned_data: Types of data exposed in the breach
            timestamp: Time when the threat was detected
            details: Additional details about the threat
            source: Source of the threat detection
        """
        super().__init__(type_, level, description, timestamp, details, source)
        self.email = email
        self.breach_name = breach_name
        self.breach_date = breach_date
        self.pwned_data = pwned_data

class BrowserThreat(Threat):
    """Threat detected in browser data (cookies, history, etc.)."""
    
    def __init__(
        self, 
        type_: ThreatType, 
        level: ThreatLevel, 
        description: str, 
        browser: str,
        threat_source: str,
        url: Optional[str] = None,
        timestamp: Optional[datetime] = None, 
        details: Optional[Dict[str, Any]] = None, 
        source: Optional[str] = None
    ):
        """
        Initialize a browser threat.
        
        Args:
            type_: Type of the threat
            level: Severity level of the threat
            description: Human-readable description of the threat
            browser: Browser where the threat was detected
            threat_source: Source of the threat (cookie, history, etc.)
            url: URL associated with the threat
            timestamp: Time when the threat was detected
            details: Additional details about the threat
            source: Source of the threat detection
        """
        super().__init__(type_, level, description, timestamp, details, source)
        self.browser = browser
        self.threat_source = threat_source
        self.url = url
    
class ThreatDatabase:
    """Store and manage detected threats."""
    
    def __init__(self):
        self.threats: List[Threat] = []
        
    def add_threat(self, threat: Threat) -> None:
        """Add a new threat to the database."""
        self.threats.append(threat)
        
    def get_threats(self, 
                   threat_type: Optional[ThreatType] = None, 
                   level: Optional[ThreatLevel] = None, 
                   since: Optional[datetime] = None) -> List[Threat]:
        """Get threats filtered by type, level, and/or time."""
        filtered_threats = self.threats
        
        if threat_type:
            filtered_threats = [t for t in filtered_threats if t.type == threat_type]
            
        if level:
            filtered_threats = [t for t in filtered_threats if t.level == level]
            
        if since:
            filtered_threats = [t for t in filtered_threats if t.timestamp and t.timestamp >= since]
            
        return filtered_threats
    
    def get_by_severity(self) -> Dict[ThreatLevel, List[Threat]]:
        """Group threats by severity level."""
        result = {level: [] for level in ThreatLevel}
        for threat in self.threats:
            result[threat.level].append(threat)
        return result
    
    def clear(self) -> None:
        """Clear all threats from the database."""
        self.threats = []
