"""
Browser cookie and data analyzer for detecting tracking and suspicious behavior.
This module provides enhanced detection for advanced tracking techniques, browser fingerprinting,
local storage abuse, and other privacy concerns.
"""
import os
import json
import sqlite3
import logging
import platform
import shutil
import tempfile
import re
import base64
from pathlib import Path
from typing import List, Dict, Set, Optional, Callable, Tuple, Any, Union
from datetime import datetime

from cyberfox.config import CONFIG
from cyberfox.core.threats import Threat, BrowserThreat, ThreatType, ThreatLevel

# Initialize logger
logger = logging.getLogger(__name__)

# Categorized tracking domains
TRACKING_DOMAINS = {
    # Ad networks and exchanges
    "doubleclick.net": "advertising",
    "googleadservices.com": "advertising",
    "googlesyndication.com": "advertising",
    "adnxs.com": "advertising",
    "amazon-adsystem.com": "advertising",
    "adroll.com": "advertising",
    "criteo.com": "advertising",
    "outbrain.com": "advertising",
    "taboola.com": "advertising",
    "adform.net": "advertising",
    "ads.pubmatic.com": "advertising",
    "ads.yahoo.com": "advertising",
    "rubiconproject.com": "advertising",
    "advertising.com": "advertising",
    "bidswitch.net": "advertising",
    "openx.net": "advertising",
    "33across.com": "advertising",
    "sonobi.com": "advertising",
    "indexww.com": "advertising",
    "smartadserver.com": "advertising",
    "casalemedia.com": "advertising",
    "sharethrough.com": "advertising",
    "lijit.com": "advertising", 
    "teads.tv": "advertising",
    "contextweb.com": "advertising",
    "adtech.com": "advertising",
    
    # Analytics and tracking
    "analytics.google.com": "analytics",
    "googletagmanager.com": "analytics",
    "google-analytics.com": "analytics",
    "mixpanel.com": "analytics",
    "segment.io": "analytics",
    "amplitude.com": "analytics",
    "hotjar.com": "analytics",
    "matomo.cloud": "analytics",
    "analytics.yahoo.com": "analytics",
    "clarity.ms": "analytics",
    "analytics.tiktok.com": "analytics",
    "fullstory.com": "analytics",
    "mouseflow.com": "analytics",
    "contentsquare.com": "analytics",
    "heap.io": "analytics",
    "loggly.com": "analytics",
    "pendo.io": "analytics",
    "crazyegg.com": "analytics",
    "woopra.com": "analytics",
    "gaug.es": "analytics",
    "quantserve.com": "analytics",
    "luckyorange.com": "analytics",
    "newrelic.com": "analytics",
    "dynatrace.com": "analytics",
    "inspectlet.com": "analytics",
    "sessioncam.com": "analytics",
    "smartlook.com": "analytics",
    
    # Social media tracking
    "facebook.com": "social",
    "facebook.net": "social",
    "fbcdn.net": "social",
    "tiktok.com": "social",
    "tiktokcdn.com": "social",
    "snapchat.com": "social",
    "pinterest.com": "social",
    "quora.com": "social",
    "twitter.com": "social",
    "linkedin.com": "social",
    "instagram.com": "social",
    "reddit.com": "social",
    "disqus.com": "social",
    
    # Mobile attribution and tracking
    "mparticle.com": "attribution",
    "branch.io": "attribution",
    "adjust.com": "attribution",
    "appsflyer.com": "attribution",
    "kochava.com": "attribution",
    "singular.net": "attribution",
    "tenjin.io": "attribution",
    "airbridge.io": "attribution",
    "tune.com": "attribution",
    
    # Fingerprinting and advanced tracking
    "fingerprintjs.com": "fingerprinting",
    "pro.ip-api.com": "fingerprinting",
    "iovation.com": "fingerprinting",
    "securepubads.g.doubleclick.net": "fingerprinting",
    "pagead2.googlesyndication.com": "fingerprinting",
    "browser-update.org": "fingerprinting",
    "d2.parrable.com": "fingerprinting",
    "px-cloud.net": "fingerprinting",
    "cookiebot.com": "fingerprinting",
    "disconnect.me": "fingerprinting",
    "optanon.com": "fingerprinting",
    "gdpr-wrapper.privacymanager.io": "fingerprinting",
    
    # Session replay trackers
    "sessionreplay.com": "session_replay",
    "userreplay.com": "session_replay",
    "decibelinsight.com": "session_replay",
    "clicktale.net": "session_replay",
    "glassbox.com": "session_replay",
    
    # Cross-site tracking
    "scorecardresearch.com": "cross_site",
    "cxense.com": "cross_site",
    "rlcdn.com": "cross_site",
    "bluekai.com": "cross_site",
    "exelator.com": "cross_site",
    "id5-sync.com": "cross_site",
    "adsrvr.org": "cross_site",
    "tapad.com": "cross_site",
    "agkn.com": "cross_site",
    "crwdcntrl.net": "cross_site",
    "everesttech.net": "cross_site",
    "krxd.net": "cross_site",
    "innovid.com": "cross_site",
    "spotxchange.com": "cross_site",
    "demdex.net": "cross_site",
    "chartbeat.com": "cross_site",
    
    # Real-time bidding
    "bidder.criteo.com": "rtb",
    "prebid.org": "rtb",
    "1rx.io": "rtb",
    "adhigh.net": "rtb",
    "adkernel.com": "rtb",
    "admixer.net": "rtb",
    "ad-stir.com": "rtb",
    "between.com": "rtb",
    "gumgum.com": "rtb",
    "improve-digital.com": "rtb",
    
    # Ad fraud detection (still tracking)
    "moatads.com": "ad_verification", 
    "doubleverify.com": "ad_verification",
    "adsafeprotected.com": "ad_verification",
    "integral-marketing.com": "ad_verification",
    "trustarc.com": "ad_verification",
    "flashtalking.com": "ad_verification",

    # Newer sophisticated tracking domains
    "splitio.com": "a/b_testing",
    "cdn-pci.optimizely.com": "a/b_testing",
    "convertexperiments.com": "a/b_testing",
    "device.4seeresults.com": "fingerprinting",
    "cdn.mouseflow.com": "session_replay",
    "device-api.urbanairship.com": "attribution",
    "static.audienceproject.com": "fingerprinting",
    "widget.surveymonkey.com": "analytics",
    "go.affec.tv": "cross_site",
    "trc.taboola.com": "advertising",
    "us-u.openx.net": "rtb",
    "c.bing.com": "analytics",
    "beacon.krxd.net": "cross_site",
    "sync.mathtag.com": "fingerprinting"
}

# Fingerprinting JavaScript patterns to detect in local storage and history
FINGERPRINTING_PATTERNS = [
    # Basic navigator properties
    'navigator.userAgent',
    'navigator.plugins',
    'navigator.mimeTypes',
    'navigator.language',
    'navigator.languages',
    'navigator.cookieEnabled',
    'navigator.doNotTrack',
    'navigator.hardwareConcurrency',
    'navigator.deviceMemory',
    'navigator.platform',
    'navigator.vendor',
    'navigator.appVersion',
    'navigator.productSub',
    'navigator.connection',
    'navigator.buildID',
    
    # Screen properties
    'screen.width',
    'screen.height',
    'screen.availWidth',
    'screen.availHeight',
    'screen.colorDepth',
    'screen.pixelDepth',
    'window.devicePixelRatio',
    'window.screen.orientation',
    
    # Canvas fingerprinting
    'canvas.toDataURL',
    'canvas.getImageData',
    'createImageBitmap',
    'CanvasRenderingContext2D',
    
    # WebGL fingerprinting
    'webgl.getParameter',
    'getExtension',
    'getShaderPrecisionFormat',
    'getContextAttributes',
    'getSupportedExtensions',
    'drawArrays',
    'drawElements',
    'readPixels',
    'WEBGL_debug_renderer_info',
    
    # Audio fingerprinting
    'AudioContext',
    'OscillatorNode',
    'createOscillator',
    'createAnalyser',
    'getChannelData',
    'getFloatFrequencyData',
    
    # Battery fingerprinting
    'getBattery',
    
    # Geometry and font fingerprinting
    'getClientRects',
    'getBoundingClientRect',
    'offsetWidth',
    'offsetHeight',
    'fonts.load',
    'document.fonts',
    'fontFamily',
    
    # Media devices
    'enumerateDevices',
    'MediaDevices.enumerateDevices',
    'getUserMedia',
    
    # Network fingerprinting
    'RTCPeerConnection',
    'createDataChannel',
    'onicecandidate',
    
    # Style fingerprinting
    'getComputedStyle',
    'CSSStyleDeclaration',
    
    # Fingerprinting libraries
    'canvascreated',
    'fingerprintjs',
    'fingerprint2',
    'fingerprintjs2',
    'clientjs',
    'fingerprinting',
    
    # Crypto and randomness
    'getRandomValues',
    'crypto.subtle',
    
    # New advanced techniques
    'performance.now',
    'performance.memory',
    'Intl.DateTimeFormat',
    'Intl.NumberFormat',
    'speechSynthesis.getVoices',
    'vibrate',
    'maxTouchPoints',
    'ontouchstart',
    'onorientationchange'
]

# Canvas fingerprinting patterns
CANVAS_FINGERPRINTING_PATTERNS = [
    # Text rendering
    'fillText(',
    'strokeText(',
    'measureText(',
    'textBaseline',
    'textAlign',
    'font',
    
    # Data extraction
    'toDataURL(',
    'toBlob(',
    'getImageData(',
    
    # Advanced 2D operations
    'isPointInPath(',
    'isPointInStroke(',
    'createPattern(',
    'createLinearGradient(',
    'createRadialGradient(',
    
    # Composite operations
    'globalCompositeOperation',
    'globalAlpha',
    
    # Canvas manipulations
    'rotate(',
    'transform(',
    'scale(',
    'translate(',
    
    # Hidden canvas elements
    'createElement(\'canvas\'',
    '<canvas style="display:none"',
    'canvas.style.visibility',
    'canvas.style.display',
    
    # Emoji rendering - often used as they render differently across platforms
    '😀', '🔥', '✅', '🎉'
]

# WebRTC fingerprinting patterns
WEBRTC_FINGERPRINTING_PATTERNS = [
    # Connection setup
    'RTCPeerConnection(',
    'webkitRTCPeerConnection(',
    'mozRTCPeerConnection(',
    
    # Data channels
    'createDataChannel(',
    'ondatachannel',
    
    # ICE candidates - key for IP leakage
    'onicecandidate',
    'addIceCandidate(',
    'icecandidate',
    'setLocalDescription',
    'createOffer',
    'createAnswer',
    
    # STUN/TURN servers - often used to reveal real IP
    'stun:stun.l.google.com',
    'stun:',
    'turn:',
    
    # WebRTC leak tests
    'peercdn.com',
    'webrtc-leak',
    'webrtc.internals'
]

# Suspicious localStorage keys
SUSPICIOUS_LOCALSTORAGE_KEYS = [
    # User identification
    'uid',
    'uuid',
    'deviceid',
    'fingerprint',
    'visitorid',
    'userid',
    'trackid',
    'sessionid',
    'puid',
    'clientid',
    'cid',
    'gauid',
    'visitor',
    'did',
    'identity',
    'fpid',
    'pid'
]

class BrowserAnalyzer:
    """Analyze browser cookies and data for tracking and suspicious behavior."""
    
    def __init__(self, callback: Callable[[BrowserThreat], None] = None):
        """
        Initialize the browser analyzer.
        
        Args:
            callback: Function to call when a threat is detected
        """
        self.callback = callback
        self.browser_config = CONFIG["browser_analyzer"]
        
    def get_browser_path(self, browser: str) -> Optional[Path]:
        """
        Get the path to browser profile directory.
        
        Args:
            browser: Browser name (chrome, firefox, edge)
            
        Returns:
            Path to browser profile directory or None if not found
        """
        system = platform.system()
        home = Path.home()
        
        if system == "Windows":
            appdata_local = Path(os.environ.get("LOCALAPPDATA", ""))
            appdata_roaming = Path(os.environ.get("APPDATA", ""))
            
            if browser == "chrome":
                return appdata_local / "Google" / "Chrome" / "User Data" / "Default"
            elif browser == "firefox":
                # Find the default profile
                mozilla_dir = appdata_roaming / "Mozilla" / "Firefox" / "Profiles"
                if mozilla_dir.exists():
                    for profile in mozilla_dir.glob("*.default-release"):
                        return profile
            elif browser == "edge":
                return appdata_local / "Microsoft" / "Edge" / "User Data" / "Default"
                
        elif system == "Darwin":  # macOS
            if browser == "chrome":
                return home / "Library" / "Application Support" / "Google" / "Chrome" / "Default"
            elif browser == "firefox":
                # Find the default profile
                mozilla_dir = home / "Library" / "Application Support" / "Firefox" / "Profiles"
                if mozilla_dir.exists():
                    for profile in mozilla_dir.glob("*.default-release"):
                        return profile
            elif browser == "edge":
                return home / "Library" / "Application Support" / "Microsoft Edge" / "Default"
                
        elif system == "Linux":
            if browser == "chrome":
                return home / ".config" / "google-chrome" / "Default"
            elif browser == "firefox":
                # Find the default profile
                mozilla_dir = home / ".mozilla" / "firefox" / "Profiles"
                if mozilla_dir.exists():
                    for profile in mozilla_dir.glob("*.default-release"):
                        return profile
            elif browser == "edge":
                return home / ".config" / "microsoft-edge" / "Default"
                
        return None
        
    def detect_domain_from_url(self, url: str) -> str:
        """
        Extract domain name from URL.
        
        Args:
            url: URL to extract domain from
            
        Returns:
            Domain name
        """
        # Remove protocol
        if "://" in url:
            url = url.split("://", 1)[1]
            
        # Remove path and query
        if "/" in url:
            url = url.split("/", 1)[0]
            
        # Remove port
        if ":" in url:
            url = url.split(":", 1)[0]
            
        return url
        
    def is_tracking_domain(self, domain: str) -> tuple[bool, Optional[str]]:
        """
        Check if domain is a known tracking domain and get its category.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (is_tracking, category)
        """
        # Check exact match
        if domain in TRACKING_DOMAINS:
            return True, TRACKING_DOMAINS[domain]
            
        # Check if domain ends with any tracking domain
        for tracking_domain, category in TRACKING_DOMAINS.items():
            if domain.endswith("." + tracking_domain):
                return True, category
                
        return False, None
        
    def get_tracking_category_severity(self, category: str) -> ThreatLevel:
        """
        Determine the threat level based on the tracking category.
        
        Args:
            category: Tracking category
            
        Returns:
            Threat level
        """
        # Higher risk categories
        if category in ["fingerprinting", "session_replay", "cross_site"]:
            return ThreatLevel.HIGH
        # Medium risk categories
        elif category in ["advertising", "rtb", "social"]:
            return ThreatLevel.MEDIUM
        # Lower risk categories
        else:
            return ThreatLevel.LOW
        
    def analyze_cookies_chrome(self, profile_path: Path) -> List[BrowserThreat]:
        """
        Analyze Chrome/Edge cookies for tracking with enhanced detection.
        
        Args:
            profile_path: Path to browser profile
            
        Returns:
            List of BrowserThreat objects
        """
        threats = []
        cookies_db = profile_path / "Network" / "Cookies"
        
        if not cookies_db.exists():
            cookies_db = profile_path / "Cookies"
            if not cookies_db.exists():
                logger.warning(f"Cookies database not found at {cookies_db}")
                return threats
                
        # Create a copy of the database to avoid lock issues
        temp_dir = tempfile.mkdtemp()
        temp_db = Path(temp_dir) / "cookies.db"
        try:
            shutil.copy2(cookies_db, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Query depends on Chrome version
            try:
                cursor.execute("SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly, creation_utc FROM cookies")
            except sqlite3.OperationalError:
                # Try older schema
                cursor.execute("SELECT host_key, name, value, path, expires_utc, secure, httponly, creation_utc FROM cookies")
                
            tracking_cookies = []
            
            for row in cursor.fetchall():
                domain = row[0]
                if domain.startswith('.'):
                    domain = domain[1:]
                    
                is_tracking, category = self.is_tracking_domain(domain)
                if is_tracking:
                    tracking_cookies.append({
                        "domain": domain,
                        "name": row[1],
                        "path": row[3],
                        "secure": bool(row[5]),
                        "httponly": bool(row[6]),
                        "category": category
                    })
                    
            conn.close()
            
            # Group cookies by domain
            domain_cookies = {}
            domain_categories = {}
            
            for cookie in tracking_cookies:
                domain = cookie["domain"]
                category = cookie["category"]
                
                if domain not in domain_cookies:
                    domain_cookies[domain] = []
                    domain_categories[domain] = category
                
                domain_cookies[domain].append(cookie)
                
            # Create threats for each domain with tracking cookies
            browser_name = "Edge" if "edge" in str(profile_path).lower() else "Chrome"
            
            # Group domains by tracking category for analysis
            category_domains = {}
            for domain, category in domain_categories.items():
                if category not in category_domains:
                    category_domains[category] = []
                category_domains[category].append(domain)
            
            # Check for high-risk fingerprinting or session replay
            for high_risk_category in ["fingerprinting", "session_replay", "cross_site"]:
                if high_risk_category in category_domains:
                    domains = category_domains[high_risk_category]
                    
                    # Create a high severity threat for each domain
                    for domain in domains:
                        cookies = domain_cookies[domain]
                        
                        description = ""
                        if high_risk_category == "fingerprinting":
                            description = f"HIGH RISK: Browser fingerprinting detected from {domain}"
                            threat_type = ThreatType.SUSPICIOUS_CONNECTION
                        elif high_risk_category == "session_replay":
                            description = f"HIGH RISK: Session recording detected from {domain}"
                            threat_type = ThreatType.SUSPICIOUS_CONNECTION
                        else:  # cross_site
                            description = f"HIGH RISK: Cross-site tracking detected from {domain}"
                            threat_type = ThreatType.COOKIE_TRACKING
                        
                        threat = BrowserThreat(
                            type_=threat_type,
                            level=ThreatLevel.HIGH,
                            description=description,
                            browser=browser_name,
                            threat_source="cookies",
                            details={
                                "domain": domain,
                                "cookie_count": len(cookies),
                                "cookies": cookies,
                                "category": high_risk_category,
                                "privacy_impact": "High - May track you across websites and build detailed profiles"
                            },
                            source="browser_analyzer"
                        )
                        
                        threats.append(threat)
                        
                        if self.callback:
                            self.callback(threat)
            
            # Check for excessive cookies from advertising networks or RTB
            for ad_category in ["advertising", "rtb"]:
                if ad_category in category_domains:
                    ad_domains = category_domains[ad_category]
                    ad_cookie_count = sum(len(domain_cookies[d]) for d in ad_domains)
                    
                    # If there are many ad cookies overall, create a general threat
                    if ad_cookie_count > 20:
                        threat = BrowserThreat(
                            type_=ThreatType.COOKIE_TRACKING,
                            level=ThreatLevel.MEDIUM,
                            description=f"Excessive advertising tracking detected ({ad_cookie_count} cookies from {len(ad_domains)} domains)",
                            browser=browser_name,
                            threat_source="cookies",
                            details={
                                "ad_cookie_count": ad_cookie_count,
                                "ad_domains": ad_domains,
                                "category": ad_category,
                                "privacy_impact": "Medium - Tracking for targeted advertising"
                            },
                            source="browser_analyzer"
                        )
                        
                        threats.append(threat)
                        
                        if self.callback:
                            self.callback(threat)
                    
                    # Also check individual domains with many cookies
                    for domain in ad_domains:
                        cookies = domain_cookies[domain]
                        if len(cookies) >= 5:  # Higher threshold for advertising
                            threat = BrowserThreat(
                                type_=ThreatType.COOKIE_TRACKING,
                                level=ThreatLevel.MEDIUM,
                                description=f"Excessive tracking from advertising network {domain}",
                                browser=browser_name,
                                threat_source="cookies",
                                details={
                                    "domain": domain,
                                    "cookie_count": len(cookies),
                                    "cookies": cookies,
                                    "category": ad_category,
                                    "privacy_impact": "Medium - Detailed ad targeting data collection"
                                },
                                source="browser_analyzer"
                            )
                            
                            threats.append(threat)
                            
                            if self.callback:
                                self.callback(threat)
            
            # Check for social media cookies (potential tracking across sites)
            if "social" in category_domains:
                social_domains = category_domains["social"]
                
                for domain in social_domains:
                    cookies = domain_cookies[domain]
                    
                    # Even a single cookie from social media can be tracking
                    threat = BrowserThreat(
                        type_=ThreatType.COOKIE_TRACKING,
                        level=ThreatLevel.MEDIUM,
                        description=f"Social media tracking detected from {domain}",
                        browser=browser_name,
                        threat_source="cookies",
                        details={
                            "domain": domain,
                            "cookie_count": len(cookies),
                            "cookies": cookies,
                            "category": "social",
                            "privacy_impact": "Medium - Social platform tracking your web activity"
                        },
                        source="browser_analyzer"
                    )
                    
                    threats.append(threat)
                    
                    if self.callback:
                        self.callback(threat)
            
            # Handle analytics and other lower-risk categories
            for category in ["analytics", "attribution", "ad_verification"]:
                if category in category_domains:
                    domains = category_domains[category]
                    
                    # Only generate a threat if there are multiple domains in this category
                    if len(domains) >= 3:
                        total_cookies = sum(len(domain_cookies[d]) for d in domains)
                        
                        threat = BrowserThreat(
                            type_=ThreatType.COOKIE_TRACKING,
                            level=ThreatLevel.LOW,
                            description=f"Multiple analytics trackers detected ({len(domains)} trackers)",
                            browser=browser_name,
                            threat_source="cookies",
                            details={
                                "domains": domains,
                                "cookie_count": total_cookies,
                                "category": category,
                                "privacy_impact": "Low - Website analytics and metrics tracking"
                            },
                            source="browser_analyzer"
                        )
                        
                        threats.append(threat)
                        
                        if self.callback:
                            self.callback(threat)
                
            return threats
            
        except Exception as e:
            logger.error(f"Error analyzing Chrome/Edge cookies: {e}")
            return threats
        finally:
            # Clean up
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    def analyze_local_storage_chrome(self, profile_path: Path) -> List[BrowserThreat]:
        """
        Analyze Chrome/Edge local storage for tracking and fingerprinting.
        
        Args:
            profile_path: Path to browser profile
            
        Returns:
            List of BrowserThreat objects
        """
        threats = []
        browser_name = "Edge" if "edge" in str(profile_path).lower() else "Chrome"
        
        # Path to local storage
        local_storage_path = profile_path / "Local Storage" / "leveldb"
        if not local_storage_path.exists():
            logger.warning(f"Local Storage directory not found at {local_storage_path}")
            return threats
            
        # Analyze LevelDB files
        fingerprinting_detected = False
        fingerprinting_evidence = []
        suspicious_storage_items = []
        suspicious_domains = set()
        
        try:
            # Extract content from LevelDB files
            content = ""
            js_files = list(local_storage_path.glob("*.ldb"))
            js_files.extend(local_storage_path.glob("*.log"))
            
            for file in js_files:
                try:
                    with open(file, 'rb') as f:
                        data = f.read()
                        # Extract readable strings
                        # This is a simple approach that works for basic text analysis
                        # A more robust approach would be to use a LevelDB parser
                        strings = re.findall(b'[\\x20-\\x7E]{8,}', data)
                        for s in strings:
                            try:
                                decoded = s.decode('utf-8', errors='ignore')
                                content += decoded + "\n"
                            except:
                                pass
                except Exception as e:
                    logger.warning(f"Error reading {file}: {e}")
            
            # Look for fingerprinting patterns
            for pattern in FINGERPRINTING_PATTERNS:
                if pattern in content:
                    fingerprinting_detected = True
                    fingerprinting_evidence.append(pattern)
            
            # Look for canvas fingerprinting
            canvas_fingerprinting = False
            canvas_evidence = []
            for pattern in CANVAS_FINGERPRINTING_PATTERNS:
                if pattern in content:
                    canvas_fingerprinting = True
                    canvas_evidence.append(pattern)
            
            # Look for WebRTC fingerprinting
            webrtc_fingerprinting = False
            webrtc_evidence = []
            for pattern in WEBRTC_FINGERPRINTING_PATTERNS:
                if pattern in content:
                    webrtc_fingerprinting = True
                    webrtc_evidence.append(pattern)
            
            # Look for suspicious localStorage keys
            for key in SUSPICIOUS_LOCALSTORAGE_KEYS:
                # Look for the key with quotes surrounding it (as it would be in JSON)
                pattern = f'"{key}":'
                if pattern in content:
                    suspicious_storage_items.append(key)
                    
                    # Try to extract the domain
                    lines = content.split('\n')
                    for i, line in enumerate(lines):
                        if pattern in line:
                            # Look in nearby lines for domain information
                            context_lines = lines[max(0, i-5):i+5]
                            for context in context_lines:
                                if "http" in context:
                                    domain = self.detect_domain_from_url(context)
                                    suspicious_domains.add(domain)
            
            # If fingerprinting detected, create a threat
            if fingerprinting_detected:
                details = {
                    "fingerprinting_evidence": fingerprinting_evidence,
                    "canvas_fingerprinting": canvas_fingerprinting,
                    "canvas_evidence": canvas_evidence if canvas_fingerprinting else None,
                    "webrtc_fingerprinting": webrtc_fingerprinting,
                    "webrtc_evidence": webrtc_evidence if webrtc_fingerprinting else None,
                    "suspicious_storage_items": suspicious_storage_items,
                    "suspicious_domains": list(suspicious_domains) if suspicious_domains else ["unknown"],
                    "privacy_impact": "High - May track you even when cookies are cleared or in incognito mode"
                }
                
                threat = BrowserThreat(
                    type_=ThreatType.SUSPICIOUS_BEHAVIOR,
                    level=ThreatLevel.HIGH,
                    description=f"Browser fingerprinting detected in {browser_name} local storage",
                    browser=browser_name,
                    threat_source="local_storage",
                    url=None,
                    details=details,
                    source="browser_analyzer"
                )
                
                threats.append(threat)
                
                if self.callback:
                    self.callback(threat)
                    
        except Exception as e:
            logger.error(f"Error analyzing local storage: {e}")
            
        return threats
        
    def analyze_indexed_db_chrome(self, profile_path: Path) -> List[BrowserThreat]:
        """
        Analyze Chrome/Edge IndexedDB for tracking and persistent storage techniques.
        This method detects sites using IndexedDB for long-term tracking and data persistence
        even when cookies are cleared.
        
        Args:
            profile_path: Path to browser profile
            
        Returns:
            List of BrowserThreat objects
        """
        threats = []
        browser_name = "Edge" if "edge" in str(profile_path).lower() else "Chrome"
        
        # Path to IndexedDB
        indexed_db_path = profile_path / "IndexedDB"
        if not indexed_db_path.exists():
            logger.warning(f"IndexedDB directory not found at {indexed_db_path}")
            return threats
            
        # Look for suspicious domain patterns in IndexedDB folders
        suspicious_domains = []
        fingerprinting_domains = []
        large_storage_domains = []
        domain_storage_sizes = {}
        
        # Patterns indicating suspicious IndexedDB usage
        suspicious_db_names = [
            'fingerprint', 'device', 'visitor', 'tracking', 'uid', 
            'profile', 'identity', 'behavior', 'analytics', 'persist'
        ]
        
        try:
            # Analyze folder structure and sizes
            for folder in indexed_db_path.glob("*"):
                if folder.is_dir():
                    folder_name = folder.name.lower()
                    domain = None
                    
                    # Extract domain from folder name (Chrome format)
                    # Format examples: 
                    # - https_domain_0.indexeddb.leveldb
                    # - domain.com_0.indexeddb.blob
                    if "https_" in folder_name and "_" in folder_name:
                        parts = folder_name.split("_")
                        if len(parts) > 1:
                            domain = parts[1].replace("-", ".")
                    elif ".indexeddb" in folder_name:
                        parts = folder_name.split(".")
                        if parts:
                            domain = parts[0].replace("-", ".")
                    
                    if not domain:
                        continue
                    
                    # Calculate storage size
                    folder_size = 0
                    for file_path in folder.glob("**/*"):
                        if file_path.is_file():
                            folder_size += file_path.stat().st_size
                    
                    domain_storage_sizes[domain] = folder_size
                    
                    # Check for large storage (>500KB)
                    if folder_size > 500 * 1024:
                        large_storage_domains.append((domain, folder_size))
                    
                    # Check for suspicious database names in leveldb files
                    has_suspicious_db = False
                    for db_file in folder.glob("*.ldb"):
                        if db_file.is_file():
                            try:
                                with open(db_file, 'rb') as f:
                                    content = f.read().decode('utf-8', errors='ignore')
                                    for pattern in suspicious_db_names:
                                        if pattern in content.lower():
                                            has_suspicious_db = True
                                            break
                            except:
                                pass
                        
                        if has_suspicious_db:
                            break
                    
                    # Check if it's a known tracking domain
                    is_tracking, category = self.is_tracking_domain(domain)
                    
                    # Determine threat classification
                    if is_tracking:
                        if category == "fingerprinting" or has_suspicious_db:
                            fingerprinting_domains.append((domain, category, folder_size))
                        elif category in ["session_replay", "cross_site"]:
                            suspicious_domains.append((domain, category, folder_size))
                    elif has_suspicious_db:
                        suspicious_domains.append((domain, "suspicious_storage", folder_size))
            
            # Create threats for fingerprinting domains
            for domain, category, size in fingerprinting_domains:
                # Convert size to human-readable format
                size_mb = size / (1024 * 1024)
                
                threat = BrowserThreat(
                    type_=ThreatType.SUSPICIOUS_CONNECTION,
                    level=ThreatLevel.HIGH,
                    description=f"Advanced fingerprinting detected in {browser_name} IndexedDB from {domain}",
                    browser=browser_name,
                    threat_source="indexeddb",
                    url=f"https://{domain}",
                    details={
                        "domain": domain,
                        "category": category,
                        "storage_size_bytes": size,
                        "storage_size_mb": f"{size_mb:.2f} MB",
                        "privacy_impact": "High - Persistent storage used for browser fingerprinting and tracking",
                        "concern": "This site may be able to identify you even in private/incognito mode or after clearing cookies"
                    },
                    source="browser_analyzer"
                )
                
                threats.append(threat)
                
                if self.callback:
                    self.callback(threat)
            
            # Create threats for suspicious domains
            for domain, category, size in suspicious_domains:
                # Convert size to human-readable format
                size_mb = size / (1024 * 1024)
                
                # Determine description based on category
                if category == "session_replay":
                    description = f"Session recording data detected in {browser_name} IndexedDB from {domain}"
                    privacy_impact = "High - Your browsing behavior may be recorded in detail"
                elif category == "cross_site":
                    description = f"Cross-site tracking detected in {browser_name} IndexedDB from {domain}"
                    privacy_impact = "Medium - This site may track you across multiple websites"
                else:
                    description = f"Suspicious data storage detected in {browser_name} IndexedDB from {domain}"
                    privacy_impact = "Medium - Persistent tracking data storage"
                
                threat = BrowserThreat(
                    type_=ThreatType.COOKIE_TRACKING,
                    level=ThreatLevel.MEDIUM,
                    description=description,
                    browser=browser_name,
                    threat_source="indexeddb",
                    url=f"https://{domain}",
                    details={
                        "domain": domain,
                        "category": category,
                        "storage_size_bytes": size,
                        "storage_size_mb": f"{size_mb:.2f} MB",
                        "privacy_impact": privacy_impact
                    },
                    source="browser_analyzer"
                )
                
                threats.append(threat)
                
                if self.callback:
                    self.callback(threat)
            
            # Create additional threats for very large storage domains that weren't already flagged
            for domain, size in large_storage_domains:
                # Skip domains already reported as fingerprinting or suspicious
                already_reported = False
                for d, _, _ in fingerprinting_domains + suspicious_domains:
                    if d == domain:
                        already_reported = True
                        break
                
                if already_reported:
                    continue
                
                # Convert size to human-readable format
                size_mb = size / (1024 * 1024)
                
                # Only report if storage is significant (>2MB)
                if size_mb > 2.0:
                    threat_level = ThreatLevel.MEDIUM
                    if size_mb > 10.0:
                        threat_level = ThreatLevel.HIGH
                    
                    threat = BrowserThreat(
                        type_=ThreatType.SUSPICIOUS_BEHAVIOR,
                        level=threat_level,
                        description=f"Unusually large data storage ({size_mb:.1f} MB) detected in {browser_name} IndexedDB from {domain}",
                        browser=browser_name,
                        threat_source="indexeddb",
                        url=f"https://{domain}",
                        details={
                            "domain": domain,
                            "storage_size_bytes": size,
                            "storage_size_mb": f"{size_mb:.2f} MB",
                            "concern": "Large persistent storage may be used for tracking or excessive data collection",
                            "privacy_impact": "Medium - May retain browsing data even after clearing cookies",
                            "recommendation": "Consider clearing IndexedDB storage or using private browsing mode"
                        },
                        source="browser_analyzer"
                    )
                    
                    threats.append(threat)
                    
                    if self.callback:
                        self.callback(threat)
                    
        except Exception as e:
            logger.error(f"Error analyzing IndexedDB: {e}")
            
        return threats
            
    def analyze_history_chrome(self, profile_path: Path) -> List[BrowserThreat]:
        """
        Analyze Chrome/Edge history for known tracking sites and suspicious patterns.
        
        Args:
            profile_path: Path to browser profile
            
        Returns:
            List of BrowserThreat objects
        """
        threats = []
        browser_name = "Edge" if "edge" in str(profile_path).lower() else "Chrome"
        
        # Path to History database
        history_db = profile_path / "History"
        if not history_db.exists():
            logger.warning(f"History database not found at {history_db}")
            return threats
            
        # Create a copy of the database to avoid lock issues
        temp_dir = tempfile.mkdtemp()
        temp_db = Path(temp_dir) / "history.db"
        
        try:
            shutil.copy2(history_db, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get URLs from history
            cursor.execute("SELECT url, visit_count FROM urls ORDER BY visit_count DESC LIMIT 1000")
            
            # Analyze for tracking domains
            tracking_sites = {}
            fingerprinting_sites = {}
            unique_tracking_categories = set()
            
            for row in cursor.fetchall():
                url = row[0]
                visit_count = row[1]
                
                domain = self.detect_domain_from_url(url)
                
                # Check if it's a known tracking domain
                is_tracking, category = self.is_tracking_domain(domain)
                if is_tracking:
                    unique_tracking_categories.add(category)
                    
                    if category == "fingerprinting":
                        if domain not in fingerprinting_sites:
                            fingerprinting_sites[domain] = {
                                "visit_count": 0,
                                "category": category,
                                "urls": []
                            }
                        fingerprinting_sites[domain]["visit_count"] += visit_count
                        fingerprinting_sites[domain]["urls"].append(url[:100])  # Limit URL length
                        
                    elif category in ["session_replay", "cross_site"]:
                        if domain not in tracking_sites:
                            tracking_sites[domain] = {
                                "visit_count": 0,
                                "category": category,
                                "urls": []
                            }
                        tracking_sites[domain]["visit_count"] += visit_count
                        tracking_sites[domain]["urls"].append(url[:100])  # Limit URL length
            
            conn.close()
            
            # Create threats for fingerprinting sites
            for domain, data in fingerprinting_sites.items():
                threat = BrowserThreat(
                    type_=ThreatType.SUSPICIOUS_CONNECTION,
                    level=ThreatLevel.HIGH,
                    description=f"Frequent visits to fingerprinting site {domain} detected in {browser_name} history",
                    browser=browser_name,
                    threat_source="history",
                    url=f"https://{domain}",
                    details={
                        "domain": domain,
                        "visit_count": data["visit_count"],
                        "category": data["category"],
                        "sample_urls": data["urls"][:5],  # Limit to 5 example URLs
                        "privacy_impact": "High - Persistent tracking across browsing sessions"
                    },
                    source="browser_analyzer"
                )
                
                threats.append(threat)
                
                if self.callback:
                    self.callback(threat)
            
            # Create threats for tracking sites
            for domain, data in tracking_sites.items():
                threat = BrowserThreat(
                    type_=ThreatType.COOKIE_TRACKING,
                    level=ThreatLevel.MEDIUM,
                    description=f"Frequent visits to tracking site {domain} detected in {browser_name} history",
                    browser=browser_name,
                    threat_source="history",
                    url=f"https://{domain}",
                    details={
                        "domain": domain,
                        "visit_count": data["visit_count"],
                        "category": data["category"],
                        "sample_urls": data["urls"][:5],  # Limit to 5 example URLs
                        "privacy_impact": "Medium - Tracking across multiple browsing sessions"
                    },
                    source="browser_analyzer"
                )
                
                threats.append(threat)
                
                if self.callback:
                    self.callback(threat)
            
            # If many types of tracking detected, create an overall threat
            if len(unique_tracking_categories) >= 3:
                threat = BrowserThreat(
                    type_=ThreatType.SUSPICIOUS_BEHAVIOR,
                    level=ThreatLevel.HIGH,
                    description=f"Multiple types of tracking technologies detected in {browser_name} browsing history",
                    browser=browser_name,
                    threat_source="history_analysis",
                    url=None,
                    details={
                        "tracking_categories": list(unique_tracking_categories),
                        "fingerprinting_domains": list(fingerprinting_sites.keys()),
                        "tracking_domains": list(tracking_sites.keys()),
                        "privacy_impact": "High - Comprehensive tracking profile may exist"
                    },
                    source="browser_analyzer"
                )
                
                threats.append(threat)
                
                if self.callback:
                    self.callback(threat)
                    
        except Exception as e:
            logger.error(f"Error analyzing browser history: {e}")
            
        finally:
            # Clean up temp directory
            try:
                shutil.rmtree(temp_dir)
            except:
                pass
                
        return threats

    def analyze_cookies_firefox(self, profile_path: Path) -> List[BrowserThreat]:
        """
        Analyze Firefox cookies for tracking with enhanced detection.
        
        Args:
            profile_path: Path to browser profile
            
        Returns:
            List of BrowserThreat objects
        """
        threats = []
        cookies_db = profile_path / "cookies.sqlite"
        
        if not cookies_db.exists():
            logger.warning(f"Cookies database not found at {cookies_db}")
            return threats
            
        # Create a copy of the database to avoid lock issues
        temp_dir = tempfile.mkdtemp()
        temp_db = Path(temp_dir) / "cookies.sqlite"
        try:
            shutil.copy2(cookies_db, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            cursor.execute("SELECT host, name, value, path, expiry, isSecure, isHttpOnly, creationTime FROM moz_cookies")
            
            tracking_cookies = []
            
            for row in cursor.fetchall():
                domain = row[0]
                if domain.startswith('.'):
                    domain = domain[1:]
                    
                is_tracking, category = self.is_tracking_domain(domain)
                if is_tracking:
                    tracking_cookies.append({
                        "domain": domain,
                        "name": row[1],
                        "path": row[3],
                        "secure": bool(row[5]),
                        "httponly": bool(row[6]),
                        "category": category
                    })
                    
            conn.close()
            
            # Group cookies by domain
            domain_cookies = {}
            domain_categories = {}
            
            for cookie in tracking_cookies:
                domain = cookie["domain"]
                category = cookie["category"]
                
                if domain not in domain_cookies:
                    domain_cookies[domain] = []
                    domain_categories[domain] = category
                
                domain_cookies[domain].append(cookie)
                
            # Create threats for each domain with tracking cookies
            browser_name = "Firefox"
            
            # Group domains by tracking category for analysis
            category_domains = {}
            for domain, category in domain_categories.items():
                if category not in category_domains:
                    category_domains[category] = []
                category_domains[category].append(domain)
            
            # Check for high-risk fingerprinting or session replay
            for high_risk_category in ["fingerprinting", "session_replay", "cross_site"]:
                if high_risk_category in category_domains:
                    domains = category_domains[high_risk_category]
                    
                    # Create a high severity threat for each domain
                    for domain in domains:
                        cookies = domain_cookies[domain]
                        
                        description = ""
                        if high_risk_category == "fingerprinting":
                            description = f"HIGH RISK: Browser fingerprinting detected from {domain}"
                            threat_type = ThreatType.SUSPICIOUS_CONNECTION
                        elif high_risk_category == "session_replay":
                            description = f"HIGH RISK: Session recording detected from {domain}"
                            threat_type = ThreatType.SUSPICIOUS_CONNECTION
                        else:  # cross_site
                            description = f"HIGH RISK: Cross-site tracking detected from {domain}"
                            threat_type = ThreatType.COOKIE_TRACKING
                        
                        threat = BrowserThreat(
                            type_=threat_type,
                            level=ThreatLevel.HIGH,
                            description=description,
                            browser=browser_name,
                            threat_source="cookies",
                            details={
                                "domain": domain,
                                "cookie_count": len(cookies),
                                "cookies": cookies,
                                "category": high_risk_category,
                                "privacy_impact": "High - May track you across websites and build detailed profiles"
                            },
                            source="browser_analyzer"
                        )
                        
                        threats.append(threat)
                        
                        if self.callback:
                            self.callback(threat)
            
            # Check for excessive cookies from advertising networks or RTB
            for ad_category in ["advertising", "rtb"]:
                if ad_category in category_domains:
                    ad_domains = category_domains[ad_category]
                    ad_cookie_count = sum(len(domain_cookies[d]) for d in ad_domains)
                    
                    # If there are many ad cookies overall, create a general threat
                    if ad_cookie_count > 20:
                        threat = BrowserThreat(
                            type_=ThreatType.COOKIE_TRACKING,
                            level=ThreatLevel.MEDIUM,
                            description=f"Excessive advertising tracking detected ({ad_cookie_count} cookies from {len(ad_domains)} domains)",
                            browser=browser_name,
                            threat_source="cookies",
                            details={
                                "ad_cookie_count": ad_cookie_count,
                                "ad_domains": ad_domains,
                                "category": ad_category,
                                "privacy_impact": "Medium - Tracking for targeted advertising"
                            },
                            source="browser_analyzer"
                        )
                        
                        threats.append(threat)
                        
                        if self.callback:
                            self.callback(threat)
                    
                    # Also check individual domains with many cookies
                    for domain in ad_domains:
                        cookies = domain_cookies[domain]
                        if len(cookies) >= 5:  # Higher threshold for advertising
                            threat = BrowserThreat(
                                type_=ThreatType.COOKIE_TRACKING,
                                level=ThreatLevel.MEDIUM,
                                description=f"Excessive tracking from advertising network {domain}",
                                browser=browser_name,
                                threat_source="cookies",
                                details={
                                    "domain": domain,
                                    "cookie_count": len(cookies),
                                    "cookies": cookies,
                                    "category": ad_category,
                                    "privacy_impact": "Medium - Detailed ad targeting data collection"
                                },
                                source="browser_analyzer"
                            )
                            
                            threats.append(threat)
                            
                            if self.callback:
                                self.callback(threat)
            
            # Check for social media cookies (potential tracking across sites)
            if "social" in category_domains:
                social_domains = category_domains["social"]
                
                for domain in social_domains:
                    cookies = domain_cookies[domain]
                    
                    # Even a single cookie from social media can be tracking
                    threat = BrowserThreat(
                        type_=ThreatType.COOKIE_TRACKING,
                        level=ThreatLevel.MEDIUM,
                        description=f"Social media tracking detected from {domain}",
                        browser=browser_name,
                        threat_source="cookies",
                        details={
                            "domain": domain,
                            "cookie_count": len(cookies),
                            "cookies": cookies,
                            "category": "social",
                            "privacy_impact": "Medium - Social platform tracking your web activity"
                        },
                        source="browser_analyzer"
                    )
                    
                    threats.append(threat)
                    
                    if self.callback:
                        self.callback(threat)
            
            # Handle analytics and other lower-risk categories
            for category in ["analytics", "attribution", "ad_verification"]:
                if category in category_domains:
                    domains = category_domains[category]
                    
                    # Only generate a threat if there are multiple domains in this category
                    if len(domains) >= 3:
                        total_cookies = sum(len(domain_cookies[d]) for d in domains)
                        
                        threat = BrowserThreat(
                            type_=ThreatType.COOKIE_TRACKING,
                            level=ThreatLevel.LOW,
                            description=f"Multiple analytics trackers detected ({len(domains)} trackers)",
                            browser=browser_name,
                            threat_source="cookies",
                            details={
                                "domains": domains,
                                "cookie_count": total_cookies,
                                "category": category,
                                "privacy_impact": "Low - Website analytics and metrics tracking"
                            },
                            source="browser_analyzer"
                        )
                        
                        threats.append(threat)
                        
                        if self.callback:
                            self.callback(threat)
                
            return threats
            
        except Exception as e:
            logger.error(f"Error analyzing Firefox cookies: {e}")
            return threats
        finally:
            # Clean up
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    def scan_browser(self, browser: str) -> List[BrowserThreat]:
        """
        Scan browser data for threats with advanced detection of tracking techniques.
        
        This method performs comprehensive analysis of browser data including:
        - Cookie analysis
        - LocalStorage analysis
        - IndexedDB analysis
        - Browser history analysis
        - Canvas fingerprinting detection
        - WebRTC and network information leakage detection
        
        Args:
            browser: Browser name (chrome, firefox, edge)
            
        Returns:
            List of BrowserThreat objects
        """
        if browser not in self.browser_config["supported_browsers"]:
            logger.warning(f"Browser {browser} not supported")
            return []
            
        if not self.browser_config["scan_cookies"]:
            logger.info("Cookie scanning disabled in configuration")
            return []
            
        profile_path = self.get_browser_path(browser)
        if not profile_path:
            logger.warning(f"Could not find {browser} profile directory")
            return []
            
        threats = []
        
        try:
            if browser in ["chrome", "edge"]:
                # Analyze cookies (basic tracking detection)
                logger.info(f"Analyzing {browser} cookies...")
                cookie_threats = self.analyze_cookies_chrome(profile_path)
                threats.extend(cookie_threats)
                
                # Analyze local storage (fingerprinting detection)
                logger.info(f"Analyzing {browser} local storage...")
                local_storage_threats = self.analyze_local_storage_chrome(profile_path)
                threats.extend(local_storage_threats)
                
                # Analyze IndexedDB (persistent tracking detection)
                logger.info(f"Analyzing {browser} IndexedDB...")
                indexed_db_threats = self.analyze_indexed_db_chrome(profile_path)
                threats.extend(indexed_db_threats)
                
                # Analyze browser history for tracking patterns
                logger.info(f"Analyzing {browser} history...")
                history_threats = self.analyze_history_chrome(profile_path)
                threats.extend(history_threats)
                
            elif browser == "firefox":
                # Analyze cookies
                logger.info(f"Analyzing Firefox cookies...")
                cookie_threats = self.analyze_cookies_firefox(profile_path)
                threats.extend(cookie_threats)
                
                # TODO: Add Firefox-specific localStorage and IndexedDB analysis in the future
                # Firefox stores this data in different locations/formats
                logger.info("Advanced Firefox analysis not fully implemented yet")
                
            logger.info(f"Found {len(threats)} threats in {browser}")
            
            # Post-processing for duplicate and related threats
            consolidated_threats = self._consolidate_threats(threats)
            logger.info(f"Consolidated into {len(consolidated_threats)} threats")
            return consolidated_threats
            
        except Exception as e:
            logger.error(f"Error analyzing browser {browser}: {e}")
            return []
        
    def _consolidate_threats(self, threats: List[BrowserThreat]) -> List[BrowserThreat]:
        """
        Consolidate related threats to avoid duplicates and provide better context.
        
        Args:
            threats: List of detected browser threats
            
        Returns:
            Consolidated list of browser threats
        """
        if not threats:
            return []
            
        # Group threats by domain
        domain_threats = {}
        other_threats = []
        
        for threat in threats:
            details = threat.details if hasattr(threat, 'details') and threat.details else {}
            domain = None
            
            # Extract domain from different threat types
            if details and "domain" in details:
                domain = details["domain"]
            elif hasattr(threat, 'url') and threat.url:
                domain = self.detect_domain_from_url(threat.url)
                
            if domain:
                if domain not in domain_threats:
                    domain_threats[domain] = []
                domain_threats[domain].append(threat)
            else:
                other_threats.append(threat)
                
        # Consolidate threats from the same domain
        consolidated = []
        
        for domain, domain_threat_list in domain_threats.items():
            if len(domain_threat_list) == 1:
                # Only one threat for this domain, keep as is
                consolidated.append(domain_threat_list[0])
            else:
                # Multiple threats for the same domain
                # Determine highest severity level
                highest_level = max([t.level for t in domain_threat_list], 
                                  key=lambda l: {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[l.value])
                
                # Determine types of tracking for better description
                threat_sources = set([getattr(t, 'threat_source', 'unknown') for t in domain_threat_list])
                threat_types = set([t.type_ for t in domain_threat_list])
                browser = domain_threat_list[0].browser
                
                # Create consolidated description
                tracking_methods = []
                if "cookies" in threat_sources:
                    tracking_methods.append("cookies")
                if "local_storage" in threat_sources:
                    tracking_methods.append("local storage")
                if "indexeddb" in threat_sources:
                    tracking_methods.append("IndexedDB")
                if "history" in threat_sources:
                    tracking_methods.append("browsing history")
                    
                methods_text = ", ".join(tracking_methods)
                if not methods_text:
                    methods_text = "multiple tracking methods"
                    
                if ThreatType.SUSPICIOUS_CONNECTION in threat_types or ThreatType.SUSPICIOUS_BEHAVIOR in threat_types:
                    description = f"Advanced tracking detected from {domain} using {methods_text}"
                    threat_type = ThreatType.SUSPICIOUS_CONNECTION
                else:
                    description = f"Tracking detected from {domain} using {methods_text}"
                    threat_type = ThreatType.COOKIE_TRACKING
                
                # Consolidate details
                consolidated_details = {
                    "domain": domain,
                    "tracking_methods": list(threat_sources),
                    "threat_types": [t.value for t in threat_types],
                    "original_threats_count": len(domain_threat_list),
                    "privacy_impact": "High - Multiple tracking technologies used together"
                }
                
                # Create a new consolidated threat
                consolidated_threat = BrowserThreat(
                    type_=threat_type,
                    level=highest_level,
                    description=description,
                    browser=browser,
                    threat_source="multiple",
                    url=f"https://{domain}",
                    details=consolidated_details,
                    source="browser_analyzer"
                )
                
                consolidated.append(consolidated_threat)
        
        # Add other threats that weren't consolidated
        consolidated.extend(other_threats)
        
        return consolidated
    
    def scan_all_browsers(self) -> List[BrowserThreat]:
        """
        Scan all supported browsers for threats.
        
        Returns:
            List of BrowserThreat objects
        """
        threats = []
        
        for browser in self.browser_config["supported_browsers"]:
            browser_threats = self.scan_browser(browser)
            threats.extend(browser_threats)
            
        return threats
