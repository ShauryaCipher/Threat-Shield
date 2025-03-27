"""
File system scanner for detecting malicious files and suspicious patterns.
"""
import os
import logging
import threading
import hashlib
import math
import json
import psutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Generator, Any, Set

try:
    import magic
except ImportError:
    # Fallback for systems without python-magic
    class FallbackMagic:
        def __init__(self, mime=False):
            self.mime = mime
            
        def from_file(self, filepath):
            """Simple fallback for basic file type detection"""
            if self.mime:
                ext = os.path.splitext(filepath)[1].lower()
                if ext in ['.exe', '.dll', '.sys']:
                    return "application/x-dosexec"
                elif ext in ['.txt', '.log']:
                    return "text/plain"
                elif ext in ['.html', '.htm']:
                    return "text/html"
                else:
                    return "application/octet-stream"
            else:
                return f"File {os.path.basename(filepath)}"
                
    class MagicModule:
        def Magic(self, mime=False):
            return FallbackMagic(mime)
            
    magic = MagicModule()

from cyberfox.core.threats import Threat, ThreatType, ThreatLevel, FileThreat

logger = logging.getLogger(__name__)

# Dictionary of known malicious file hashes
KNOWN_MALICIOUS_HASHES = {
    # Format: "hash": ThreatLevel.CRITICAL (or other level)
    # Will be populated from a database or online service in a real implementation
    "44d88612fea8a8f36de82e1278abb02f": ThreatLevel.CRITICAL,  # Example malware
    "5267b2f66a46f2675dcaf5c44eb9f244": ThreatLevel.HIGH,      # Example suspicious file
}

# Suspicious byte patterns to look for
SUSPICIOUS_PATTERNS = {
    "command_execution": [
        b"CreateProcess",
        b"WinExec",
        b"ShellExecute",
        b"eval(",
        b"exec(",
        b"os.system",
        b"subprocess",
        b"powershell",
        b"cmd.exe",
    ],
    "network_activity": [
        b"http://",
        b"https://",
        b"socket",
        b"connect(",
        b"recv(",
        b"send(",
    ],
    "file_operations": [
        b"CreateFile",
        b"WriteFile",
        b"DeleteFile",
        b"fopen",
        b"fwrite",
        b"unlink(",
    ],
    "registry_manipulation": [
        b"RegCreate",
        b"RegSet",
        b"RegDelete",
        b"HKEY_LOCAL_MACHINE",
        b"HKEY_CURRENT_USER",
    ],
    "encryption": [
        b"CryptEncrypt",
        b"AES",
        b"Rijndael",
        b"Crypto",
        b".encrypt",
    ],
    "anti_analysis": [
        b"IsDebuggerPresent",
        b"CheckRemoteDebuggerPresent",
        b"NtGlobalFlag",
        b"IsProcessorFeaturePresent",
        b"GetTickCount",
    ],
    "persistence": [
        b"Run\\",
        b"RunOnce",
        b"Startup",
        b"Registry.CurrentUser",
        b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    ],
    "data_exfiltration": [
        b"POST ",
        b"password",
        b"login",
        b"credentials",
        b"Cookie:",
    ],
    "memory_manipulation": [
        b"VirtualAlloc",
        b"VirtualProtect",
        b"WriteProcessMemory",
        b"memcpy",
    ],
    "system_modification": [
        b"SetWindowsHook",
        b"CreateService",
        b"StartService",
        b"DllRegisterServer",
    ],
    "macro_execution": [
        b"AutoExec",
        b"Document_Open",
        b"Auto_Open",
        b"VBA",
        b"ThisDocument",
    ],
    "obfuscation": [
        b"StrReverse",
        b"Chr(",
        b"base64",
        b"charCodeAt",
        b"fromCharCode",
        b"atob",
        b"btoa",
    ],
}

class FileScanner:
    """Scans file system for malicious content and suspicious patterns."""
    
    def __init__(self, callback: Optional[callable] = None):
        """
        Initialize the file scanner.
        
        Args:
            callback: Function to call when a threat is detected
        """
        self.callback = callback
        self.stop_scan = False
        self.current_scan = None
        
        # Default scan configuration
        self.scan_config = {
            "scan_hidden_files": False,
            "scan_system_files": False,
            "scan_external_drives": True,
            "max_file_size_mb": 100,
            "file_extensions": [
                ".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs", ".js", ".py", 
                ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".rtf", ".ppt", ".pptx",
                ".sh", ".php", ".jsp", ".aspx", ".jar", ".zip", ".rar", ".7z", ".tar.gz"
            ]
        }
        
        # Scan statistics
        self._scan_stats = {
            "files_scanned": 0,
            "threats_found": 0,
            "bytes_scanned": 0,
            "start_time": None,
            "end_time": None,
            "current_file": None,
            "progress": 0.0
        }
        
    def scan_stats(self) -> Dict:
        """Return current scan statistics."""
        return self._scan_stats
        
    def calculate_file_hash(self, filepath: str, block_size: int = 65536) -> Optional[str]:
        """
        Calculate MD5 hash of a file.
        
        Args:
            filepath: Path to the file
            block_size: Size of chunks to read from file
            
        Returns:
            MD5 hash of the file as a hexadecimal string, or None if the file could not be read
        """
        try:
            md5 = hashlib.md5()
            with open(filepath, 'rb') as f:
                for block in iter(lambda: f.read(block_size), b''):
                    md5.update(block)
            return md5.hexdigest()
        except (IOError, PermissionError) as e:
            logger.warning(f"Could not calculate hash for {filepath}: {e}")
            return None
            
    def is_suspicious_content(self, filepath: str, block_size: int = 65536) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Check if file contains suspicious patterns using advanced heuristic detection.
        
        Implements multiple detection layers:
        1. Signature-based detection for known patterns
        2. Entropy analysis for encryption/packing
        3. Behavioral analysis based on functionality
        4. Contextual analysis based on file location and type
        
        Args:
            filepath: Path to the file
            block_size: Size of chunks to read from file
            
        Returns:
            Tuple of (is_suspicious, reason, details)
        """
        try:
            # Get file extension and size
            file_ext = os.path.splitext(filepath)[1].lower()
            file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            
            # Analyze executables with special attention
            is_executable = file_ext in ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.cmd', '.scr', '.pif', '.com']
            is_script = file_ext in ['.ps1', '.vbs', '.js', '.py', '.bat', '.cmd', '.sh']
            is_document = file_ext in ['.doc', '.docx', '.xls', '.xlsx', '.pdf', '.rtf']
            is_packed = False
            
            # Initialize detailed threat analysis
            found_patterns = {}
            threat_score = 0
            entropy_score = 0
            behavioral_indicators = {}
            
            # Full file analysis for smaller files, or block analysis for larger files
            if file_size <= block_size * 2 or is_executable:
                # Read complete file for thorough analysis
                with open(filepath, 'rb') as f:
                    content = f.read()
            else:
                # Read first and last blocks for larger files
                with open(filepath, 'rb') as f:
                    first_block = f.read(block_size)
                    
                    # Try to seek to the end block
                    try:
                        f.seek(-block_size, os.SEEK_END)
                        last_block = f.read(block_size)
                        content = first_block + last_block
                    except:
                        # If seeking fails, just use the first block
                        content = first_block
            
            # ----------------------------
            # 1. Pattern-based detection
            # ----------------------------
            # Check each category of suspicious patterns
            for category, patterns in SUSPICIOUS_PATTERNS.items():
                for pattern in patterns:
                    if pattern in content:
                        if category not in found_patterns:
                            found_patterns[category] = []
                        found_patterns[category].append(pattern.decode('utf-8', errors='ignore'))
                        
                        # Increment threat score based on category severity and context
                        base_score = 0
                        if category in ['command_execution', 'encryption', 'anti_analysis']:
                            base_score = 3  # More severe
                        elif category in ['memory_manipulation', 'system_modification', 'persistence']:
                            base_score = 2  # Moderately severe
                        else:
                            base_score = 1  # Less severe
                        
                        # Adjust score based on file type context
                        if is_executable and category in ['command_execution', 'anti_analysis', 'persistence']:
                            base_score *= 1.5  # More suspicious in executables
                        elif is_script and category in ['command_execution', 'system_modification']:
                            base_score *= 1.3  # Suspicious in scripts
                        elif is_document and category in ['command_execution', 'macro_execution']:
                            base_score *= 2.0  # Very suspicious in documents
                            
                        threat_score += base_score
            
            # ----------------------------
            # 2. Entropy analysis
            # ----------------------------
            # Calculate Shannon entropy to detect encryption/packing
            if file_size > 0:
                # Count byte frequencies
                byte_counts = {}
                for b in content:
                    byte_counts[b] = byte_counts.get(b, 0) + 1
                
                # Calculate entropy
                entropy = 0
                for count in byte_counts.values():
                    probability = count / len(content)
                    entropy -= probability * math.log2(probability)
                
                entropy_score = entropy
                
                # High entropy suggests encryption or packing
                if entropy > 7.8:  # Very high entropy
                    is_packed = True
                    threat_score += 3
                elif entropy > 7.0:  # High entropy
                    is_packed = True
                    threat_score += 1
            
            # ----------------------------
            # 3. Behavioral analysis
            # ----------------------------
            # Check for obfuscated scripts
            if is_script and any(pattern in content for pattern in SUSPICIOUS_PATTERNS["obfuscation"]):
                obfuscation_count = sum(1 for pattern in SUSPICIOUS_PATTERNS["obfuscation"] if pattern in content)
                behavioral_indicators["obfuscated_script"] = obfuscation_count
                threat_score += min(obfuscation_count, 3)
            
            # Check for packed executables
            if is_executable and is_packed:
                behavioral_indicators["packed_executable"] = True
                threat_score += 2
            
            # ----------------------------
            # 4. Contextual analysis
            # ----------------------------
            # Check for executable in temp directory
            temp_dir = os.environ.get('TEMP', '') or os.environ.get('TMP', '')
            is_in_temp = temp_dir and temp_dir in filepath
            if is_in_temp and is_executable:
                behavioral_indicators["executable_in_temp"] = True
                threat_score += 2
            
            # Check for hidden files
            is_hidden = os.path.basename(filepath).startswith('.')
            if os.name == 'nt':
                try:
                    import ctypes
                    file_attribute_hidden = 2
                    attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
                    is_hidden = is_hidden or (attrs != -1 and bool(attrs & file_attribute_hidden))
                except Exception:
                    pass
            
            if is_hidden and is_executable:
                behavioral_indicators["hidden_executable"] = True
                threat_score += 1
            
            # Check for unusual locations
            system_dirs = ['windows', 'system32', 'program files']
            unusual_location = False
            if is_executable:
                if not any(d.lower() in filepath.lower() for d in system_dirs) and not filepath.lower().startswith('/usr/'):
                    unusual_location = True
            
            # Analyze potential exploit documents
            if is_document and any(pattern in content for pattern in SUSPICIOUS_PATTERNS["macro_execution"]):
                behavioral_indicators["potential_exploit_document"] = True
                threat_score += 2
            
            # Combine all analysis results
            if found_patterns or entropy_score > 7.0 or behavioral_indicators:
                # Generate a comprehensive reason based on all findings
                reasons = []
                
                if found_patterns:
                    categories = list(found_patterns.keys())
                    if len(categories) == 1:
                        reasons.append(f"Contains {categories[0]} pattern")
                    else:
                        reasons.append(f"Contains multiple suspicious patterns: {', '.join(categories)}")
                
                if entropy_score > 7.0:
                    reasons.append(f"High entropy suggesting encryption/packing ({entropy_score:.2f})")
                
                for indicator, value in behavioral_indicators.items():
                    if indicator == 'obfuscated_script':
                        reasons.append(f"Script contains obfuscation techniques ({value} markers)")
                    elif indicator == 'packed_executable':
                        reasons.append("Executable appears to be packed/protected")
                    elif indicator == 'executable_in_temp':
                        reasons.append("Executable found in temporary directory")
                    elif indicator == 'hidden_executable':
                        reasons.append("Hidden executable file")
                    elif indicator == 'potential_exploit_document':
                        reasons.append("Document contains potential exploit markers")
                
                reason = " | ".join(reasons)
                
                # Compile detailed analysis
                details = {
                    "patterns": found_patterns,
                    "entropy_analysis": {
                        "score": entropy_score,
                        "is_packed": is_packed
                    },
                    "behavioral_analysis": behavioral_indicators,
                    "contextual_analysis": {
                        "is_in_temp": is_in_temp,
                        "is_hidden": is_hidden,
                        "unusual_location": unusual_location
                    },
                    "threat_score": threat_score,
                    "file_type": {
                        "is_executable": is_executable,
                        "is_script": is_script,
                        "is_document": is_document
                    }
                }
                
                # Higher score for combinations of different pattern types
                if found_patterns and len(list(found_patterns.keys())) > 1:
                    categories = list(found_patterns.keys())
                    threat_score += len(categories)
                    
                    # Particularly dangerous combinations
                    if 'encryption' in categories and any(c in categories for c in ['data_exfiltration', 'persistence']):
                        details["potential_ransomware"] = True
                        threat_score += 5
                        
                    if 'anti_analysis' in categories and any(c in categories for c in ['memory_manipulation', 'system_modification']):
                        details["potential_rootkit"] = True
                        threat_score += 5
                
                return True, reason, details
                
            return False, None, None
        except (IOError, PermissionError) as e:
            logger.warning(f"Could not scan content of {filepath}: {e}")
            return False, None, None
    
    def should_scan_file(self, filepath: str) -> bool:
        """
        Determine if a file should be scanned based on configuration.
        
        Args:
            filepath: Path to the file
            
        Returns:
            Boolean indicating if file should be scanned
        """
        path = Path(filepath)
        
        # Skip if file doesn't exist or is a directory
        if not path.is_file():
            return False
            
        # Check file size limit
        max_size = self.scan_config["max_file_size_mb"] * 1024 * 1024
        try:
            if path.stat().st_size > max_size:
                return False
        except (OSError, PermissionError):
            return False
            
        # Check if hidden (platform-independent approach)
        is_hidden = path.name.startswith('.')
        # Additional Windows-specific check for hidden attribute
        if os.name == 'nt':
            try:
                import ctypes
                file_attribute_hidden = 2
                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
                is_hidden = is_hidden or (attrs != -1 and bool(attrs & file_attribute_hidden))
            except (ImportError, AttributeError):
                # Fallback if ctypes not available or other issue
                pass
                
        if is_hidden and not self.scan_config["scan_hidden_files"]:
            return False
            
        # Check file extension
        if path.suffix.lower() in self.scan_config["file_extensions"]:
            return True
            
        # Check if it's an executable based on file header
        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(str(path))
            return "application/x-executable" in file_type or "application/x-dosexec" in file_type
        except Exception:
            # If we can't determine file type, err on the side of caution
            return True
            
    def scan_file(self, filepath: str) -> Optional[FileThreat]:
        """
        Scan a single file for threats.
        
        Args:
            filepath: Path to the file
            
        Returns:
            FileThreat object if a threat is found, None otherwise
        """
        if not self.should_scan_file(filepath):
            return None
            
        self._scan_stats["current_file"] = filepath
        
        try:
            # Update scan statistics
            filesize = os.path.getsize(filepath)
            self._scan_stats["files_scanned"] += 1
            self._scan_stats["bytes_scanned"] += filesize
            
            # Check hash against known malicious hashes
            file_hash = self.calculate_file_hash(filepath)
            if file_hash and file_hash in KNOWN_MALICIOUS_HASHES:
                threat_level = KNOWN_MALICIOUS_HASHES[file_hash]
                threat = FileThreat(
                    type_=ThreatType.MALWARE,
                    level=threat_level,
                    description=f"Known malicious file detected: {os.path.basename(filepath)}",
                    filepath=filepath,
                    hash_=file_hash,
                    file_size=filesize,
                    source="hash_database"
                )
                self._scan_stats["threats_found"] += 1
                if self.callback:
                    self.callback(threat)
                return threat
                
            # Check for suspicious content
            is_suspicious, reason, details = self.is_suspicious_content(filepath)
            if is_suspicious:
                # Determine threat level based on threat score
                threat_level = ThreatLevel.MEDIUM  # Default
                
                if details:
                    threat_score = details.get("threat_score", 0)
                    
                    if threat_score >= 10 or details.get("potential_ransomware", False):
                        threat_level = ThreatLevel.CRITICAL
                    elif threat_score >= 5 or details.get("potential_rootkit", False):
                        threat_level = ThreatLevel.HIGH
                    elif threat_score >= 3:
                        threat_level = ThreatLevel.MEDIUM
                    else:
                        threat_level = ThreatLevel.LOW
                
                # Determine threat type based on patterns
                threat_type = ThreatType.SUSPICIOUS_BEHAVIOR
                if details and details.get("patterns"):
                    patterns = details.get("patterns", {})
                    
                    if "encryption" in patterns and details.get("potential_ransomware", False):
                        threat_type = ThreatType.MALWARE
                        reason = f"Potential ransomware detected: {os.path.basename(filepath)}"
                    elif "anti_analysis" in patterns and details.get("potential_rootkit", False):
                        threat_type = ThreatType.MALWARE
                        reason = f"Potential rootkit detected: {os.path.basename(filepath)}"
                    elif "persistence" in patterns:
                        reason = f"Persistence mechanism detected in file: {os.path.basename(filepath)}"
                    elif "data_exfiltration" in patterns:
                        reason = f"Data exfiltration capabilities detected: {os.path.basename(filepath)}"
                
                threat = FileThreat(
                    type_=threat_type,
                    level=threat_level,
                    description=reason or f"Suspicious content detected in file: {os.path.basename(filepath)}",
                    details=details,
                    filepath=filepath,
                    hash_=file_hash,
                    file_size=filesize,
                    source="enhanced_pattern_matching"
                )
                self._scan_stats["threats_found"] += 1
                if self.callback:
                    self.callback(threat)
                return threat
                
            return None
            
        except Exception as e:
            logger.error(f"Error scanning file {filepath}: {e}")
            return None
    
    def get_drives(self) -> List[str]:
        """
        Get list of available drives to scan.
        
        Returns:
            List of drive paths
        """
        drives = []
        
        # Add system drive
        drives.append(os.path.abspath(os.sep))
        
        # Add removable drives if configured
        if self.scan_config["scan_external_drives"]:
            try:
                for partition in psutil.disk_partitions():
                    if 'removable' in partition.opts or 'cdrom' in partition.opts:
                        drives.append(partition.mountpoint)
            except Exception as e:
                logger.error(f"Error getting drives: {e}")
                
        return drives
    
    def walk_directory(self, root_path: str) -> Generator[str, None, None]:
        """
        Generator to walk through directory and yield file paths.
        
        Args:
            root_path: Starting directory path
            
        Yields:
            File paths to scan
        """
        for dirpath, dirnames, filenames in os.walk(root_path):
            # Check if scan was stopped
            if self.stop_scan:
                break
                
            # Skip hidden directories if configured
            if not self.scan_config["scan_hidden_files"]:
                dirnames[:] = [d for d in dirnames if not d.startswith('.')]
                
            for filename in filenames:
                yield os.path.join(dirpath, filename)
    
    def scan_path(self, path: str, recursive: bool = True) -> List[FileThreat]:
        """
        Scan a path for threats.
        
        Args:
            path: Path to scan
            recursive: Whether to scan recursively
            
        Returns:
            List of detected threats
        """
        threats = []
        
        if not os.path.exists(path):
            logger.warning(f"Path does not exist: {path}")
            return threats
            
        self._scan_stats["current_file"] = path
        
        if os.path.isfile(path):
            threat = self.scan_file(path)
            if threat:
                threats.append(threat)
        elif os.path.isdir(path) and recursive:
            file_count = sum([len(files) for _, _, files in os.walk(path)])
            processed = 0
            
            for filepath in self.walk_directory(path):
                if self.stop_scan:
                    break
                    
                threat = self.scan_file(filepath)
                if threat:
                    threats.append(threat)
                    
                processed += 1
                self._scan_stats["progress"] = processed / file_count if file_count > 0 else 1.0
                
        return threats
    
    def start_scan(self, paths: Optional[List[str]] = None, recursive: bool = True) -> None:
        """
        Start a new scan in a separate thread.
        
        Args:
            paths: List of paths to scan. If None, scan all drives.
            recursive: Whether to scan recursively
        """
        if self.current_scan and self.current_scan.is_alive():
            logger.warning("A scan is already in progress")
            return
            
        self.stop_scan = False
        self._scan_stats = {
            "files_scanned": 0,
            "threats_found": 0,
            "bytes_scanned": 0,
            "start_time": datetime.now(),
            "end_time": None,
            "current_file": None,
            "progress": 0.0
        }
        
        if not paths:
            paths = self.get_drives()
            
        self.current_scan = threading.Thread(
            target=self._scan_thread,
            args=(paths, recursive),
            daemon=True
        )
        self.current_scan.start()
        
    def _scan_thread(self, paths: List[str], recursive: bool) -> None:
        """
        Thread function to perform scanning.
        
        Args:
            paths: List of paths to scan
            recursive: Whether to scan recursively
        """
        threats = []
        
        try:
            for path in paths:
                if self.stop_scan:
                    break
                path_threats = self.scan_path(path, recursive)
                threats.extend(path_threats)
        except Exception as e:
            logger.error(f"Error during scan: {e}")
        finally:
            self._scan_stats["end_time"] = datetime.now()
            logger.info(f"Scan completed. Scanned {self._scan_stats['files_scanned']} files, "
                       f"found {self._scan_stats['threats_found']} threats.")
    
    def stop_scanning(self) -> None:
        """Stop the current scan."""
        self.stop_scan = True
        if self.current_scan and self.current_scan.is_alive():
            self.current_scan.join(timeout=2.0)