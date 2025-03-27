"""
Real-time system protection module for CyberFox.

This module provides continuous monitoring of the system for suspicious activities:
1. File system monitoring for suspicious file operations
2. Process monitoring for potentially malicious processes
3. Network connection monitoring
4. USB device monitoring
"""
import os
import re
import time
import queue
import socket
import logging
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Optional, Callable, Tuple, Any, Union

import psutil

from cyberfox.config import CONFIG
from cyberfox.utils.helpers import is_exe_file, get_file_type, format_size
from cyberfox.core.threats import Threat, FileThreat, ThreatType, ThreatLevel
from cyberfox.core.file_scanner import FileScanner

# Initialize logger
logger = logging.getLogger(__name__)

# Maximum queue size for events
MAX_QUEUE_SIZE = 1000

# Process reputation data
SUSPICIOUS_PROCESS_NAMES = [
    "netsh",
    "powershell",
    "cmd.exe",
    "regsvr32",
    "rundll32",
    "mshta",
    "schtasks",
    "wscript",
    "cscript",
    "bitsadmin",
    "certutil",
    "sc"
]

SUSPICIOUS_NETWORK_DESTINATIONS = [
    "127.0.0.1:4444",  # Common Metasploit
    "0.0.0.0",  # Listening on all interfaces
]

# Suspicious parent-child process combinations
SUSPICIOUS_PROCESS_CHAINS = [
    # Format: (parent_name, child_name)
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("iexplore.exe", "cmd.exe"),
    ("iexplore.exe", "powershell.exe"),
    ("chrome.exe", "cmd.exe"),
    ("chrome.exe", "powershell.exe"),
]

class FileSystemEvent:
    """Represents a file system event."""
    
    def __init__(self, event_type: str, path: str, is_directory: bool = False):
        """
        Initialize a file system event.
        
        Args:
            event_type: Type of event (created, modified, deleted)
            path: Path to the affected file/directory
            is_directory: Whether the path is a directory
        """
        self.event_type = event_type
        self.path = path
        self.is_directory = is_directory
        self.timestamp = datetime.now()


class ProcessEvent:
    """Represents a process-related event."""
    
    def __init__(self, event_type: str, pid: int, name: str, cmd_line: Optional[List[str]] = None, 
                 parent_pid: Optional[int] = None, parent_name: Optional[str] = None):
        """
        Initialize a process event.
        
        Args:
            event_type: Type of event (created, terminated)
            pid: Process ID
            name: Process name
            cmd_line: Command line arguments
            parent_pid: Parent process ID
            parent_name: Parent process name
        """
        self.event_type = event_type
        self.pid = pid
        self.name = name
        self.cmd_line = cmd_line or []
        self.parent_pid = parent_pid
        self.parent_name = parent_name
        self.timestamp = datetime.now()


class NetworkEvent:
    """Represents a network connection event."""
    
    def __init__(self, event_type: str, pid: int, process_name: str, 
                 local_addr: Tuple[str, int], remote_addr: Tuple[str, int], 
                 status: str, protocol: str = "TCP"):
        """
        Initialize a network event.
        
        Args:
            event_type: Type of event (established, closed)
            pid: Process ID
            process_name: Process name
            local_addr: Local address (ip, port)
            remote_addr: Remote address (ip, port)
            status: Connection status
            protocol: Protocol (TCP, UDP)
        """
        self.event_type = event_type
        self.pid = pid
        self.process_name = process_name
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.status = status
        self.protocol = protocol
        self.timestamp = datetime.now()


class USBEvent:
    """Represents a USB device-related event."""
    
    def __init__(self, event_type: str, device_id: str, device_name: Optional[str] = None):
        """
        Initialize a USB event.
        
        Args:
            event_type: Type of event (connected, disconnected)
            device_id: Device identifier
            device_name: Human-readable device name
        """
        self.event_type = event_type
        self.device_id = device_id
        self.device_name = device_name
        self.timestamp = datetime.now()


class RealTimeProtection:
    """Real-time system protection and monitoring module."""
    
    def __init__(self, callback: Optional[Callable[[Threat], None]] = None):
        """
        Initialize real-time protection.
        
        Args:
            callback: Function to call when a threat is detected
        """
        self.callback = callback
        self.config = CONFIG["realtime_protection"]
        self.file_scanner = FileScanner(callback)
        
        # Initialize queues for events
        self.filesystem_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.process_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.network_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.usb_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        
        # Initialize monitoring threads
        self.filesystem_thread = None
        self.process_thread = None
        self.network_thread = None
        self.usb_thread = None
        self.analyzer_thread = None
        
        # Initialize monitoring state
        self.monitoring = False
        self.prev_processes = {}
        self.prev_connections = {}
        self.prev_usb_devices = set()
        
        # Initialize monitoring statistics
        self.stats = {
            "start_time": None,
            "filesystem_events": 0,
            "process_events": 0,
            "network_events": 0,
            "usb_events": 0,
            "threats_detected": 0
        }
    
    def start_monitoring(self) -> bool:
        """
        Start real-time monitoring in separate threads.
        
        Returns:
            Boolean indicating if monitoring was started
        """
        if self.monitoring:
            logger.warning("Real-time protection is already running")
            return False
        
        self.monitoring = True
        self.stats["start_time"] = datetime.now()
        
        # Start monitoring threads
        if self.config["monitor_filesystem"]:
            self.filesystem_thread = threading.Thread(
                target=self._filesystem_monitor_thread,
                daemon=True
            )
            self.filesystem_thread.start()
            logger.info("File system monitoring started")
        
        if self.config["monitor_processes"]:
            self.process_thread = threading.Thread(
                target=self._process_monitor_thread,
                daemon=True
            )
            self.process_thread.start()
            logger.info("Process monitoring started")
        
        if self.config["monitor_network"]:
            self.network_thread = threading.Thread(
                target=self._network_monitor_thread,
                daemon=True
            )
            self.network_thread.start()
            logger.info("Network monitoring started")
        
        if self.config["monitor_usb"]:
            self.usb_thread = threading.Thread(
                target=self._usb_monitor_thread,
                daemon=True
            )
            self.usb_thread.start()
            logger.info("USB device monitoring started")
        
        # Start analyzer thread
        self.analyzer_thread = threading.Thread(
            target=self._analyzer_thread,
            daemon=True
        )
        self.analyzer_thread.start()
        logger.info("Real-time protection analyzer started")
        
        return True
    
    def stop_monitoring(self) -> None:
        """Stop real-time monitoring."""
        if not self.monitoring:
            logger.warning("Real-time protection is not running")
            return
        
        logger.info("Stopping real-time protection...")
        self.monitoring = False
        
        # Wait for threads to finish
        if self.filesystem_thread and self.filesystem_thread.is_alive():
            self.filesystem_thread.join(timeout=2.0)
        
        if self.process_thread and self.process_thread.is_alive():
            self.process_thread.join(timeout=2.0)
        
        if self.network_thread and self.network_thread.is_alive():
            self.network_thread.join(timeout=2.0)
        
        if self.usb_thread and self.usb_thread.is_alive():
            self.usb_thread.join(timeout=2.0)
        
        if self.analyzer_thread and self.analyzer_thread.is_alive():
            self.analyzer_thread.join(timeout=2.0)
        
        logger.info("Real-time protection stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get current monitoring statistics.
        
        Returns:
            Dictionary with monitoring statistics
        """
        stats = self.stats.copy()
        if stats["start_time"]:
            stats["uptime_seconds"] = (datetime.now() - stats["start_time"]).total_seconds()
        return stats
    
    def _filesystem_monitor_thread(self) -> None:
        """Thread function for monitoring file system events."""
        logger.info("File system monitoring thread started")
        
        # Initialize file system monitoring
        # We'll use different approaches depending on the platform:
        # - For Windows, we'll use ReadDirectoryChangesW via Python's watchdog library (if available)
        # - For Linux, we'll use inotify via Python's pyinotify library (if available)
        # - As a fallback, we'll use polling-based approach
        
        # For this implementation, we'll use a simple polling approach
        # to avoid external dependencies
        prev_files = {}
        monitored_paths = self.config.get("monitored_paths", [str(Path.home())])
        
        # Get initial file list
        for path in monitored_paths:
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        prev_files[file_path] = os.path.getmtime(file_path)
                    except (OSError, PermissionError):
                        pass
        
        while self.monitoring:
            # Sleep to reduce CPU usage
            time.sleep(5)
            
            # Check monitored paths
            current_files = {}
            for path in monitored_paths:
                try:
                    for root, _, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                current_files[file_path] = os.path.getmtime(file_path)
                            except (OSError, PermissionError):
                                pass
                except (OSError, PermissionError) as e:
                    logger.error(f"Error walking directory {path}: {e}")
            
            # Check for new or modified files
            for file_path, mtime in current_files.items():
                if file_path not in prev_files:
                    # New file
                    event = FileSystemEvent("created", file_path)
                    try:
                        self.filesystem_queue.put(event, block=False)
                        self.stats["filesystem_events"] += 1
                    except queue.Full:
                        logger.warning("File system event queue is full, event dropped")
                elif mtime > prev_files[file_path]:
                    # Modified file
                    event = FileSystemEvent("modified", file_path)
                    try:
                        self.filesystem_queue.put(event, block=False)
                        self.stats["filesystem_events"] += 1
                    except queue.Full:
                        logger.warning("File system event queue is full, event dropped")
            
            # Check for deleted files
            for file_path in set(prev_files.keys()) - set(current_files.keys()):
                event = FileSystemEvent("deleted", file_path)
                try:
                    self.filesystem_queue.put(event, block=False)
                    self.stats["filesystem_events"] += 1
                except queue.Full:
                    logger.warning("File system event queue is full, event dropped")
            
            # Update previous files
            prev_files = current_files
        
        logger.info("File system monitoring thread stopped")
    
    def _process_monitor_thread(self) -> None:
        """Thread function for monitoring process creation and termination."""
        logger.info("Process monitoring thread started")
        
        # Get initial process list
        self.prev_processes = {p.pid: p for p in psutil.process_iter(attrs=['name', 'cmdline', 'ppid'])}
        
        while self.monitoring:
            # Sleep to reduce CPU usage
            time.sleep(1)
            
            # Get current processes
            try:
                current_processes = {p.pid: p for p in psutil.process_iter(attrs=['name', 'cmdline', 'ppid'])}
            except Exception as e:
                logger.error(f"Error getting process list: {e}")
                continue
            
            # Check for new processes
            for pid, proc in current_processes.items():
                if pid not in self.prev_processes:
                    # New process
                    try:
                        name = proc.info['name'] or "Unknown"
                        cmd_line = proc.info['cmdline'] or []
                        ppid = proc.info['ppid']
                        parent_name = "Unknown"
                        
                        if ppid in current_processes:
                            parent_proc = current_processes[ppid]
                            parent_name = parent_proc.info['name'] or "Unknown"
                        
                        event = ProcessEvent(
                            "created",
                            pid,
                            name,
                            cmd_line,
                            ppid,
                            parent_name
                        )
                        
                        try:
                            self.process_queue.put(event, block=False)
                            self.stats["process_events"] += 1
                        except queue.Full:
                            logger.warning("Process event queue is full, event dropped")
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            
            # Check for terminated processes
            for pid in set(self.prev_processes.keys()) - set(current_processes.keys()):
                proc = self.prev_processes[pid]
                try:
                    name = proc.info['name'] or "Unknown"
                    event = ProcessEvent("terminated", pid, name)
                    
                    try:
                        self.process_queue.put(event, block=False)
                        self.stats["process_events"] += 1
                    except queue.Full:
                        logger.warning("Process event queue is full, event dropped")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Update previous processes
            self.prev_processes = current_processes
        
        logger.info("Process monitoring thread stopped")
    
    def _network_monitor_thread(self) -> None:
        """Thread function for monitoring network connections."""
        logger.info("Network monitoring thread started")
        
        # Get initial connections
        self.prev_connections = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.raddr and conn.pid:
                    key = (conn.pid, conn.laddr, conn.raddr, conn.status)
                    self.prev_connections[key] = conn
        except (psutil.AccessDenied, PermissionError):
            logger.warning("Permission denied when accessing network connections. Running without admin/root privileges may limit functionality.")
        
        while self.monitoring:
            # Sleep to reduce CPU usage
            time.sleep(1)
            
            # Get current connections
            current_connections = {}
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.laddr and conn.raddr and conn.pid:
                        key = (conn.pid, conn.laddr, conn.raddr, conn.status)
                        current_connections[key] = conn
            except (psutil.AccessDenied, PermissionError):
                continue
            
            # Check for new connections
            for key, conn in current_connections.items():
                if key not in self.prev_connections:
                    # New connection
                    try:
                        pid = conn.pid
                        try:
                            proc = psutil.Process(pid)
                            process_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            process_name = "Unknown"
                        
                        event = NetworkEvent(
                            "established",
                            pid,
                            process_name,
                            conn.laddr,
                            conn.raddr,
                            conn.status
                        )
                        
                        try:
                            self.network_queue.put(event, block=False)
                            self.stats["network_events"] += 1
                        except queue.Full:
                            logger.warning("Network event queue is full, event dropped")
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            
            # Check for closed connections
            for key in set(self.prev_connections.keys()) - set(current_connections.keys()):
                conn = self.prev_connections[key]
                try:
                    pid = conn.pid
                    try:
                        proc = psutil.Process(pid)
                        process_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = "Unknown"
                    
                    event = NetworkEvent(
                        "closed",
                        pid,
                        process_name,
                        conn.laddr,
                        conn.raddr,
                        "CLOSED"
                    )
                    
                    try:
                        self.network_queue.put(event, block=False)
                        self.stats["network_events"] += 1
                    except queue.Full:
                        logger.warning("Network event queue is full, event dropped")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Update previous connections
            self.prev_connections = current_connections
        
        logger.info("Network monitoring thread stopped")
    
    def _usb_monitor_thread(self) -> None:
        """Thread function for monitoring USB devices."""
        logger.info("USB device monitoring thread started")
        
        # Initial USB device detection depends on the platform
        # This is a simplified implementation that works across platforms
        self.prev_usb_devices = self._get_usb_devices()
        
        while self.monitoring:
            # Sleep to reduce CPU usage
            time.sleep(2)
            
            # Get current USB devices
            current_usb_devices = self._get_usb_devices()
            
            # Check for new devices
            for device_id in current_usb_devices - self.prev_usb_devices:
                device_name = self._get_usb_device_name(device_id)
                event = USBEvent("connected", device_id, device_name)
                
                try:
                    self.usb_queue.put(event, block=False)
                    self.stats["usb_events"] += 1
                except queue.Full:
                    logger.warning("USB event queue is full, event dropped")
            
            # Check for removed devices
            for device_id in self.prev_usb_devices - current_usb_devices:
                device_name = self._get_usb_device_name(device_id)
                event = USBEvent("disconnected", device_id, device_name)
                
                try:
                    self.usb_queue.put(event, block=False)
                    self.stats["usb_events"] += 1
                except queue.Full:
                    logger.warning("USB event queue is full, event dropped")
            
            # Update previous devices
            self.prev_usb_devices = current_usb_devices
        
        logger.info("USB device monitoring thread stopped")
    
    def _get_usb_devices(self) -> Set[str]:
        """
        Get a set of USB device IDs.
        
        Returns:
            Set of USB device IDs
        """
        devices = set()
        
        if os.name == 'nt':  # Windows
            try:
                # Use Windows Management Instrumentation (WMI)
                import wmi
                c = wmi.WMI()
                for device in c.Win32_USBHub():
                    devices.add(device.DeviceID)
            except ImportError:
                # Fallback if WMI is not available
                try:
                    output = subprocess.check_output(['wmic', 'path', 'Win32_USBHub', 'get', 'DeviceID']).decode('utf-8')
                    for line in output.strip().split('\n')[1:]:
                        if line.strip():
                            devices.add(line.strip())
                except (subprocess.SubprocessError, FileNotFoundError):
                    logger.warning("Could not get USB devices on Windows")
        
        elif os.name == 'posix':  # Linux/Mac
            try:
                # Check /proc/bus/usb if it exists (older Linux systems)
                if os.path.exists('/proc/bus/usb'):
                    for root, _, files in os.walk('/proc/bus/usb'):
                        for file in files:
                            if file.isdigit():
                                devices.add(os.path.join(root, file))
                
                # Check /sys/bus/usb/devices (newer Linux systems)
                if os.path.exists('/sys/bus/usb/devices'):
                    for device in os.listdir('/sys/bus/usb/devices'):
                        if ':' in device:  # Only include USB devices, not interfaces
                            devices.add(device)
                
                # On macOS, use system_profiler
                if os.path.exists('/usr/sbin/system_profiler'):
                    try:
                        output = subprocess.check_output(['system_profiler', 'SPUSBDataType']).decode('utf-8')
                        for line in output.split('\n'):
                            if 'Product ID:' in line:
                                product_id = line.split('Product ID:')[1].strip()
                                devices.add(product_id)
                    except subprocess.SubprocessError:
                        pass
            
            except (OSError, PermissionError) as e:
                logger.warning(f"Error getting USB devices: {e}")
        
        return devices
    
    def _get_usb_device_name(self, device_id: str) -> Optional[str]:
        """
        Get a human-readable name for a USB device.
        
        Args:
            device_id: USB device ID
            
        Returns:
            Human-readable device name or None
        """
        # This is a simplified implementation
        if os.name == 'nt':  # Windows
            try:
                import wmi
                c = wmi.WMI()
                for device in c.Win32_USBHub():
                    if device.DeviceID == device_id:
                        return device.Description
            except ImportError:
                pass
        
        elif os.name == 'posix':  # Linux/Mac
            if os.path.exists(f'/sys/bus/usb/devices/{device_id}/product'):
                try:
                    with open(f'/sys/bus/usb/devices/{device_id}/product', 'r') as f:
                        return f.read().strip()
                except (OSError, PermissionError):
                    pass
        
        return None
    
    def _analyzer_thread(self) -> None:
        """Thread function for analyzing events and detecting threats."""
        logger.info("Event analyzer thread started")
        
        while self.monitoring:
            # Process file system events
            try:
                while not self.filesystem_queue.empty():
                    event = self.filesystem_queue.get_nowait()
                    self._analyze_filesystem_event(event)
                    self.filesystem_queue.task_done()
            except Exception as e:
                logger.error(f"Error processing file system event: {e}")
            
            # Process process events
            try:
                while not self.process_queue.empty():
                    event = self.process_queue.get_nowait()
                    self._analyze_process_event(event)
                    self.process_queue.task_done()
            except Exception as e:
                logger.error(f"Error processing process event: {e}")
            
            # Process network events
            try:
                while not self.network_queue.empty():
                    event = self.network_queue.get_nowait()
                    self._analyze_network_event(event)
                    self.network_queue.task_done()
            except Exception as e:
                logger.error(f"Error processing network event: {e}")
            
            # Process USB events
            try:
                while not self.usb_queue.empty():
                    event = self.usb_queue.get_nowait()
                    self._analyze_usb_event(event)
                    self.usb_queue.task_done()
            except Exception as e:
                logger.error(f"Error processing USB event: {e}")
            
            # Sleep to reduce CPU usage
            time.sleep(0.1)
        
        logger.info("Event analyzer thread stopped")
    
    def _analyze_filesystem_event(self, event: FileSystemEvent) -> None:
        """
        Analyze a file system event for potential threats.
        
        Args:
            event: File system event to analyze
        """
        # Skip directories
        if event.is_directory:
            return
        
        # Only analyze created or modified files
        if event.event_type not in ['created', 'modified']:
            return
        
        # Skip non-existent files
        if not os.path.exists(event.path):
            return
        
        # Only analyze executable or suspicious file types
        file_path = event.path
        try:
            # Check if it's an executable
            if is_exe_file(file_path):
                logger.info(f"Scanning created/modified executable: {file_path}")
                self._scan_suspicious_file(file_path, "executable_file")
            
            # Check file extension for suspicious types
            file_ext = os.path.splitext(file_path)[1].lower()
            suspicious_extensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.jar', '.hta', '.scr']
            
            if file_ext in suspicious_extensions:
                logger.info(f"Scanning suspicious file type: {file_path}")
                self._scan_suspicious_file(file_path, "suspicious_extension")
            
            # Check for suspicious file names
            file_name = os.path.basename(file_path).lower()
            suspicious_names = [
                'crack', 'keygen', 'patch', 'hack', 'trojan', 'malware', 'virus', 
                'rootkit', 'exploit', 'backdoor'
            ]
            
            if any(name in file_name for name in suspicious_names):
                logger.info(f"Scanning file with suspicious name: {file_path}")
                self._scan_suspicious_file(file_path, "suspicious_name")
        
        except (OSError, PermissionError) as e:
            logger.warning(f"Error accessing file {file_path}: {e}")
    
    def _scan_suspicious_file(self, file_path: str, reason: str) -> None:
        """
        Scan a suspicious file for threats.
        
        Args:
            file_path: Path to the file
            reason: Reason for scanning
        """
        try:
            # Use the file scanner to check the file
            threat = self.file_scanner.scan_file(file_path)
            
            if threat:
                # Update the source to indicate it was found by real-time protection
                threat_details = threat.details or {}
                threat_details["detection_source"] = "realtime_protection"
                threat_details["detection_reason"] = reason
                threat.details = threat_details
                
                # Update statistics
                self.stats["threats_detected"] += 1
                
                # Notify callback
                if self.callback:
                    self.callback(threat)
                
                logger.warning(f"Realtime protection detected threat: {threat.description}")
        
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
    
    def _analyze_process_event(self, event: ProcessEvent) -> None:
        """
        Analyze a process event for potential threats.
        
        Args:
            event: Process event to analyze
        """
        # Only analyze process creation
        if event.event_type != 'created':
            return
        
        threat_found = False
        threat_level = ThreatLevel.LOW
        threat_details = {
            "pid": event.pid,
            "process_name": event.name,
            "parent_pid": event.parent_pid,
            "parent_name": event.parent_name,
            "command_line": event.cmd_line,
            "timestamp": event.timestamp,
            "detection_source": "realtime_protection",
            "detection_reasons": []
        }
        
        # Check for suspicious process names
        if any(suspect.lower() in event.name.lower() for suspect in SUSPICIOUS_PROCESS_NAMES):
            threat_found = True
            threat_details["detection_reasons"].append("suspicious_process_name")
            threat_level = ThreatLevel.MEDIUM
        
        # Check for suspicious parent-child process chains
        if event.parent_name and event.name:
            parent_child = (event.parent_name.lower(), event.name.lower())
            for suspicious_pair in SUSPICIOUS_PROCESS_CHAINS:
                if parent_child[0].startswith(suspicious_pair[0].lower()) and parent_child[1].startswith(suspicious_pair[1].lower()):
                    threat_found = True
                    threat_details["detection_reasons"].append("suspicious_process_chain")
                    threat_level = ThreatLevel.HIGH
                    break
        
        # Check for suspicious command-line arguments
        suspicious_args = [
            '-e', 'iex', 'invoke-expression', 'downloadstring', 'invoke-webrequest',
            'hidden', 'invoke-mimikatz', 'invoke-shellcode', 'bypass', 'encodedcommand',
            'base64', 'webclient', 'downloadfile', 'bitsadmin /transfer', 'regsvr32'
        ]
        
        cmd_line = ' '.join(event.cmd_line).lower() if event.cmd_line else ""
        if any(arg.lower() in cmd_line for arg in suspicious_args):
            threat_found = True
            threat_details["detection_reasons"].append("suspicious_command_line")
            threat_level = ThreatLevel.HIGH
        
        # Create threat if suspicious activity found
        if threat_found:
            description = f"Suspicious process activity detected: {event.name}"
            if event.parent_name:
                description += f" (parent: {event.parent_name})"
            
            threat = Threat(
                type_=ThreatType.SUSPICIOUS_BEHAVIOR,
                level=threat_level,
                description=description,
                details=threat_details,
                source="realtime_protection"
            )
            
            # Update statistics
            self.stats["threats_detected"] += 1
            
            # Notify callback
            if self.callback:
                self.callback(threat)
            
            logger.warning(f"Realtime protection detected threat: {description}")
    
    def _analyze_network_event(self, event: NetworkEvent) -> None:
        """
        Analyze a network event for potential threats.
        
        Args:
            event: Network event to analyze
        """
        # Only analyze established connections
        if event.event_type != 'established':
            return
        
        threat_found = False
        threat_level = ThreatLevel.LOW
        threat_details = {
            "pid": event.pid,
            "process_name": event.process_name,
            "local_address": f"{event.local_addr[0]}:{event.local_addr[1]}",
            "remote_address": f"{event.remote_addr[0]}:{event.remote_addr[1]}",
            "status": event.status,
            "protocol": event.protocol,
            "timestamp": event.timestamp,
            "detection_source": "realtime_protection",
            "detection_reasons": []
        }
        
        # Check for known malicious destinations
        remote_addr_str = f"{event.remote_addr[0]}:{event.remote_addr[1]}"
        if any(addr in remote_addr_str for addr in SUSPICIOUS_NETWORK_DESTINATIONS):
            threat_found = True
            threat_details["detection_reasons"].append("suspicious_destination")
            threat_level = ThreatLevel.HIGH
        
        # Check for uncommon ports that might indicate C2 traffic
        # Common legitimate services typically use well-known ports
        # Malware often uses uncommon ports or known ports for other protocols
        remote_port = event.remote_addr[1]
        suspicious_ports = [4444, 1337, 31337, 8080, 8090, 8000, 9001, 9002]
        if remote_port in suspicious_ports:
            threat_found = True
            threat_details["detection_reasons"].append("suspicious_port")
            threat_level = ThreatLevel.MEDIUM
        
        # Check for suspicious combinations (e.g., browser connecting to unusual ports)
        browsers = ['chrome.exe', 'firefox.exe', 'iexplore.exe', 'edge.exe', 'opera.exe', 'safari.exe']
        if any(browser in event.process_name.lower() for browser in browsers):
            if remote_port not in [80, 443, 8080, 8443]:
                threat_found = True
                threat_details["detection_reasons"].append("browser_unusual_port")
                threat_level = ThreatLevel.MEDIUM
        
        # Create threat if suspicious activity found
        if threat_found:
            description = f"Suspicious network connection detected: {event.process_name} connecting to {event.remote_addr[0]}:{event.remote_addr[1]}"
            
            threat = Threat(
                type_=ThreatType.SUSPICIOUS_CONNECTION,
                level=threat_level,
                description=description,
                details=threat_details,
                source="realtime_protection"
            )
            
            # Update statistics
            self.stats["threats_detected"] += 1
            
            # Notify callback
            if self.callback:
                self.callback(threat)
            
            logger.warning(f"Realtime protection detected threat: {description}")
    
    def _analyze_usb_event(self, event: USBEvent) -> None:
        """
        Analyze a USB event for potential threats.
        
        Args:
            event: USB event to analyze
        """
        # Only analyze connected devices
        if event.event_type != 'connected':
            return
        
        # Check if USB monitoring is enabled in the configuration
        if not self.config.get("monitor_usb_autorun", True):
            return
        
        logger.info(f"USB device connected: {event.device_name or event.device_id}")
        
        # In a real implementation, you would:
        # 1. Identify the drive letter of the connected USB device
        # 2. Check for autorun.inf and other potentially malicious files
        # 3. Scan the device for threats
        
        # This is a simplified implementation that logs the event
        # and triggers a notification but doesn't scan the device
        
        # Notify the user about the USB device
        device_name = event.device_name or event.device_id
        description = f"USB device connected: {device_name}"
        
        # Create a notification threat with low severity
        threat = Threat(
            type_=ThreatType.SUSPICIOUS_BEHAVIOR,
            level=ThreatLevel.LOW,
            description=description,
            details={
                "device_id": event.device_id,
                "device_name": event.device_name,
                "timestamp": event.timestamp,
                "detection_source": "realtime_protection",
                "action_required": "Consider scanning this device before use if it's from an untrusted source"
            },
            source="realtime_protection"
        )
        
        # Update statistics
        self.stats["threats_detected"] += 1
        
        # Notify callback
        if self.callback:
            self.callback(threat)