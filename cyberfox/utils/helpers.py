"""
Helper functions for the CyberFox application.
"""
import os
import sys
import logging
import hashlib
import re
import platform
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

def get_home_directory() -> Path:
    """
    Get the user's home directory.
    
    Returns:
        Path to the home directory
    """
    return Path.home()

def get_system_temp_directory() -> Path:
    """
    Get the system temporary directory.
    
    Returns:
        Path to the temp directory
    """
    import tempfile
    return Path(tempfile.gettempdir())

def get_documents_directory() -> Path:
    """
    Get the user's documents directory.
    
    Returns:
        Path to the documents directory
    """
    home = get_home_directory()
    
    if platform.system() == "Windows":
        return home / "Documents"
    elif platform.system() == "Darwin":  # macOS
        return home / "Documents"
    else:  # Linux and others
        return home / "Documents"

def get_downloads_directory() -> Path:
    """
    Get the user's downloads directory.
    
    Returns:
        Path to the downloads directory
    """
    home = get_home_directory()
    
    if platform.system() == "Windows":
        return home / "Downloads"
    elif platform.system() == "Darwin":  # macOS
        return home / "Downloads"
    else:  # Linux and others
        return home / "Downloads"

def get_desktop_directory() -> Path:
    """
    Get the user's desktop directory.
    
    Returns:
        Path to the desktop directory
    """
    home = get_home_directory()
    
    if platform.system() == "Windows":
        return home / "Desktop"
    elif platform.system() == "Darwin":  # macOS
        return home / "Desktop"
    else:  # Linux and others
        return home / "Desktop"

def format_size(size_bytes: int) -> str:
    """
    Format a size in bytes to a human-readable string.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def format_time_elapsed(seconds: int) -> str:
    """
    Format time elapsed in seconds to a human-readable string.
    
    Args:
        seconds: Time in seconds
        
    Returns:
        Formatted time string
    """
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"

def calculate_file_hash(filepath: str, algorithm: str = "md5", block_size: int = 65536) -> Optional[str]:
    """
    Calculate the hash of a file.
    
    Args:
        filepath: Path to the file
        algorithm: Hash algorithm to use (md5, sha1, sha256)
        block_size: Size of chunks to read
        
    Returns:
        Hash digest as a hexadecimal string, or None if the file could not be read
    """
    try:
        if algorithm == "md5":
            hasher = hashlib.md5()
        elif algorithm == "sha1":
            hasher = hashlib.sha1()
        elif algorithm == "sha256":
            hasher = hashlib.sha256()
        else:
            logger.error(f"Unsupported hash algorithm: {algorithm}")
            return None
            
        with open(filepath, 'rb') as f:
            buf = f.read(block_size)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(block_size)
        return hasher.hexdigest()
    except (IOError, PermissionError) as e:
        logger.warning(f"Could not hash file {filepath}: {e}")
        return None

def is_valid_email(email: str) -> bool:
    """
    Check if a string is a valid email address.
    
    Args:
        email: Email address to check
        
    Returns:
        True if the email is valid, False otherwise
    """
    # Basic email validation pattern
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))

def is_exe_file(filepath: str) -> bool:
    """
    Check if a file is an executable.
    
    Args:
        filepath: Path to the file
        
    Returns:
        True if the file is an executable, False otherwise
    """
    if not os.path.isfile(filepath):
        return False
        
    # Check by extension
    ext = os.path.splitext(filepath)[1].lower()
    if ext in ['.exe', '.com', '.bat', '.cmd', '.msi', '.ps1', '.vbs', '.js', '.jar', '.sh']:
        return True
        
    # Check if file is executable on Unix-like systems
    if platform.system() != "Windows":
        return os.access(filepath, os.X_OK)
        
    return False

def get_file_type(filepath: str) -> str:
    """
    Get the type of a file.
    
    Args:
        filepath: Path to the file
        
    Returns:
        Type of the file as a string
    """
    try:
        import magic
        mime = magic.Magic(mime=True)
        return mime.from_file(filepath)
    except ImportError:
        # Fallback if python-magic is not available
        ext = os.path.splitext(filepath)[1].lower()
        
        # Map common extensions to MIME types
        ext_to_mime = {
            '.txt': 'text/plain',
            '.html': 'text/html',
            '.htm': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.bmp': 'image/bmp',
            '.svg': 'image/svg+xml',
            '.mp3': 'audio/mpeg',
            '.wav': 'audio/wav',
            '.mp4': 'video/mp4',
            '.avi': 'video/x-msvideo',
            '.mov': 'video/quicktime',
            '.wmv': 'video/x-ms-wmv',
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.ppt': 'application/vnd.ms-powerpoint',
            '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            '.zip': 'application/zip',
            '.rar': 'application/x-rar-compressed',
            '.tar': 'application/x-tar',
            '.gz': 'application/gzip',
            '.7z': 'application/x-7z-compressed',
            '.exe': 'application/x-msdownload',
            '.dll': 'application/x-msdownload',
            '.bin': 'application/octet-stream',
            '.dat': 'application/octet-stream',
        }
        
        return ext_to_mime.get(ext, 'application/octet-stream')

def remove_html_tags(text: str) -> str:
    """
    Remove HTML tags from a string.
    
    Args:
        text: Text to process
        
    Returns:
        Text with HTML tags removed
    """
    import re
    clean = re.compile('<.*?>')
    return re.sub(clean, '', text)

def is_file_hidden(filepath: str) -> bool:
    """
    Check if a file is hidden.
    
    Args:
        filepath: Path to the file
        
    Returns:
        True if the file is hidden, False otherwise
    """
    # Check by name (Unix-style hidden files)
    if os.path.basename(filepath).startswith('.'):
        return True
        
    # Check Windows hidden attribute
    if platform.system() == "Windows":
        try:
            import win32api
            import win32con
            attrs = win32api.GetFileAttributes(filepath)
            return attrs & win32con.FILE_ATTRIBUTE_HIDDEN
        except ImportError:
            # Fallback if pywin32 is not available
            return False
            
    return False

def get_system_drives() -> List[str]:
    """
    Get a list of system drives.
    
    Returns:
        List of drive paths
    """
    if platform.system() == "Windows":
        from ctypes import windll
        
        drives = []
        bitmask = windll.kernel32.GetLogicalDrives()
        for letter in range(65, 91):  # A to Z
            if bitmask & 1:
                drives.append(chr(letter) + ":\\")
            bitmask >>= 1
        return drives
    else:
        # On Unix-like systems, everything is mounted under root
        return ["/"]

def get_drive_info(drive_path: str) -> Dict[str, Any]:
    """
    Get information about a drive.
    
    Args:
        drive_path: Path to the drive
        
    Returns:
        Dictionary with drive information
    """
    try:
        total, used, free = shutil.disk_usage(drive_path)
        return {
            "path": drive_path,
            "total": total,
            "used": used,
            "free": free,
            "percent_used": (used / total) * 100 if total > 0 else 0
        }
    except Exception as e:
        logger.error(f"Error getting drive info for {drive_path}: {e}")
        return {
            "path": drive_path,
            "error": str(e)
        }

def is_admin() -> bool:
    """
    Check if the current process is running with administrator/root privileges.
    
    Returns:
        True if running as admin/root, False otherwise
    """
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        # On Unix-like systems, root has UID 0
        return os.geteuid() == 0

def is_process_running(process_name: str) -> bool:
    """
    Check if a process is running.
    
    Args:
        process_name: Name of the process
        
    Returns:
        True if the process is running, False otherwise
    """
    try:
        import psutil
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == process_name:
                return True
        return False
    except ImportError:
        logger.warning("psutil not available, cannot check for running processes")
        return False

def get_browser_paths() -> Dict[str, str]:
    """
    Get paths to installed browsers.
    
    Returns:
        Dictionary mapping browser names to their executable paths
    """
    browsers = {}
    
    if platform.system() == "Windows":
        # Common browser locations on Windows
        program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
        
        paths = [
            (program_files + "\\Google\\Chrome\\Application\\chrome.exe", "chrome"),
            (program_files_x86 + "\\Google\\Chrome\\Application\\chrome.exe", "chrome"),
            (program_files + "\\Mozilla Firefox\\firefox.exe", "firefox"),
            (program_files_x86 + "\\Mozilla Firefox\\firefox.exe", "firefox"),
            (program_files + "\\Microsoft\\Edge\\Application\\msedge.exe", "edge"),
            (program_files_x86 + "\\Microsoft\\Edge\\Application\\msedge.exe", "edge"),
        ]
        
        for path, name in paths:
            if os.path.exists(path):
                browsers[name] = path
                
    elif platform.system() == "Darwin":  # macOS
        paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Firefox.app/Contents/MacOS/firefox",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Safari.app/Contents/MacOS/Safari",
        ]
        
        names = ["chrome", "firefox", "edge", "safari"]
        
        for path, name in zip(paths, names):
            if os.path.exists(path):
                browsers[name] = path
                
    else:  # Linux and others
        import shutil
        
        paths = [
            "google-chrome",
            "chrome",
            "firefox",
            "microsoft-edge",
            "edge",
        ]
        
        for cmd in paths:
            path = shutil.which(cmd)
            if path:
                if "chrome" in cmd:
                    browsers["chrome"] = path
                elif "firefox" in cmd:
                    browsers["firefox"] = path
                elif "edge" in cmd:
                    browsers["edge"] = path
                    
    return browsers
