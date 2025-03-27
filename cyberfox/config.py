"""
Configuration settings for the CyberFox application.
"""
import os
import json
import yaml
from pathlib import Path

# Application name and version
APP_NAME = "CyberFox"
APP_VERSION = "1.0.0"

# Default paths
HOME_DIR = Path.home()
CONFIG_DIR = HOME_DIR / ".cyberfox"
LOGS_DIR = CONFIG_DIR / "logs"
SCANS_DIR = CONFIG_DIR / "scans"

# Ensure directories exist
CONFIG_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
SCANS_DIR.mkdir(exist_ok=True)

# Default configuration
DEFAULT_CONFIG = {
    "scan_settings": {
        "file_extensions": [".exe", ".dll", ".bat", ".js", ".vbs", ".ps1", ".py", ".jar", ".sh"],
        "max_file_size_mb": 100,
        "scan_system_files": False,
        "scan_hidden_files": True,
        "scan_external_drives": True
    },
    "darkweb_monitor": {
        "enable_tor": True,
        "search_interval_hours": 24,
        "keywords": [],
        "emails": []
    },
    "breach_check": {
        "enable_hibp": True,
        "check_interval_days": 7
    },
    "browser_analyzer": {
        "scan_cookies": True,
        "scan_history": False,
        "scan_saved_passwords": False,
        "supported_browsers": ["chrome", "firefox", "edge"]
    },
    "realtime_protection": {
        "enabled": True,
        "start_on_launch": True,
        "monitor_filesystem": True,
        "monitor_processes": True,
        "monitor_network": True,
        "monitor_usb": True,
        "monitor_usb_autorun": True,
        "monitored_paths": [str(Path.home())],
        "exclusions": {
            "paths": [],
            "processes": ["explorer.exe", "svchost.exe", "spoolsv.exe"],
            "network_ports": [80, 443, 8080, 22]
        },
        "alert_level": "medium",  # low, medium, high
        "auto_block_threats": False,
        "scan_new_files": True
    },
    "ui_settings": {
        "theme": "dark",
        "animation_speed": 1.0,
        "enable_notifications": True
    },
    "n8n_integration": {
        "enabled": False,
        "url": "http://localhost:5678/webhook/",
        "workflow_id": ""
    }
}

# API Keys from environment
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")

CONFIG_FILE = CONFIG_DIR / "config.yaml"

def load_config():
    """Load configuration from file or create default if not exists"""
    if not CONFIG_FILE.exists():
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f)
        # Merge with default config to ensure all keys exist
        merged_config = DEFAULT_CONFIG.copy()
        for key, value in config.items():
            if isinstance(value, dict) and key in merged_config:
                merged_config[key].update(value)
            else:
                merged_config[key] = value
        return merged_config
    except Exception as e:
        print(f"Error loading config: {e}")
        return DEFAULT_CONFIG

def save_config(config):
    """Save configuration to file"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False

# Load config at import time
CONFIG = load_config()
