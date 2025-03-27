#!/usr/bin/env python3
"""
Main entry script for running the CyberFox application.
"""
import sys
import os
import logging
from pathlib import Path

def setup_environment():
    """Set up the Python environment."""
    # Add the parent directory to sys.path if running from script directory
    current_dir = Path(__file__).resolve().parent
    
    if current_dir not in sys.path:
        sys.path.insert(0, str(current_dir))
    
    # Check for required packages
    try:
        import PyQt5
        import stem
        import magic
        import requests
        import yaml
    except ImportError as e:
        print(f"Missing required package: {e}")
        print("Please install the required packages using pip:")
        print("pip install PyQt5 stem python-magic requests pyyaml")
        sys.exit(1)

def main():
    """Main entry point."""
    # Set up environment
    setup_environment()
    
    # Now import from the cyberfox package
    from cyberfox.main import main as cyberfox_main
    
    # Run the application
    sys.exit(cyberfox_main())

if __name__ == "__main__":
    main()
