#!/usr/bin/env python3
"""
Build script for creating an executable of the CyberFox application.
"""
import os
import sys
import shutil
import subprocess
import platform
from pathlib import Path

def check_requirements():
    """Check if the required packages are installed."""
    try:
        import PyInstaller
    except ImportError:
        print("PyInstaller is not installed. Please install it with:")
        print("pip install pyinstaller")
        return False
        
    try:
        import PyQt5
        import stem
        import magic
        import requests
        import yaml
        import trafilatura
        import psutil
        import pysocks
    except ImportError as e:
        print(f"Missing required package: {e}")
        print("Please install all required packages:")
        print("pip install PyQt5 stem python-magic requests pyyaml trafilatura psutil pysocks")
        return False
        
    return True

def build_executable():
    """Build the executable using PyInstaller."""
    print("Building CyberFox executable...")
    
    # Create the build directory
    build_dir = Path("build")
    dist_dir = Path("dist")
    exe_dir = Path("executable")
    
    # Clean existing directories if they exist
    for directory in [build_dir, dist_dir, exe_dir]:
        if directory.exists():
            print(f"Cleaning {directory}...")
            shutil.rmtree(directory)
            
        directory.mkdir(exist_ok=True)
    
    # Determine the extension for the executable
    exe_ext = ".exe" if platform.system() == "Windows" else ""
    
    # Configure PyInstaller command
    pyinstaller_cmd = [
        "pyinstaller",
        "--name=CyberFox",
        "--onefile",
        "--windowed",  # Don't show console window
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        f"--specpath={build_dir}",
        "--clean",
        "--noupx",  # Don't use UPX for compression
        "--add-data=cyberfox/config.py:cyberfox",  # Include the config module
        "--hidden-import=PyQt5.QtSvg",  # Make sure SVG support is included
        "--hidden-import=PyQt5.QtXml",  # Required for SVG
        "--hidden-import=stem.socket",  # Required for Tor connectivity
        "--hidden-import=yaml",  # For config loading
        "--hidden-import=magic",  # For file type detection
        "--hidden-import=trafilatura",  # For web scraping
        "--hidden-import=psutil",  # For system information
        "--hidden-import=pysocks",  # For SOCKS proxy support
    ]
    
    # Add additional data files
    pyinstaller_cmd.append("--add-data=generated-icon.png:.")
    
    # Add icon if one exists
    if Path("generated-icon.png").exists():
        pyinstaller_cmd.append("--icon=generated-icon.png")
    
    # Fallback to other icon paths if main one doesn't exist    
    icon_path = Path("cyberfox/ui/assets/icon.ico")
    if icon_path.exists():
        pyinstaller_cmd.append(f"--icon={icon_path}")
    
    # Add the entry point script
    pyinstaller_cmd.append("run.py")
    
    # Run PyInstaller
    try:
        subprocess.run(pyinstaller_cmd, check=True)
        print("PyInstaller build completed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Error building executable: {e}")
        return False
    
    # Copy the executable to the 'executable' directory
    src_exe = dist_dir / f"CyberFox{exe_ext}"
    dst_exe = exe_dir / f"CyberFox{exe_ext}"
    
    if src_exe.exists():
        shutil.copy2(src_exe, dst_exe)
        print(f"Executable copied to {dst_exe}")
        
        # Copy additional files needed
        readme_file = Path("README.md")
        if readme_file.exists():
            shutil.copy2(readme_file, exe_dir / "README.md")
            print("Copied README.md to executable directory")
            
        icon_file = Path("generated-icon.png")
        if icon_file.exists():
            shutil.copy2(icon_file, exe_dir / "icon.png")
            print("Copied icon to executable directory")
        
        # Create a simple batch file to run the executable on Windows
        if platform.system() == "Windows":
            batch_file = exe_dir / "Run CyberFox.bat"
            with open(batch_file, "w") as f:
                f.write('@echo off\necho Starting CyberFox...\n"%~dp0CyberFox.exe"\n')
            print("Created Windows batch file")
        
        print("\nDeployment package created successfully!")
        return True
    else:
        print(f"Error: Executable not found at {src_exe}")
        return False

def main():
    """Main build script function."""
    print("CyberFox Executable Builder")
    print("--------------------------")
    
    if not check_requirements():
        print("Error: Missing required packages. Build aborted.")
        return 1
    
    print("All required packages are installed.")
    
    if build_executable():
        print("\nBuild successful!")
        print(f"Executable is available in the 'executable' directory.")
        return 0
    else:
        print("\nBuild failed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
