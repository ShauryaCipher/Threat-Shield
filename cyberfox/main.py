"""
Entry point for the CyberFox application.
Initializes the main application window and components.
"""
import sys
import os
import logging
from pathlib import Path
from PyQt5.QtWidgets import QApplication, QSplashScreen
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtSvg import QSvgWidget

from cyberfox.config import CONFIG_DIR, CONFIG, LOGS_DIR
from cyberfox.ui.style import get_splash_animation
from cyberfox.ui.main_window import MainWindow
from cyberfox.ui.resources import initialize_resources

# Setup logging
def setup_logging():
    """Configure logging for the application."""
    log_file = LOGS_DIR / f"cyberfox.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    # Set third-party loggers to WARNING level to reduce noise
    logging.getLogger("stem").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

def main():
    """Main entry point for CyberFox application."""
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Starting CyberFox application")
    
    # Check if running in Replit environment
    is_replit = os.environ.get('REPL_ID') is not None
    
    if is_replit:
        # In Replit, we can't run the GUI, so we'll just display a message
        logger.info("Running in Replit environment - GUI is not available.")
        print("=" * 50)
        print("CyberFox Threat Detection Tool")
        print("=" * 50)
        print("This application requires a GUI environment to run properly.")
        print("When running on your local machine or from the executable, the application will display a graphical interface.")
        print("Project structure and functionality are all implemented.")
        print("\nTo build an executable (.exe) file for Windows:")
        print("1. Run the build_exe.py script")
        print("2. Find the executable in the 'executable' directory")
        print("3. Share the entire 'executable' directory with your friends")
        return 0
    
    # Create QApplication instance
    app = QApplication(sys.argv)
    app.setApplicationName("CyberFox")
    app.setQuitOnLastWindowClosed(True)
    
    # Initialize resources
    initialize_resources()
    
    # Set application style
    from cyberfox.ui.style import get_stylesheet, Theme
    theme = Theme(CONFIG["ui_settings"]["theme"])
    app.setStyleSheet(get_stylesheet(theme))
    
    # Create a temporary file to store the splash animation
    temp_splash_file = Path(CONFIG_DIR) / "splash_temp.svg"
    with open(temp_splash_file, "w") as f:
        f.write(get_splash_animation())
    
    # Create splash screen
    splash_widget = QSvgWidget(str(temp_splash_file))
    splash_widget.setFixedSize(400, 300)
    
    # Create splash screen from widget
    splash_pixmap = QPixmap(400, 300)
    splash_widget.render(splash_pixmap)
    splash = QSplashScreen(splash_pixmap)
    splash.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.SplashScreen)
    splash.show()
    
    # Process events to make sure splash is displayed
    app.processEvents()
    
    # Create and initialize the main window
    window = MainWindow()
    
    # Close splash and show main window after a delay
    QTimer.singleShot(2500, lambda: (splash.close(), window.show()))
    
    # Execute the application
    exit_code = app.exec_()
    
    # Clean up
    if temp_splash_file.exists():
        os.unlink(temp_splash_file)
        
    logger.info(f"CyberFox application exiting with code {exit_code}")
    return exit_code

if __name__ == "__main__":
    sys.exit(main())
