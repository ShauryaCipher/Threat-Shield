"""
Main window for the CyberFox application.
"""
import os
import sys
import logging
from datetime import datetime
from typing import Dict, List, Optional

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTabWidget, QLabel, QPushButton, QToolBar, 
    QStatusBar, QAction, QMenu, QMessageBox, 
    QFileDialog, QInputDialog, QDialog, QTreeWidget,
    QTreeWidgetItem, QHeaderView, QToolButton, QFrame
)
from PyQt5.QtCore import Qt, QSize, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QIcon, QPixmap, QColor, QPalette
from PyQt5.QtSvg import QSvgWidget

from cyberfox.config import CONFIG, CONFIG_DIR, save_config
from cyberfox.ui.style import get_icon_svg, get_logo_svg, COLORS, Theme
from cyberfox.ui.dashboard import DashboardWidget
from cyberfox.ui.animations import AnimatedIcon, PulseAnimation
from cyberfox.ui.visualization_tab import VisualizationTab
from cyberfox.core.threats import (
    Threat, FileThreat, DarkWebThreat, DataBreachThreat, 
    BrowserThreat, ThreatType, ThreatLevel, ThreatDatabase
)
from cyberfox.core.file_scanner import FileScanner
from cyberfox.core.darkweb_monitor import DarkWebMonitor
from cyberfox.core.breach_checker import BreachChecker
from cyberfox.core.browser_analyzer import BrowserAnalyzer
from cyberfox.core.realtime_protection import RealTimeProtection
from cyberfox.utils.n8n_integration import N8NIntegration

logger = logging.getLogger(__name__)

class MainWindow(QMainWindow):
    """Main window for the CyberFox application."""
    
    def __init__(self):
        """Initialize the main window."""
        super().__init__()
        
        # Initialize core components
        self.threat_db = ThreatDatabase()
        self.file_scanner = FileScanner(callback=self.on_threat_detected)
        self.darkweb_monitor = DarkWebMonitor(callback=self.on_threat_detected)
        self.breach_checker = BreachChecker(callback=self.on_threat_detected)
        self.browser_analyzer = BrowserAnalyzer(callback=self.on_threat_detected)
        self.realtime_protection = RealTimeProtection(callback=self.on_threat_detected)
        self.n8n = N8NIntegration()
        
        # Start real-time protection if enabled in settings
        if CONFIG["realtime_protection"]["enabled"] and CONFIG["realtime_protection"]["start_on_launch"]:
            self.start_realtime_protection()
        
        # Set up the UI
        self.setup_ui()
        
        # Set up periodic update timer (every 5 seconds)
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_stats)
        self.update_timer.start(5000)  # 5-second updates
        
        # Update the UI with initial stats
        self.update_stats()
        
    def setup_ui(self):
        """Set up the user interface."""
        # Configure the main window
        self.setWindowTitle("CyberFox - Advanced Threat Detection")
        self.setMinimumSize(1000, 700)
        
        # Set window icon (creating an SVG icon)
        icon_svg = get_icon_svg("shield", COLORS[CONFIG["ui_settings"]["theme"]]["primary"])
        icon_file = os.path.join(CONFIG_DIR, "icon_temp.svg")
        with open(icon_file, "w") as f:
            f.write(icon_svg)
        self.setWindowIcon(QIcon(icon_file))
        
        # Create the central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(10)
        
        # Create the header with logo and title
        self.setup_header()
        
        # Create the tab widget
        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)
        
        # Add the dashboard tab
        self.dashboard = DashboardWidget(
            self.threat_db, 
            self.file_scanner,
            self.darkweb_monitor, 
            self.breach_checker, 
            self.browser_analyzer
        )
        self.tab_widget.addTab(self.dashboard, "Dashboard")
        
        # Add the scan tab
        self.scan_tab = self.create_scan_tab()
        self.tab_widget.addTab(self.scan_tab, "Scanner")
        
        # Add the dark web monitor tab
        self.darkweb_tab = self.create_darkweb_tab()
        self.tab_widget.addTab(self.darkweb_tab, "Dark Web Monitor")
        
        # Add the breach checker tab
        self.breach_tab = self.create_breach_tab()
        self.tab_widget.addTab(self.breach_tab, "Data Breach Checker")
        
        # Add the browser analyzer tab
        self.browser_tab = self.create_browser_tab()
        self.tab_widget.addTab(self.browser_tab, "Browser Analyzer")
        
        # Add the threat log tab
        self.threat_log_tab = self.create_threat_log_tab()
        self.tab_widget.addTab(self.threat_log_tab, "Threat Log")
        
        # Add the visualization tab
        self.visualization_tab = VisualizationTab(self.threat_db)
        self.tab_widget.addTab(self.visualization_tab, "Risk Visualization")
        
        # Add the settings tab
        self.settings_tab = self.create_settings_tab()
        self.tab_widget.addTab(self.settings_tab, "Settings")
        
        # Setup toolbar
        self.setup_toolbar()
        
        # Setup status bar
        self.setup_status_bar()
        
        # Setup menu bar
        self.setup_menu_bar()
        
        # Connect tab change signal
        self.tab_widget.currentChanged.connect(self.on_tab_changed)
        
    def setup_header(self):
        """Set up the header with logo and title."""
        header_layout = QHBoxLayout()
        
        # Add logo
        logo_svg = get_logo_svg()
        logo_file = os.path.join(CONFIG_DIR, "logo_temp.svg")
        with open(logo_file, "w") as f:
            f.write(logo_svg)
        
        logo_widget = QSvgWidget(logo_file)
        logo_widget.setFixedSize(80, 80)
        header_layout.addWidget(logo_widget)
        
        # Add title and subtitle
        title_layout = QVBoxLayout()
        title = QLabel("CyberFox")
        title.setObjectName("headingLabel")
        
        subtitle = QLabel("Advanced Threat Detection")
        subtitle.setObjectName("subheadingLabel")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        title_layout.addStretch(1)
        
        header_layout.addLayout(title_layout)
        header_layout.addStretch(1)
        
        # Add header to main layout
        self.main_layout.addLayout(header_layout)
        
    def setup_toolbar(self):
        """Set up the toolbar."""
        self.toolbar = QToolBar("Main Toolbar")
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(24, 24))
        self.toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        
        # Create custom SVG icons for toolbar actions
        icons = {
            "scan": get_icon_svg("shield", COLORS[CONFIG["ui_settings"]["theme"]]["primary"]),
            "scan_stop": get_icon_svg("shield-off", COLORS[CONFIG["ui_settings"]["theme"]]["danger"]),
            "monitor": get_icon_svg("eye", COLORS[CONFIG["ui_settings"]["theme"]]["primary"]),
            "monitor_stop": get_icon_svg("eye-off", COLORS[CONFIG["ui_settings"]["theme"]]["danger"]),
            "check": get_icon_svg("search", COLORS[CONFIG["ui_settings"]["theme"]]["primary"]),
            "settings": get_icon_svg("settings", COLORS[CONFIG["ui_settings"]["theme"]]["primary"]),
            "refresh": get_icon_svg("refresh-cw", COLORS[CONFIG["ui_settings"]["theme"]]["primary"]),
            "help": get_icon_svg("info", COLORS[CONFIG["ui_settings"]["theme"]]["primary"]),
        }
        
        # Save icons to temp files
        icon_files = {}
        for name, svg in icons.items():
            icon_file = os.path.join(CONFIG_DIR, f"icon_{name}_temp.svg")
            with open(icon_file, "w") as f:
                f.write(svg)
            icon_files[name] = icon_file
        
        # Create actions
        self.scan_action = QAction(QIcon(icon_files["scan"]), "Quick Scan", self)
        self.scan_action.triggered.connect(self.start_quick_scan)
        
        self.stop_scan_action = QAction(QIcon(icon_files["scan_stop"]), "Stop Scan", self)
        self.stop_scan_action.triggered.connect(self.stop_scan)
        self.stop_scan_action.setEnabled(False)
        
        self.monitor_action = QAction(QIcon(icon_files["monitor"]), "Start Monitoring", self)
        self.monitor_action.triggered.connect(self.start_monitoring)
        
        self.stop_monitor_action = QAction(QIcon(icon_files["monitor_stop"]), "Stop Monitoring", self)
        self.stop_monitor_action.triggered.connect(self.stop_monitoring)
        self.stop_monitor_action.setEnabled(False)
        
        self.check_action = QAction(QIcon(icon_files["check"]), "Check Email", self)
        self.check_action.triggered.connect(self.check_email)
        
        self.refresh_action = QAction(QIcon(icon_files["refresh"]), "Refresh", self)
        self.refresh_action.triggered.connect(self.update_stats)
        
        self.settings_action = QAction(QIcon(icon_files["settings"]), "Settings", self)
        self.settings_action.triggered.connect(self.show_settings)
        
        self.help_action = QAction(QIcon(icon_files["help"]), "Help", self)
        self.help_action.triggered.connect(self.show_help)
        
        # Add actions to toolbar
        self.toolbar.addAction(self.scan_action)
        self.toolbar.addAction(self.stop_scan_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.monitor_action)
        self.toolbar.addAction(self.stop_monitor_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.check_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.refresh_action)
        self.toolbar.addAction(self.settings_action)
        self.toolbar.addAction(self.help_action)
        
        self.addToolBar(self.toolbar)
        
    def setup_status_bar(self):
        """Set up the status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Create status labels
        self.status_label = QLabel("Ready")
        self.scan_status_label = QLabel("Scanner: Inactive")
        self.monitor_status_label = QLabel("Monitoring: Inactive")
        self.realtime_status_label = QLabel("Real-time Protection: Inactive")
        
        # Add animated icons
        scan_icon_svg = get_icon_svg("shield", COLORS[CONFIG["ui_settings"]["theme"]]["scanner_inactive"])
        scan_icon_file = os.path.join(CONFIG_DIR, "scan_icon_temp.svg")
        with open(scan_icon_file, "w") as f:
            f.write(scan_icon_svg)
        
        self.scan_icon = AnimatedIcon(scan_icon_file, 16, 16)
        self.scan_icon.setToolTip("Scanner Status")
        
        monitor_icon_svg = get_icon_svg("eye", COLORS[CONFIG["ui_settings"]["theme"]]["scanner_inactive"])
        monitor_icon_file = os.path.join(CONFIG_DIR, "monitor_icon_temp.svg")
        with open(monitor_icon_file, "w") as f:
            f.write(monitor_icon_svg)
        
        self.monitor_icon = AnimatedIcon(monitor_icon_file, 16, 16)
        self.monitor_icon.setToolTip("Monitoring Status")
        
        realtime_icon_svg = get_icon_svg("activity", COLORS[CONFIG["ui_settings"]["theme"]]["scanner_inactive"])
        realtime_icon_file = os.path.join(CONFIG_DIR, "realtime_icon_temp.svg")
        with open(realtime_icon_file, "w") as f:
            f.write(realtime_icon_svg)
        
        self.realtime_icon = AnimatedIcon(realtime_icon_file, 16, 16)
        self.realtime_icon.setToolTip("Real-time Protection Status")
        
        # Add widgets to status bar
        self.status_bar.addWidget(self.status_label, 1)
        self.status_bar.addPermanentWidget(self.scan_icon)
        self.status_bar.addPermanentWidget(self.scan_status_label)
        self.status_bar.addPermanentWidget(self.monitor_icon)
        self.status_bar.addPermanentWidget(self.monitor_status_label)
        self.status_bar.addPermanentWidget(self.realtime_icon)
        self.status_bar.addPermanentWidget(self.realtime_status_label)
        
    def setup_menu_bar(self):
        """Set up the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Scan menu
        scan_menu = menubar.addMenu("Scan")
        
        quick_scan_action = QAction("Quick Scan", self)
        quick_scan_action.triggered.connect(self.start_quick_scan)
        scan_menu.addAction(quick_scan_action)
        
        full_scan_action = QAction("Full System Scan", self)
        full_scan_action.triggered.connect(self.start_full_scan)
        scan_menu.addAction(full_scan_action)
        
        custom_scan_action = QAction("Custom Scan...", self)
        custom_scan_action.triggered.connect(self.start_custom_scan)
        scan_menu.addAction(custom_scan_action)
        
        scan_menu.addSeparator()
        
        stop_scan_action = QAction("Stop Scan", self)
        stop_scan_action.triggered.connect(self.stop_scan)
        scan_menu.addAction(stop_scan_action)
        
        # Protection menu
        protection_menu = menubar.addMenu("Protection")
        
        start_realtime_action = QAction("Start Real-time Protection", self)
        start_realtime_action.triggered.connect(self.start_realtime_protection)
        protection_menu.addAction(start_realtime_action)
        
        stop_realtime_action = QAction("Stop Real-time Protection", self)
        stop_realtime_action.triggered.connect(self.stop_realtime_protection)
        protection_menu.addAction(stop_realtime_action)
        
        # Monitor menu
        monitor_menu = menubar.addMenu("Monitor")
        
        start_monitor_action = QAction("Start Monitoring", self)
        start_monitor_action.triggered.connect(self.start_monitoring)
        monitor_menu.addAction(start_monitor_action)
        
        stop_monitor_action = QAction("Stop Monitoring", self)
        stop_monitor_action.triggered.connect(self.stop_monitoring)
        monitor_menu.addAction(stop_monitor_action)
        
        monitor_menu.addSeparator()
        
        add_keyword_action = QAction("Add Keyword...", self)
        add_keyword_action.triggered.connect(self.add_keyword)
        monitor_menu.addAction(add_keyword_action)
        
        add_email_action = QAction("Add Email...", self)
        add_email_action.triggered.connect(self.add_email)
        monitor_menu.addAction(add_email_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        check_email_action = QAction("Check Email for Breaches...", self)
        check_email_action.triggered.connect(self.check_email)
        tools_menu.addAction(check_email_action)
        
        scan_browsers_action = QAction("Scan Browsers", self)
        scan_browsers_action.triggered.connect(self.scan_browsers)
        tools_menu.addAction(scan_browsers_action)
        
        tools_menu.addSeparator()
        
        clear_threats_action = QAction("Clear Threat Log", self)
        clear_threats_action.triggered.connect(self.clear_threats)
        tools_menu.addAction(clear_threats_action)
        
        # View menu
        view_menu = menubar.addMenu("View")
        
        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.update_stats)
        view_menu.addAction(refresh_action)
        
        view_menu.addSeparator()
        
        theme_menu = QMenu("Theme", self)
        
        dark_theme_action = QAction("Dark", self)
        dark_theme_action.triggered.connect(lambda: self.change_theme(Theme.DARK))
        theme_menu.addAction(dark_theme_action)
        
        light_theme_action = QAction("Light", self)
        light_theme_action.triggered.connect(lambda: self.change_theme(Theme.LIGHT))
        theme_menu.addAction(light_theme_action)
        
        view_menu.addMenu(theme_menu)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        help_action = QAction("Help", self)
        help_action.triggered.connect(self.show_help)
        help_menu.addAction(help_action)
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def create_scan_tab(self):
        """Create the scan tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("File System Scanner")
        header.setObjectName("headingLabel")
        layout.addWidget(header)
        
        description = QLabel(
            "Scan your file system for malicious files, suspicious patterns, and potential threats. "
            "You can perform a quick scan of common locations, a full system scan, or specify custom locations to scan."
        )
        description.setObjectName("subheadingLabel")
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Scan actions
        actions_layout = QHBoxLayout()
        
        # Quick scan button
        quick_scan_btn = QPushButton("Quick Scan")
        quick_scan_btn.setMinimumHeight(50)
        quick_scan_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_scan_temp.svg")))
        quick_scan_btn.clicked.connect(self.start_quick_scan)
        actions_layout.addWidget(quick_scan_btn)
        
        # Full scan button
        full_scan_btn = QPushButton("Full System Scan")
        full_scan_btn.setMinimumHeight(50)
        full_scan_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_scan_temp.svg")))
        full_scan_btn.clicked.connect(self.start_full_scan)
        actions_layout.addWidget(full_scan_btn)
        
        # Custom scan button
        custom_scan_btn = QPushButton("Custom Scan...")
        custom_scan_btn.setMinimumHeight(50)
        custom_scan_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_scan_temp.svg")))
        custom_scan_btn.clicked.connect(self.start_custom_scan)
        actions_layout.addWidget(custom_scan_btn)
        
        # Stop scan button
        stop_scan_btn = QPushButton("Stop Scan")
        stop_scan_btn.setObjectName("dangerButton")
        stop_scan_btn.setMinimumHeight(50)
        stop_scan_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_scan_stop_temp.svg")))
        stop_scan_btn.clicked.connect(self.stop_scan)
        stop_scan_btn.setEnabled(False)
        actions_layout.addWidget(stop_scan_btn)
        
        # Store the stop button to enable/disable it
        self.stop_scan_btn = stop_scan_btn
        
        layout.addLayout(actions_layout)
        
        # Scan status frame
        status_frame = QFrame()
        status_frame.setObjectName("cardWidget")
        status_frame.setFrameShape(QFrame.StyledPanel)
        status_frame.setFrameShadow(QFrame.Raised)
        status_layout = QVBoxLayout(status_frame)
        
        # Status header
        status_header = QLabel("Scan Status")
        status_header.setObjectName("subheadingLabel")
        status_layout.addWidget(status_header)
        
        # Status details
        status_grid = QHBoxLayout()
        
        # Left column
        left_col = QVBoxLayout()
        self.scan_status_title = QLabel("Status:")
        left_col.addWidget(self.scan_status_title)
        
        self.scan_files_scanned = QLabel("Files Scanned: 0")
        left_col.addWidget(self.scan_files_scanned)
        
        self.scan_threats_found = QLabel("Threats Found: 0")
        left_col.addWidget(self.scan_threats_found)
        
        status_grid.addLayout(left_col)
        
        # Right column
        right_col = QVBoxLayout()
        self.scan_current_file = QLabel("Current File: None")
        self.scan_current_file.setWordWrap(True)
        right_col.addWidget(self.scan_current_file)
        
        self.scan_bytes_scanned = QLabel("Data Scanned: 0 bytes")
        right_col.addWidget(self.scan_bytes_scanned)
        
        self.scan_time_elapsed = QLabel("Time Elapsed: 00:00:00")
        right_col.addWidget(self.scan_time_elapsed)
        
        status_grid.addLayout(right_col)
        status_layout.addLayout(status_grid)
        
        layout.addWidget(status_frame)
        
        # Recent threats frame
        threats_frame = QFrame()
        threats_frame.setObjectName("cardWidget")
        threats_frame.setFrameShape(QFrame.StyledPanel)
        threats_frame.setFrameShadow(QFrame.Raised)
        threats_layout = QVBoxLayout(threats_frame)
        
        # Threats header
        threats_header = QLabel("Recent File Threats")
        threats_header.setObjectName("subheadingLabel")
        threats_layout.addWidget(threats_header)
        
        # Threats tree
        self.file_threats_tree = QTreeWidget()
        self.file_threats_tree.setHeaderLabels(["Threat", "Level", "Path", "Detection Time"])
        self.file_threats_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.file_threats_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.file_threats_tree.header().setSectionResizeMode(2, QHeaderView.Stretch)
        self.file_threats_tree.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.file_threats_tree.setAlternatingRowColors(True)
        self.file_threats_tree.itemDoubleClicked.connect(self.show_threat_details)
        threats_layout.addWidget(self.file_threats_tree)
        
        layout.addWidget(threats_frame)
        
        # Fill the tree with any existing file threats
        self.update_file_threats_tree()
        
        return tab
        
    def create_darkweb_tab(self):
        """Create the dark web monitoring tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("Dark Web Monitor")
        header.setObjectName("headingLabel")
        layout.addWidget(header)
        
        description = QLabel(
            "Monitor the dark web for mentions of your sensitive information. "
            "CyberFox searches Tor hidden services for keywords and email addresses you specify, "
            "alerting you if your data appears on the dark web."
        )
        description.setObjectName("subheadingLabel")
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Monitor actions
        actions_layout = QHBoxLayout()
        
        # Start monitoring button
        self.start_monitor_btn = QPushButton("Start Monitoring")
        self.start_monitor_btn.setMinimumHeight(50)
        self.start_monitor_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_monitor_temp.svg")))
        self.start_monitor_btn.clicked.connect(self.start_monitoring)
        actions_layout.addWidget(self.start_monitor_btn)
        
        # Stop monitoring button
        self.stop_monitor_btn = QPushButton("Stop Monitoring")
        self.stop_monitor_btn.setObjectName("dangerButton")
        self.stop_monitor_btn.setMinimumHeight(50)
        self.stop_monitor_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_monitor_stop_temp.svg")))
        self.stop_monitor_btn.clicked.connect(self.stop_monitoring)
        self.stop_monitor_btn.setEnabled(False)
        actions_layout.addWidget(self.stop_monitor_btn)
        
        # Add keyword button
        add_keyword_btn = QPushButton("Add Keyword")
        add_keyword_btn.setMinimumHeight(50)
        add_keyword_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_plus_temp.svg")))
        add_keyword_btn.clicked.connect(self.add_keyword)
        actions_layout.addWidget(add_keyword_btn)
        
        # Add email button
        add_email_btn = QPushButton("Add Email")
        add_email_btn.setMinimumHeight(50)
        add_email_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_mail_temp.svg")))
        add_email_btn.clicked.connect(self.add_email)
        actions_layout.addWidget(add_email_btn)
        
        layout.addLayout(actions_layout)
        
        # Keywords and Emails frame
        monitoring_frame = QFrame()
        monitoring_frame.setObjectName("cardWidget")
        monitoring_frame.setFrameShape(QFrame.StyledPanel)
        monitoring_frame.setFrameShadow(QFrame.Raised)
        monitoring_layout = QVBoxLayout(monitoring_frame)
        
        # Monitoring items header
        monitoring_header = QLabel("Monitored Items")
        monitoring_header.setObjectName("subheadingLabel")
        monitoring_layout.addWidget(monitoring_header)
        
        # Monitoring grid
        monitoring_grid = QHBoxLayout()
        
        # Keywords column
        keywords_layout = QVBoxLayout()
        keywords_label = QLabel("Keywords")
        keywords_label.setObjectName("infoLabel")
        keywords_layout.addWidget(keywords_label)
        
        self.keywords_tree = QTreeWidget()
        self.keywords_tree.setHeaderLabels(["Keyword"])
        self.keywords_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.keywords_tree.setAlternatingRowColors(True)
        self.keywords_tree.setMinimumHeight(150)
        self.keywords_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.keywords_tree.customContextMenuRequested.connect(self.show_keyword_context_menu)
        keywords_layout.addWidget(self.keywords_tree)
        
        monitoring_grid.addLayout(keywords_layout)
        
        # Emails column
        emails_layout = QVBoxLayout()
        emails_label = QLabel("Email Addresses")
        emails_label.setObjectName("infoLabel")
        emails_layout.addWidget(emails_label)
        
        self.emails_tree = QTreeWidget()
        self.emails_tree.setHeaderLabels(["Email Address"])
        self.emails_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.emails_tree.setAlternatingRowColors(True)
        self.emails_tree.setMinimumHeight(150)
        self.emails_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.emails_tree.customContextMenuRequested.connect(self.show_email_context_menu)
        emails_layout.addWidget(self.emails_tree)
        
        monitoring_grid.addLayout(emails_layout)
        monitoring_layout.addLayout(monitoring_grid)
        
        layout.addWidget(monitoring_frame)
        
        # Monitor status frame
        status_frame = QFrame()
        status_frame.setObjectName("cardWidget")
        status_frame.setFrameShape(QFrame.StyledPanel)
        status_frame.setFrameShadow(QFrame.Raised)
        status_layout = QVBoxLayout(status_frame)
        
        # Status header
        status_header = QLabel("Monitoring Status")
        status_header.setObjectName("subheadingLabel")
        status_layout.addWidget(status_header)
        
        # Status details
        status_grid = QHBoxLayout()
        
        # Left column
        left_col = QVBoxLayout()
        self.monitor_status_title = QLabel("Status: Inactive")
        left_col.addWidget(self.monitor_status_title)
        
        self.monitor_sites_scanned = QLabel("Sites Monitored: 0")
        left_col.addWidget(self.monitor_sites_scanned)
        
        self.monitor_alerts = QLabel("Alerts Triggered: 0")
        left_col.addWidget(self.monitor_alerts)
        
        status_grid.addLayout(left_col)
        
        # Right column
        right_col = QVBoxLayout()
        self.monitor_last_scan = QLabel("Last Scan: Never")
        right_col.addWidget(self.monitor_last_scan)
        
        self.monitor_next_scan = QLabel("Next Scan: N/A")
        right_col.addWidget(self.monitor_next_scan)
        
        self.monitor_current_site = QLabel("Current Site: None")
        self.monitor_current_site.setWordWrap(True)
        right_col.addWidget(self.monitor_current_site)
        
        status_grid.addLayout(right_col)
        status_layout.addLayout(status_grid)
        
        layout.addWidget(status_frame)
        
        # Recent darkweb threats frame
        threats_frame = QFrame()
        threats_frame.setObjectName("cardWidget")
        threats_frame.setFrameShape(QFrame.StyledPanel)
        threats_frame.setFrameShadow(QFrame.Raised)
        threats_layout = QVBoxLayout(threats_frame)
        
        # Threats header
        threats_header = QLabel("Dark Web Alerts")
        threats_header.setObjectName("subheadingLabel")
        threats_layout.addWidget(threats_header)
        
        # Threats tree
        self.darkweb_threats_tree = QTreeWidget()
        self.darkweb_threats_tree.setHeaderLabels(["Description", "Level", "Keywords Found", "Detection Time"])
        self.darkweb_threats_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.darkweb_threats_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.darkweb_threats_tree.header().setSectionResizeMode(2, QHeaderView.Stretch)
        self.darkweb_threats_tree.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.darkweb_threats_tree.setAlternatingRowColors(True)
        self.darkweb_threats_tree.itemDoubleClicked.connect(self.show_threat_details)
        threats_layout.addWidget(self.darkweb_threats_tree)
        
        layout.addWidget(threats_frame)
        
        # Update the lists and tree
        self.update_darkweb_tab()
        
        return tab
        
    def create_breach_tab(self):
        """Create the data breach tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("Data Breach Checker")
        header.setObjectName("headingLabel")
        layout.addWidget(header)
        
        description = QLabel(
            "Check if your email addresses have been involved in known data breaches. "
            "CyberFox uses the Have I Been Pwned API to detect if your personal information "
            "has been exposed in security incidents."
        )
        description.setObjectName("subheadingLabel")
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Breach checker actions
        actions_layout = QHBoxLayout()
        
        # Start checker button
        self.start_checker_btn = QPushButton("Start Breach Checker")
        self.start_checker_btn.setMinimumHeight(50)
        self.start_checker_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_search_temp.svg")))
        self.start_checker_btn.clicked.connect(self.start_breach_checker)
        actions_layout.addWidget(self.start_checker_btn)
        
        # Stop checker button
        self.stop_checker_btn = QPushButton("Stop Checker")
        self.stop_checker_btn.setObjectName("dangerButton")
        self.stop_checker_btn.setMinimumHeight(50)
        self.stop_checker_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_x_temp.svg")))
        self.stop_checker_btn.clicked.connect(self.stop_breach_checker)
        self.stop_checker_btn.setEnabled(False)
        actions_layout.addWidget(self.stop_checker_btn)
        
        # Check email button
        check_email_btn = QPushButton("Check Email")
        check_email_btn.setMinimumHeight(50)
        check_email_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_mail_temp.svg")))
        check_email_btn.clicked.connect(self.check_email)
        actions_layout.addWidget(check_email_btn)
        
        # Add email button
        add_email_btn = QPushButton("Add Email to Monitor")
        add_email_btn.setMinimumHeight(50)
        add_email_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_plus_temp.svg")))
        add_email_btn.clicked.connect(self.add_email)
        actions_layout.addWidget(add_email_btn)
        
        layout.addLayout(actions_layout)
        
        # Breach checker status frame
        status_frame = QFrame()
        status_frame.setObjectName("cardWidget")
        status_frame.setFrameShape(QFrame.StyledPanel)
        status_frame.setFrameShadow(QFrame.Raised)
        status_layout = QVBoxLayout(status_frame)
        
        # Status header
        status_header = QLabel("Breach Checker Status")
        status_header.setObjectName("subheadingLabel")
        status_layout.addWidget(status_header)
        
        # Status details
        status_grid = QHBoxLayout()
        
        # Left column
        left_col = QVBoxLayout()
        self.breach_status_title = QLabel("Status: Inactive")
        left_col.addWidget(self.breach_status_title)
        
        self.breach_emails_checked = QLabel("Emails Checked: 0")
        left_col.addWidget(self.breach_emails_checked)
        
        self.breach_breaches_found = QLabel("Breaches Found: 0")
        left_col.addWidget(self.breach_breaches_found)
        
        status_grid.addLayout(left_col)
        
        # Right column
        right_col = QVBoxLayout()
        self.breach_last_check = QLabel("Last Check: Never")
        right_col.addWidget(self.breach_last_check)
        
        self.breach_next_check = QLabel("Next Check: N/A")
        right_col.addWidget(self.breach_next_check)
        
        self.breach_current_email = QLabel("Current Email: None")
        self.breach_current_email.setWordWrap(True)
        right_col.addWidget(self.breach_current_email)
        
        status_grid.addLayout(right_col)
        status_layout.addLayout(status_grid)
        
        layout.addWidget(status_frame)
        
        # Recent breach threats frame
        threats_frame = QFrame()
        threats_frame.setObjectName("cardWidget")
        threats_frame.setFrameShape(QFrame.StyledPanel)
        threats_frame.setFrameShadow(QFrame.Raised)
        threats_layout = QVBoxLayout(threats_frame)
        
        # Threats header
        threats_header = QLabel("Data Breach Alerts")
        threats_header.setObjectName("subheadingLabel")
        threats_layout.addWidget(threats_header)
        
        # Threats tree
        self.breach_threats_tree = QTreeWidget()
        self.breach_threats_tree.setHeaderLabels(["Email", "Service", "Level", "Breach Date", "Detection Time"])
        self.breach_threats_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.breach_threats_tree.header().setSectionResizeMode(1, QHeaderView.Stretch)
        self.breach_threats_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.breach_threats_tree.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.breach_threats_tree.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.breach_threats_tree.setAlternatingRowColors(True)
        self.breach_threats_tree.itemDoubleClicked.connect(self.show_threat_details)
        threats_layout.addWidget(self.breach_threats_tree)
        
        layout.addWidget(threats_frame)
        
        # Update the tree
        self.update_breach_tab()
        
        return tab
        
    def create_browser_tab(self):
        """Create the browser analyzer tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("Browser Analyzer")
        header.setObjectName("headingLabel")
        layout.addWidget(header)
        
        description = QLabel(
            "Analyze browser data for tracking cookies and suspicious activity. "
            "CyberFox can detect excessive tracking, suspicious browser extensions, and other privacy concerns."
        )
        description.setObjectName("subheadingLabel")
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Browser analyzer actions
        actions_layout = QHBoxLayout()
        
        # Scan Chrome button
        scan_chrome_btn = QPushButton("Scan Chrome")
        scan_chrome_btn.setMinimumHeight(50)
        scan_chrome_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_globe_temp.svg")))
        scan_chrome_btn.clicked.connect(lambda: self.scan_specific_browser("chrome"))
        actions_layout.addWidget(scan_chrome_btn)
        
        # Scan Firefox button
        scan_firefox_btn = QPushButton("Scan Firefox")
        scan_firefox_btn.setMinimumHeight(50)
        scan_firefox_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_globe_temp.svg")))
        scan_firefox_btn.clicked.connect(lambda: self.scan_specific_browser("firefox"))
        actions_layout.addWidget(scan_firefox_btn)
        
        # Scan Edge button
        scan_edge_btn = QPushButton("Scan Edge")
        scan_edge_btn.setMinimumHeight(50)
        scan_edge_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_globe_temp.svg")))
        scan_edge_btn.clicked.connect(lambda: self.scan_specific_browser("edge"))
        actions_layout.addWidget(scan_edge_btn)
        
        # Scan All button
        scan_all_btn = QPushButton("Scan All Browsers")
        scan_all_btn.setMinimumHeight(50)
        scan_all_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_search_temp.svg")))
        scan_all_btn.clicked.connect(self.scan_browsers)
        actions_layout.addWidget(scan_all_btn)
        
        layout.addLayout(actions_layout)
        
        # Browser threats frame
        threats_frame = QFrame()
        threats_frame.setObjectName("cardWidget")
        threats_frame.setFrameShape(QFrame.StyledPanel)
        threats_frame.setFrameShadow(QFrame.Raised)
        threats_layout = QVBoxLayout(threats_frame)
        
        # Threats header
        threats_header = QLabel("Browser Privacy Issues")
        threats_header.setObjectName("subheadingLabel")
        threats_layout.addWidget(threats_header)
        
        # Threats tree
        self.browser_threats_tree = QTreeWidget()
        self.browser_threats_tree.setHeaderLabels(["Description", "Browser", "Level", "Source", "Detection Time"])
        self.browser_threats_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.browser_threats_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.browser_threats_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.browser_threats_tree.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.browser_threats_tree.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.browser_threats_tree.setAlternatingRowColors(True)
        self.browser_threats_tree.itemDoubleClicked.connect(self.show_threat_details)
        threats_layout.addWidget(self.browser_threats_tree)
        
        layout.addWidget(threats_frame)
        
        # Privacy tips frame
        tips_frame = QFrame()
        tips_frame.setObjectName("cardWidget")
        tips_frame.setFrameShape(QFrame.StyledPanel)
        tips_frame.setFrameShadow(QFrame.Raised)
        tips_layout = QVBoxLayout(tips_frame)
        
        # Tips header
        tips_header = QLabel("Browser Privacy Tips")
        tips_header.setObjectName("subheadingLabel")
        tips_layout.addWidget(tips_header)
        
        # Tips text
        tips_text = QLabel(
            "• Clear your cookies regularly or use browser settings to clear them automatically\n"
            "• Use privacy-focused extensions like Privacy Badger, uBlock Origin, or HTTPS Everywhere\n"
            "• Consider using private/incognito mode for sensitive browsing\n"
            "• Review browser privacy settings and disable unnecessary tracking features\n"
            "• Use a privacy-focused browser like Firefox or Brave for sensitive activities\n"
            "• Regularly review and remove browser extensions you no longer use\n"
            "• Consider using a VPN for additional privacy protection"
        )
        tips_text.setWordWrap(True)
        tips_layout.addWidget(tips_text)
        
        layout.addWidget(tips_frame)
        
        # Update the tree
        self.update_browser_tab()
        
        return tab
        
    def create_threat_log_tab(self):
        """Create the threat log tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("Threat Log")
        header.setObjectName("headingLabel")
        layout.addWidget(header)
        
        description = QLabel(
            "View a comprehensive log of all detected threats and alerts. "
            "Double-click on any threat to view detailed information."
        )
        description.setObjectName("subheadingLabel")
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Threat log actions
        actions_layout = QHBoxLayout()
        
        # Clear log button
        clear_log_btn = QPushButton("Clear Log")
        clear_log_btn.setMinimumHeight(50)
        clear_log_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_trash_temp.svg")))
        clear_log_btn.clicked.connect(self.clear_threats)
        actions_layout.addWidget(clear_log_btn)
        
        # Refresh button
        refresh_log_btn = QPushButton("Refresh")
        refresh_log_btn.setMinimumHeight(50)
        refresh_log_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_refresh_temp.svg")))
        refresh_log_btn.clicked.connect(self.update_threat_log)
        actions_layout.addWidget(refresh_log_btn)
        
        layout.addLayout(actions_layout)
        
        # Threats tree
        self.all_threats_tree = QTreeWidget()
        self.all_threats_tree.setHeaderLabels(["Description", "Type", "Level", "Source", "Detection Time"])
        self.all_threats_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.all_threats_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.all_threats_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.all_threats_tree.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.all_threats_tree.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.all_threats_tree.setAlternatingRowColors(True)
        self.all_threats_tree.itemDoubleClicked.connect(self.show_threat_details)
        layout.addWidget(self.all_threats_tree)
        
        # Update the tree
        self.update_threat_log()
        
        return tab
        
    def create_settings_tab(self):
        """Create the settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("Settings")
        header.setObjectName("headingLabel")
        layout.addWidget(header)
        
        description = QLabel(
            "Configure CyberFox settings for scanning, monitoring, and user interface preferences."
        )
        description.setObjectName("subheadingLabel")
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Settings containers
        # Scan settings
        scan_frame = QFrame()
        scan_frame.setObjectName("cardWidget")
        scan_frame.setFrameShape(QFrame.StyledPanel)
        scan_frame.setFrameShadow(QFrame.Raised)
        scan_layout = QVBoxLayout(scan_frame)
        
        scan_header = QLabel("Scan Settings")
        scan_header.setObjectName("subheadingLabel")
        scan_layout.addWidget(scan_header)
        
        # Add scan settings UI elements here
        # This would typically include checkboxes, input fields, etc.
        # For the sake of brevity, I'm keeping this minimal
        
        layout.addWidget(scan_frame)
        
        # Dark web settings
        darkweb_frame = QFrame()
        darkweb_frame.setObjectName("cardWidget")
        darkweb_frame.setFrameShape(QFrame.StyledPanel)
        darkweb_frame.setFrameShadow(QFrame.Raised)
        darkweb_layout = QVBoxLayout(darkweb_frame)
        
        darkweb_header = QLabel("Dark Web Monitoring Settings")
        darkweb_header.setObjectName("subheadingLabel")
        darkweb_layout.addWidget(darkweb_header)
        
        # Add dark web settings UI elements here
        
        layout.addWidget(darkweb_frame)
        
        # Breach checker settings
        breach_frame = QFrame()
        breach_frame.setObjectName("cardWidget")
        breach_frame.setFrameShape(QFrame.StyledPanel)
        breach_frame.setFrameShadow(QFrame.Raised)
        breach_layout = QVBoxLayout(breach_frame)
        
        breach_header = QLabel("Data Breach Checker Settings")
        breach_header.setObjectName("subheadingLabel")
        breach_layout.addWidget(breach_header)
        
        # Add breach checker settings UI elements here
        
        layout.addWidget(breach_frame)
        
        # UI settings
        ui_frame = QFrame()
        ui_frame.setObjectName("cardWidget")
        ui_frame.setFrameShape(QFrame.StyledPanel)
        ui_frame.setFrameShadow(QFrame.Raised)
        ui_layout = QVBoxLayout(ui_frame)
        
        ui_header = QLabel("User Interface Settings")
        ui_header.setObjectName("subheadingLabel")
        ui_layout.addWidget(ui_header)
        
        # Add UI settings elements here
        
        layout.addWidget(ui_frame)
        
        # Save/Reset buttons
        buttons_layout = QHBoxLayout()
        
        save_btn = QPushButton("Save Settings")
        save_btn.setObjectName("successButton")
        save_btn.setMinimumHeight(50)
        save_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_check_temp.svg")))
        save_btn.clicked.connect(self.save_settings)
        buttons_layout.addWidget(save_btn)
        
        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.setObjectName("warningButton")
        reset_btn.setMinimumHeight(50)
        reset_btn.setIcon(QIcon(os.path.join(CONFIG_DIR, "icon_refresh_temp.svg")))
        reset_btn.clicked.connect(self.reset_settings)
        buttons_layout.addWidget(reset_btn)
        
        layout.addLayout(buttons_layout)
        
        return tab
    
    def on_tab_changed(self, index):
        """Handle tab change events."""
        tab_name = self.tab_widget.tabText(index)
        
        # Update specific tabs when they're selected
        if tab_name == "Scanner":
            self.update_file_threats_tree()
        elif tab_name == "Dark Web Monitor":
            self.update_darkweb_tab()
        elif tab_name == "Data Breach Checker":
            self.update_breach_tab()
        elif tab_name == "Browser Analyzer":
            self.update_browser_tab()
        elif tab_name == "Threat Log":
            self.update_threat_log()
            
    def update_stats(self):
        """Update status displays with current statistics."""
        # Update scanner stats
        scan_stats = self.file_scanner.scan_stats
        if scan_stats["start_time"] and not scan_stats["end_time"]:
            # Scan is running
            self.scan_status_title.setText("Status: <b>Scanning</b>")
            self.scan_files_scanned.setText(f"Files Scanned: {scan_stats['files_scanned']}")
            self.scan_threats_found.setText(f"Threats Found: {scan_stats['threats_found']}")
            self.scan_current_file.setText(f"Current File: {scan_stats['current_file'] or 'None'}")
            
            bytes_scanned = scan_stats["bytes_scanned"]
            if bytes_scanned < 1024:
                size_text = f"{bytes_scanned} bytes"
            elif bytes_scanned < 1024 * 1024:
                size_text = f"{bytes_scanned / 1024:.2f} KB"
            else:
                size_text = f"{bytes_scanned / (1024 * 1024):.2f} MB"
            self.scan_bytes_scanned.setText(f"Data Scanned: {size_text}")
            
            if scan_stats["start_time"]:
                elapsed = datetime.now() - scan_stats["start_time"]
                hours, remainder = divmod(elapsed.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                self.scan_time_elapsed.setText(f"Time Elapsed: {hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Update status bar
            self.scan_status_label.setText("Scanner: Active")
            scan_icon_svg = get_icon_svg("shield", COLORS[CONFIG["ui_settings"]["theme"]]["scanner_active"])
            scan_icon_file = os.path.join(CONFIG_DIR, "scan_icon_active_temp.svg")
            with open(scan_icon_file, "w") as f:
                f.write(scan_icon_svg)
            self.scan_icon.set_svg(scan_icon_file)
            self.scan_icon.start_animation()
            
            # Update buttons
            self.scan_action.setEnabled(False)
            self.stop_scan_action.setEnabled(True)
            if hasattr(self, 'stop_scan_btn'):
                self.stop_scan_btn.setEnabled(True)
        else:
            # Scan is not running
            self.scan_status_title.setText("Status: <b>Idle</b>")
            
            # Update status bar
            self.scan_status_label.setText("Scanner: Inactive")
            scan_icon_svg = get_icon_svg("shield", COLORS[CONFIG["ui_settings"]["theme"]]["scanner_inactive"])
            scan_icon_file = os.path.join(CONFIG_DIR, "scan_icon_inactive_temp.svg")
            with open(scan_icon_file, "w") as f:
                f.write(scan_icon_svg)
            self.scan_icon.set_svg(scan_icon_file)
            self.scan_icon.stop_animation()
            
            # Update buttons
            self.scan_action.setEnabled(True)
            self.stop_scan_action.setEnabled(False)
            if hasattr(self, 'stop_scan_btn'):
                self.stop_scan_btn.setEnabled(False)
        
        # Update dark web monitor stats
        monitor_stats = self.darkweb_monitor.monitoring_stats
        if monitor_stats["status"] == "active":
            # Monitoring is active
            self.monitor_status_title.setText("Status: <b>Active</b>")
            self.monitor_sites_scanned.setText(f"Sites Monitored: {monitor_stats['sites_monitored']}")
            self.monitor_alerts.setText(f"Alerts Triggered: {monitor_stats['alerts_triggered']}")
            self.monitor_current_site.setText(f"Current Site: {monitor_stats['current_site'] or 'None'}")
            
            if monitor_stats["last_scan"]:
                self.monitor_last_scan.setText(f"Last Scan: {monitor_stats['last_scan'].strftime('%Y-%m-%d %H:%M:%S')}")
            
            if monitor_stats["next_scan"]:
                self.monitor_next_scan.setText(f"Next Scan: {monitor_stats['next_scan'].strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Update status bar
            self.monitor_status_label.setText("Monitoring: Active")
            monitor_icon_svg = get_icon_svg("eye", COLORS[CONFIG["ui_settings"]["theme"]]["scanner_active"])
            monitor_icon_file = os.path.join(CONFIG_DIR, "monitor_icon_active_temp.svg")
            with open(monitor_icon_file, "w") as f:
                f.write(monitor_icon_svg)
            self.monitor_icon.set_svg(monitor_icon_file)
            self.monitor_icon.start_animation()
            
            # Update buttons
            self.monitor_action.setEnabled(False)
            self.stop_monitor_action.setEnabled(True)
            if hasattr(self, 'start_monitor_btn') and hasattr(self, 'stop_monitor_btn'):
                self.start_monitor_btn.setEnabled(False)
                self.stop_monitor_btn.setEnabled(True)
        else:
            # Monitoring is inactive
            self.monitor_status_title.setText("Status: <b>Inactive</b>")
            
            # Update status bar
            self.monitor_status_label.setText("Monitoring: Inactive")
            monitor_icon_svg = get_icon_svg("eye", COLORS[CONFIG["ui_settings"]["theme"]]["scanner_inactive"])
            monitor_icon_file = os.path.join(CONFIG_DIR, "monitor_icon_inactive_temp.svg")
            with open(monitor_icon_file, "w") as f:
                f.write(monitor_icon_svg)
            self.monitor_icon.set_svg(monitor_icon_file)
            self.monitor_icon.stop_animation()
            
            # Update buttons
            self.monitor_action.setEnabled(True)
            self.stop_monitor_action.setEnabled(False)
            if hasattr(self, 'start_monitor_btn') and hasattr(self, 'stop_monitor_btn'):
                self.start_monitor_btn.setEnabled(True)
                self.stop_monitor_btn.setEnabled(False)
        
        # Update breach checker stats
        checker_stats = self.breach_checker.checker_stats
        if checker_stats["status"] == "active":
            # Checker is active
            self.breach_status_title.setText("Status: <b>Active</b>")
            self.breach_emails_checked.setText(f"Emails Checked: {checker_stats['emails_checked']}")
            self.breach_breaches_found.setText(f"Breaches Found: {checker_stats['breaches_found']}")
            self.breach_current_email.setText(f"Current Email: {checker_stats['current_email'] or 'None'}")
            
            if checker_stats["last_check"]:
                self.breach_last_check.setText(f"Last Check: {checker_stats['last_check'].strftime('%Y-%m-%d %H:%M:%S')}")
            
            if checker_stats["next_check"]:
                self.breach_next_check.setText(f"Next Check: {checker_stats['next_check'].strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Update buttons
            if hasattr(self, 'start_checker_btn') and hasattr(self, 'stop_checker_btn'):
                self.start_checker_btn.setEnabled(False)
                self.stop_checker_btn.setEnabled(True)
        else:
            # Checker is inactive
            self.breach_status_title.setText("Status: <b>Inactive</b>")
            
            # Update buttons
            if hasattr(self, 'start_checker_btn') and hasattr(self, 'stop_checker_btn'):
                self.start_checker_btn.setEnabled(True)
                self.stop_checker_btn.setEnabled(False)
        
        # Update real-time protection stats
        protection_stats = self.realtime_protection.get_stats()
        if protection_stats["status"] == "active":
            # Protection is active
            # Update status bar
            self.realtime_status_label.setText("Real-time Protection: Active")
            realtime_icon_svg = get_icon_svg("activity", COLORS[CONFIG["ui_settings"]["theme"]]["scanner_active"])
            realtime_icon_file = os.path.join(CONFIG_DIR, "realtime_icon_active_temp.svg")
            with open(realtime_icon_file, "w") as f:
                f.write(realtime_icon_svg)
            self.realtime_icon.set_svg(realtime_icon_file)
            self.realtime_icon.start_animation()
        else:
            # Protection is inactive
            # Update status bar
            self.realtime_status_label.setText("Real-time Protection: Inactive")
            realtime_icon_svg = get_icon_svg("activity", COLORS[CONFIG["ui_settings"]["theme"]]["scanner_inactive"])
            realtime_icon_file = os.path.join(CONFIG_DIR, "realtime_icon_inactive_temp.svg")
            with open(realtime_icon_file, "w") as f:
                f.write(realtime_icon_svg)
            self.realtime_icon.set_svg(realtime_icon_file)
            self.realtime_icon.stop_animation()
        
        # Update threat counts in status bar
        threat_count = len(self.threat_db.threats)
        self.status_label.setText(f"Threats Detected: {threat_count}")
        
    def update_file_threats_tree(self):
        """Update the file threats tree."""
        self.file_threats_tree.clear()
        
        # Get all file threats
        file_threats = [t for t in self.threat_db.threats if isinstance(t, FileThreat)]
        
        # Sort by timestamp, newest first
        file_threats.sort(key=lambda t: t.timestamp, reverse=True)
        
        # Add to tree
        for threat in file_threats:
            item = QTreeWidgetItem([
                threat.description,
                threat.level.value,
                threat.filepath,
                threat.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            ])
            
            # Set color based on threat level
            level_colors = {
                ThreatLevel.CRITICAL: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_critical"]),
                ThreatLevel.HIGH: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_high"]),
                ThreatLevel.MEDIUM: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_medium"]),
                ThreatLevel.LOW: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_low"]),
            }
            
            item.setForeground(1, level_colors[threat.level])
            
            # Store the threat in the item's data
            item.setData(0, Qt.UserRole, threat)
            
            self.file_threats_tree.addTopLevelItem(item)
            
    def update_darkweb_tab(self):
        """Update the dark web monitoring tab."""
        # Update keywords list
        self.keywords_tree.clear()
        for keyword in CONFIG["darkweb_monitor"]["keywords"]:
            item = QTreeWidgetItem([keyword])
            self.keywords_tree.addTopLevelItem(item)
        
        # Update emails list
        self.emails_tree.clear()
        for email in CONFIG["darkweb_monitor"]["emails"]:
            item = QTreeWidgetItem([email])
            self.emails_tree.addTopLevelItem(item)
        
        # Update darkweb threats tree
        self.darkweb_threats_tree.clear()
        
        # Get all darkweb threats
        darkweb_threats = [t for t in self.threat_db.threats if isinstance(t, DarkWebThreat)]
        
        # Sort by timestamp, newest first
        darkweb_threats.sort(key=lambda t: t.timestamp, reverse=True)
        
        # Add to tree
        for threat in darkweb_threats:
            # Create a comprehensive list of found items that combines keywords and sensitive data types
            found_items = threat.keywords.copy()
            
            # Add sensitive data indicators if present
            if hasattr(threat, 'sensitive_data') and threat.sensitive_data:
                if threat.sensitive_data.get('credit_cards'):
                    found_items.append(f"{len(threat.sensitive_data['credit_cards'])} credit card(s)")
                    
                if threat.sensitive_data.get('bitcoin_addresses'):
                    found_items.append(f"{len(threat.sensitive_data['bitcoin_addresses'])} crypto address(es)")
                    
                if threat.sensitive_data.get('phone_numbers'):
                    found_items.append(f"{len(threat.sensitive_data['phone_numbers'])} phone number(s)")
                    
                if threat.sensitive_data.get('ssn') and threat.sensitive_data['ssn']:
                    found_items.append(f"{len(threat.sensitive_data['ssn'])} SSN(s)")
                    
                if threat.sensitive_data.get('ip_addresses'):
                    found_items.append(f"{len(threat.sensitive_data['ip_addresses'])} IP address(es)")
            
            item = QTreeWidgetItem([
                threat.description,
                threat.level.value,
                ", ".join(found_items),
                threat.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            ])
            
            # Set color based on threat level
            level_colors = {
                ThreatLevel.CRITICAL: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_critical"]),
                ThreatLevel.HIGH: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_high"]),
                ThreatLevel.MEDIUM: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_medium"]),
                ThreatLevel.LOW: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_low"]),
            }
            
            item.setForeground(1, level_colors[threat.level])
            
            # Store the threat in the item's data
            item.setData(0, Qt.UserRole, threat)
            
            self.darkweb_threats_tree.addTopLevelItem(item)
            
    def update_breach_tab(self):
        """Update the breach checker tab."""
        # Update breach threats tree
        self.breach_threats_tree.clear()
        
        # Get all breach threats
        breach_threats = [t for t in self.threat_db.threats if isinstance(t, DataBreachThreat)]
        
        # Sort by timestamp, newest first
        breach_threats.sort(key=lambda t: t.timestamp, reverse=True)
        
        # Add to tree
        for threat in breach_threats:
            item = QTreeWidgetItem([
                threat.email,
                threat.breach_name,
                threat.level.value,
                threat.breach_date.strftime("%Y-%m-%d"),
                threat.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            ])
            
            # Set color based on threat level
            level_colors = {
                ThreatLevel.CRITICAL: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_critical"]),
                ThreatLevel.HIGH: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_high"]),
                ThreatLevel.MEDIUM: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_medium"]),
                ThreatLevel.LOW: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_low"]),
            }
            
            item.setForeground(2, level_colors[threat.level])
            
            # Store the threat in the item's data
            item.setData(0, Qt.UserRole, threat)
            
            self.breach_threats_tree.addTopLevelItem(item)
            
    def update_browser_tab(self):
        """Update the browser analyzer tab."""
        # Update browser threats tree
        self.browser_threats_tree.clear()
        
        # Get all browser threats
        browser_threats = [t for t in self.threat_db.threats if isinstance(t, BrowserThreat)]
        
        # Sort by timestamp, newest first
        browser_threats.sort(key=lambda t: t.timestamp, reverse=True)
        
        # Add to tree
        for threat in browser_threats:
            item = QTreeWidgetItem([
                threat.description,
                threat.browser,
                threat.level.value,
                threat.threat_source,
                threat.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            ])
            
            # Set color based on threat level
            level_colors = {
                ThreatLevel.CRITICAL: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_critical"]),
                ThreatLevel.HIGH: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_high"]),
                ThreatLevel.MEDIUM: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_medium"]),
                ThreatLevel.LOW: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_low"]),
            }
            
            item.setForeground(2, level_colors[threat.level])
            
            # Store the threat in the item's data
            item.setData(0, Qt.UserRole, threat)
            
            self.browser_threats_tree.addTopLevelItem(item)
            
    def update_threat_log(self):
        """Update the threat log tab."""
        # Update all threats tree
        self.all_threats_tree.clear()
        
        # Get all threats
        all_threats = self.threat_db.threats.copy()
        
        # Sort by timestamp, newest first
        all_threats.sort(key=lambda t: t.timestamp, reverse=True)
        
        # Add to tree
        for threat in all_threats:
            # Determine source based on threat type
            source = "Unknown"
            if isinstance(threat, FileThreat):
                source = "File Scanner"
            elif isinstance(threat, DarkWebThreat):
                source = "Dark Web Monitor"
                
                # Add indicator icon for sensitive data if present 
                if hasattr(threat, 'sensitive_data') and threat.sensitive_data:
                    sensitive_data_present = False
                    for data_type in ['credit_cards', 'bitcoin_addresses', 'ssn']:
                        if threat.sensitive_data.get(data_type) and threat.sensitive_data[data_type]:
                            sensitive_data_present = True
                            break
                    
                    if sensitive_data_present:
                        # Add critical indicator to description
                        threat.description = "⚠️ " + threat.description
            elif isinstance(threat, DataBreachThreat):
                source = "Breach Checker"
            elif isinstance(threat, BrowserThreat):
                source = "Browser Analyzer"
                
            item = QTreeWidgetItem([
                threat.description,
                threat.type.value,
                threat.level.value,
                source,
                threat.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            ])
            
            # Set color based on threat level
            level_colors = {
                ThreatLevel.CRITICAL: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_critical"]),
                ThreatLevel.HIGH: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_high"]),
                ThreatLevel.MEDIUM: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_medium"]),
                ThreatLevel.LOW: QColor(COLORS[CONFIG["ui_settings"]["theme"]]["threat_low"]),
            }
            
            item.setForeground(2, level_colors[threat.level])
            
            # Store the threat in the item's data
            item.setData(0, Qt.UserRole, threat)
            
            self.all_threats_tree.addTopLevelItem(item)
            
    def on_threat_detected(self, threat: Threat):
        """Handle a newly detected threat."""
        # Add to threat database
        self.threat_db.add_threat(threat)
        
        # Send to n8n if configured
        if CONFIG["n8n_integration"]["enabled"]:
            self.n8n.send_threat(threat)
        
        # Update UI
        self.update_stats()
        
        # Update specific tree based on threat type
        if isinstance(threat, FileThreat):
            self.update_file_threats_tree()
        elif isinstance(threat, DarkWebThreat):
            self.update_darkweb_tab()
        elif isinstance(threat, DataBreachThreat):
            self.update_breach_tab()
        elif isinstance(threat, BrowserThreat):
            self.update_browser_tab()
            
        # Update overall threat log
        self.update_threat_log()
        
    def start_quick_scan(self):
        """Start a quick scan of common locations."""
        # Common locations to scan
        locations = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/AppData/Local/Temp") if os.name == 'nt' else "/tmp",
        ]
        
        # Filter out non-existent locations
        locations = [loc for loc in locations if os.path.exists(loc)]
        
        # Start the scan
        self.file_scanner.start_scan(locations, True)
        
        # Update the UI
        self.update_stats()
        
        # Show a notification
        self.status_bar.showMessage("Quick scan started...", 3000)
        
    def start_full_scan(self):
        """Start a full system scan."""
        # Start the scan with no specific paths (will scan all drives)
        self.file_scanner.start_scan(None, True)
        
        # Update the UI
        self.update_stats()
        
        # Show a notification
        self.status_bar.showMessage("Full system scan started...", 3000)
        
    def start_custom_scan(self):
        """Start a custom scan of user-selected locations."""
        # Open directory selection dialog
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Directory to Scan",
            os.path.expanduser("~"),
            QFileDialog.ShowDirsOnly
        )
        
        if dir_path:
            # Start the scan
            self.file_scanner.start_scan([dir_path], True)
            
            # Update the UI
            self.update_stats()
            
            # Show a notification
            self.status_bar.showMessage(f"Custom scan of {dir_path} started...", 3000)
        
    def stop_scan(self):
        """Stop the current scan."""
        self.file_scanner.stop_scanning()
        
        # Update the UI
        self.update_stats()
        
        # Show a notification
        self.status_bar.showMessage("Scan stopped", 3000)
        
    def start_monitoring(self):
        """Start dark web monitoring."""
        if not CONFIG["darkweb_monitor"]["keywords"] and not CONFIG["darkweb_monitor"]["emails"]:
            QMessageBox.warning(
                self,
                "No Monitoring Items",
                "Please add at least one keyword or email address to monitor."
            )
            return
            
        # Start monitoring
        self.darkweb_monitor.monitor_dark_web()
        
        # Start breach checker if enabled
        if CONFIG["breach_check"]["enable_hibp"]:
            self.breach_checker.start_checker()
        
        # Update the UI
        self.update_stats()
        
        # Show a notification
        self.status_bar.showMessage("Dark web monitoring started", 3000)
        
    def stop_monitoring(self):
        """Stop dark web monitoring."""
        # Stop monitoring
        self.darkweb_monitor.stop_monitoring()
        
        # Stop breach checker
        self.breach_checker.stop_checker()
        
        # Update the UI
        self.update_stats()
        
        # Show a notification
        self.status_bar.showMessage("Dark web monitoring stopped", 3000)
        
    def add_keyword(self):
        """Add a keyword to monitor."""
        keyword, ok = QInputDialog.getText(
            self,
            "Add Keyword",
            "Enter a keyword to monitor on the dark web:"
        )
        
        if ok and keyword:
            if self.darkweb_monitor.add_keyword(keyword):
                # Update the UI
                self.update_darkweb_tab()
                
                # Show a notification
                self.status_bar.showMessage(f"Keyword '{keyword}' added", 3000)
            else:
                QMessageBox.warning(
                    self,
                    "Add Keyword",
                    f"Keyword '{keyword}' could not be added. It may already exist."
                )
        
    def add_email(self):
        """Add an email to monitor."""
        email, ok = QInputDialog.getText(
            self,
            "Add Email",
            "Enter an email address to monitor for breaches and dark web mentions:"
        )
        
        if ok and email:
            if self.darkweb_monitor.add_email(email):
                # Update the UI
                self.update_darkweb_tab()
                
                # Show a notification
                self.status_bar.showMessage(f"Email '{email}' added", 3000)
            else:
                QMessageBox.warning(
                    self,
                    "Add Email",
                    f"Email '{email}' could not be added. It may be invalid or already exist."
                )
        
    def show_keyword_context_menu(self, position):
        """Show context menu for keywords."""
        item = self.keywords_tree.itemAt(position)
        if not item:
            return
            
        keyword = item.text(0)
        
        menu = QMenu()
        remove_action = menu.addAction("Remove Keyword")
        
        action = menu.exec_(self.keywords_tree.mapToGlobal(position))
        
        if action == remove_action:
            if self.darkweb_monitor.remove_keyword(keyword):
                # Update the UI
                self.update_darkweb_tab()
                
                # Show a notification
                self.status_bar.showMessage(f"Keyword '{keyword}' removed", 3000)
        
    def show_email_context_menu(self, position):
        """Show context menu for emails."""
        item = self.emails_tree.itemAt(position)
        if not item:
            return
            
        email = item.text(0)
        
        menu = QMenu()
        remove_action = menu.addAction("Remove Email")
        check_action = menu.addAction("Check for Breaches")
        
        action = menu.exec_(self.emails_tree.mapToGlobal(position))
        
        if action == remove_action:
            if self.darkweb_monitor.remove_email(email):
                # Update the UI
                self.update_darkweb_tab()
                
                # Show a notification
                self.status_bar.showMessage(f"Email '{email}' removed", 3000)
        elif action == check_action:
            # Check for breaches
            self.check_specific_email(email)
        
    def check_email(self):
        """Check an email for breaches."""
        email, ok = QInputDialog.getText(
            self,
            "Check Email",
            "Enter an email address to check for breaches:"
        )
        
        if ok and email:
            self.check_specific_email(email)
            
    def check_specific_email(self, email):
        """Check a specific email for breaches."""
        # Show a message that we're checking
        self.status_bar.showMessage(f"Checking email '{email}' for breaches...", 3000)
        
        # Check the email
        threats = self.breach_checker.manual_check(email)
        
        if threats:
            # Update the UI
            self.update_breach_tab()
            self.update_threat_log()
            
            # Show a notification
            QMessageBox.warning(
                self,
                "Breaches Found",
                f"Found {len(threats)} breaches for email '{email}'.\n\n"
                "See the Data Breach Checker tab for details."
            )
        else:
            # Show a notification
            QMessageBox.information(
                self,
                "No Breaches Found",
                f"No breaches found for email '{email}'."
            )
        
    def start_breach_checker(self):
        """Start the breach checker."""
        if not CONFIG["darkweb_monitor"]["emails"]:
            QMessageBox.warning(
                self,
                "No Emails",
                "Please add at least one email address to check for breaches."
            )
            return
            
        # Start the checker
        success = self.breach_checker.start_checker()
        
        if not success:
            QMessageBox.warning(
                self,
                "Breach Checker",
                "Could not start breach checker. Please check your API key."
            )
            return
            
        # Update the UI
        self.update_stats()
        
        # Show a notification
        self.status_bar.showMessage("Breach checker started", 3000)
        
    def stop_breach_checker(self):
        """Stop the breach checker."""
        # Stop the checker
        self.breach_checker.stop_checker()
        
        # Update the UI
        self.update_stats()
        
        # Show a notification
        self.status_bar.showMessage("Breach checker stopped", 3000)
        
    def scan_browsers(self):
        """Scan all browsers."""
        # Show a message that we're scanning
        self.status_bar.showMessage("Scanning browsers for privacy issues...", 3000)
        
        # Scan all browsers
        threats = self.browser_analyzer.scan_all_browsers()
        
        # Update the UI
        self.update_browser_tab()
        self.update_threat_log()
        
        # Show a notification
        if threats:
            QMessageBox.warning(
                self,
                "Browser Issues Found",
                f"Found {len(threats)} privacy issues in your browsers.\n\n"
                "See the Browser Analyzer tab for details."
            )
        else:
            QMessageBox.information(
                self,
                "No Issues Found",
                "No privacy issues found in your browsers."
            )
        
    def scan_specific_browser(self, browser):
        """Scan a specific browser."""
        # Show a message that we're scanning
        self.status_bar.showMessage(f"Scanning {browser} for privacy issues...", 3000)
        
        # Scan the browser
        threats = self.browser_analyzer.scan_browser(browser)
        
        # Update the UI
        self.update_browser_tab()
        self.update_threat_log()
        
        # Show a notification
        if threats:
            QMessageBox.warning(
                self,
                "Browser Issues Found",
                f"Found {len(threats)} privacy issues in {browser}.\n\n"
                "See the Browser Analyzer tab for details."
            )
        else:
            QMessageBox.information(
                self,
                "No Issues Found",
                f"No privacy issues found in {browser}."
            )
        
    def clear_threats(self):
        """Clear all threats from the database."""
        reply = QMessageBox.question(
            self,
            "Clear Threats",
            "Are you sure you want to clear all threats from the database?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Clear the database
            self.threat_db.clear()
            
            # Update all trees
            self.update_file_threats_tree()
            self.update_darkweb_tab()
            self.update_breach_tab()
            self.update_browser_tab()
            self.update_threat_log()
            
            # Show a notification
            self.status_bar.showMessage("Threat database cleared", 3000)
        
    def show_threat_details(self, item, column):
        """Show detailed information about a threat."""
        # Get the threat from the item's data
        threat = item.data(0, Qt.UserRole)
        
        if not threat:
            return
            
        # Create a dialog to show the details
        dialog = QDialog(self)
        dialog.setWindowTitle("Threat Details")
        dialog.setMinimumSize(500, 400)
        
        layout = QVBoxLayout(dialog)
        
        # Threat header
        header = QLabel(threat.description)
        header.setObjectName("headingLabel")
        header.setWordWrap(True)
        layout.addWidget(header)
        
        # Basic info
        basic_frame = QFrame()
        basic_frame.setObjectName("cardWidget")
        basic_frame.setFrameShape(QFrame.StyledPanel)
        basic_frame.setFrameShadow(QFrame.Raised)
        basic_layout = QVBoxLayout(basic_frame)
        
        basic_layout.addWidget(QLabel(f"Type: {threat.type.value}"))
        basic_layout.addWidget(QLabel(f"Level: {threat.level.value}"))
        basic_layout.addWidget(QLabel(f"Detected: {threat.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"))
        basic_layout.addWidget(QLabel(f"Source: {threat.source or 'Unknown'}"))
        
        layout.addWidget(basic_frame)
        
        # Specific info based on threat type
        if isinstance(threat, FileThreat):
            file_frame = QFrame()
            file_frame.setObjectName("cardWidget")
            file_frame.setFrameShape(QFrame.StyledPanel)
            file_frame.setFrameShadow(QFrame.Raised)
            file_layout = QVBoxLayout(file_frame)
            
            file_layout.addWidget(QLabel(f"File Path: {threat.filepath}"))
            if threat.hash:
                file_layout.addWidget(QLabel(f"File Hash: {threat.hash}"))
            if threat.file_size:
                size_text = f"{threat.file_size} bytes"
                if threat.file_size >= 1024:
                    size_text += f" ({threat.file_size / 1024:.2f} KB)"
                if threat.file_size >= 1024 * 1024:
                    size_text += f" ({threat.file_size / (1024 * 1024):.2f} MB)"
                file_layout.addWidget(QLabel(f"File Size: {size_text}"))
            
            layout.addWidget(file_frame)
            
        elif isinstance(threat, DarkWebThreat):
            darkweb_frame = QFrame()
            darkweb_frame.setObjectName("cardWidget")
            darkweb_frame.setFrameShape(QFrame.StyledPanel)
            darkweb_frame.setFrameShadow(QFrame.Raised)
            darkweb_layout = QVBoxLayout(darkweb_frame)
            
            darkweb_layout.addWidget(QLabel(f"Keywords Found: {', '.join(threat.keywords)}"))
            if threat.url:
                darkweb_layout.addWidget(QLabel(f"Source URL: {threat.url}"))
                
            # Display sensitive data if present
            if hasattr(threat, 'sensitive_data') and threat.sensitive_data:
                sensitive_data_found = False
                
                # Credit card numbers (masked for security)
                if threat.sensitive_data.get('credit_cards'):
                    sensitive_data_found = True
                    cc_list = []
                    for cc in threat.sensitive_data['credit_cards']:
                        # Show only first 4 and last 4 digits
                        masked_cc = cc[0:4] + "********" + cc[-4:]
                        cc_list.append(masked_cc)
                    darkweb_layout.addWidget(QLabel(f"Credit Cards Found: {', '.join(cc_list)}"))
                
                # Bitcoin addresses (partially masked)
                if threat.sensitive_data.get('bitcoin_addresses'):
                    sensitive_data_found = True
                    btc_list = []
                    for btc in threat.sensitive_data['bitcoin_addresses']:
                        # Show only first 6 and last 4 characters
                        masked_btc = btc[0:6] + "..." + btc[-4:]
                        btc_list.append(masked_btc)
                    darkweb_layout.addWidget(QLabel(f"Cryptocurrency Addresses Found: {', '.join(btc_list)}"))
                
                # Phone numbers (masked)
                if threat.sensitive_data.get('phone_numbers'):
                    sensitive_data_found = True
                    phone_list = []
                    for phone in threat.sensitive_data['phone_numbers']:
                        # Show only country code and last 2 digits
                        if len(phone) > 4:
                            masked_phone = phone[0:3] + "****" + phone[-2:]
                            phone_list.append(masked_phone)
                        else:
                            phone_list.append("*******")
                    darkweb_layout.addWidget(QLabel(f"Phone Numbers Found: {', '.join(phone_list)}"))
                
                # SSNs (always masked)
                if threat.sensitive_data.get('ssn') and threat.sensitive_data['ssn']:
                    sensitive_data_found = True
                    darkweb_layout.addWidget(QLabel(f"Social Security Numbers Found: {len(threat.sensitive_data['ssn'])} (masked for security)"))
                
                # IP addresses
                if threat.sensitive_data.get('ip_addresses'):
                    sensitive_data_found = True
                    darkweb_layout.addWidget(QLabel(f"IP Addresses Found: {', '.join(threat.sensitive_data['ip_addresses'])}"))
                
                if sensitive_data_found:
                    darkweb_layout.addWidget(QLabel(""))
                    sensitive_warning = QLabel("⚠️ WARNING: Highly sensitive data was detected!")
                    sensitive_warning.setStyleSheet(f"color: {COLORS[CONFIG['ui_settings']['theme']]['threat_critical']}; font-weight: bold;")
                    darkweb_layout.addWidget(sensitive_warning)
            
            # Content snippet
            if threat.content_snippet:
                darkweb_layout.addWidget(QLabel("Content Snippet:"))
                snippet = QLabel(threat.content_snippet)
                snippet.setWordWrap(True)
                snippet.setTextInteractionFlags(Qt.TextSelectableByMouse)
                darkweb_layout.addWidget(snippet)
            
            layout.addWidget(darkweb_frame)
            
        elif isinstance(threat, DataBreachThreat):
            breach_frame = QFrame()
            breach_frame.setObjectName("cardWidget")
            breach_frame.setFrameShape(QFrame.StyledPanel)
            breach_frame.setFrameShadow(QFrame.Raised)
            breach_layout = QVBoxLayout(breach_frame)
            
            breach_layout.addWidget(QLabel(f"Email: {threat.email}"))
            breach_layout.addWidget(QLabel(f"Breach: {threat.breach_name}"))
            breach_layout.addWidget(QLabel(f"Breach Date: {threat.breach_date.strftime('%Y-%m-%d')}"))
            breach_layout.addWidget(QLabel(f"Data Compromised: {', '.join(threat.pwned_data)}"))
            
            layout.addWidget(breach_frame)
            
        elif isinstance(threat, BrowserThreat):
            browser_frame = QFrame()
            browser_frame.setObjectName("cardWidget")
            browser_frame.setFrameShape(QFrame.StyledPanel)
            browser_frame.setFrameShadow(QFrame.Raised)
            browser_layout = QVBoxLayout(browser_frame)
            
            browser_layout.addWidget(QLabel(f"Browser: {threat.browser}"))
            browser_layout.addWidget(QLabel(f"Source: {threat.threat_source}"))
            if threat.url:
                browser_layout.addWidget(QLabel(f"URL: {threat.url}"))
            
            layout.addWidget(browser_frame)
            
        # Details section
        if threat.details:
            details_frame = QFrame()
            details_frame.setObjectName("cardWidget")
            details_frame.setFrameShape(QFrame.StyledPanel)
            details_frame.setFrameShadow(QFrame.Raised)
            details_layout = QVBoxLayout(details_frame)
            
            details_layout.addWidget(QLabel("Additional Details:"))
            
            # Add all details as key-value pairs
            for key, value in threat.details.items():
                if isinstance(value, dict) or isinstance(value, list):
                    # Format nested structures
                    import json
                    formatted = json.dumps(value, indent=2)
                    details_layout.addWidget(QLabel(f"{key}:"))
                    text = QLabel(formatted)
                    text.setWordWrap(True)
                    text.setTextInteractionFlags(Qt.TextSelectableByMouse)
                    details_layout.addWidget(text)
                else:
                    details_layout.addWidget(QLabel(f"{key}: {value}"))
            
            layout.addWidget(details_frame)
        
        # Close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button)
        
        dialog.exec_()
        
    def change_theme(self, theme: Theme):
        """Change the application theme."""
        # Update config
        CONFIG["ui_settings"]["theme"] = theme.value
        save_config(CONFIG)
        
        # Apply new stylesheet
        from cyberfox.ui.style import get_stylesheet
        self.app().setStyleSheet(get_stylesheet(theme))
        
        # Show a notification
        self.status_bar.showMessage(f"Theme changed to {theme.value}", 3000)
        
        # Prompt for restart
        QMessageBox.information(
            self,
            "Theme Changed",
            "The theme has been changed. Some elements may not update until you restart the application."
        )
        
    def save_settings(self):
        """Save settings from the UI to the config file."""
        # In a full implementation, this would read values from UI controls
        # and update the CONFIG dictionary accordingly
        
        # For now, just save the current config
        save_config(CONFIG)
        
        # Show a notification
        self.status_bar.showMessage("Settings saved", 3000)
        
    def reset_settings(self):
        """Reset settings to defaults."""
        reply = QMessageBox.question(
            self,
            "Reset Settings",
            "Are you sure you want to reset all settings to defaults?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Reset config
            from cyberfox.config import DEFAULT_CONFIG
            global CONFIG
            CONFIG = DEFAULT_CONFIG.copy()
            save_config(CONFIG)
            
            # Show a notification
            self.status_bar.showMessage("Settings reset to defaults", 3000)
            
            # Prompt for restart
            QMessageBox.information(
                self,
                "Settings Reset",
                "Settings have been reset to defaults. Please restart the application for all changes to take effect."
            )
        
    def show_settings(self):
        """Show the settings tab."""
        self.tab_widget.setCurrentIndex(self.tab_widget.indexOf(self.settings_tab))
        
    def show_help(self):
        """Show help information."""
        QMessageBox.information(
            self,
            "CyberFox Help",
            "CyberFox is an advanced threat detection tool that helps you protect your system and data.\n\n"
            "Features:\n"
            "• File System Scanner: Detects malicious files and suspicious patterns\n"
            "• Dark Web Monitor: Searches the dark web for your sensitive information\n"
            "• Data Breach Checker: Checks if your email addresses have been compromised\n"
            "• Browser Analyzer: Detects privacy issues in your web browsers\n\n"
            "For more information, visit our website or contact support."
        )
        
    def show_about(self):
        """Show about information."""
        QMessageBox.about(
            self,
            "About CyberFox",
            f"CyberFox - Advanced Threat Detection\n\n"
            f"Version: {CONFIG['APP_VERSION']}\n"
            f"Author: {CONFIG['APP_AUTHOR']}\n\n"
            f"A comprehensive desktop threat detection tool with dark web monitoring, "
            f"file system scanning, and an animated graphical interface."
        )
        
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop all ongoing scans and monitoring
        self.file_scanner.stop_scanning()
        self.darkweb_monitor.stop_monitoring()
        self.breach_checker.stop_checker()
        
        # Accept the close event
        event.accept()
