"""
Dashboard widget for the CyberFox application.
Provides an overview of all threat detection components.
"""
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QFrame, QProgressBar, QTreeWidget, QTreeWidgetItem,
    QHeaderView, QSizePolicy, QSpacerItem, QGridLayout
)
from PyQt5.QtCore import Qt, QSize, QTimer, pyqtSignal
from PyQt5.QtGui import QIcon, QPixmap, QColor, QPalette
from PyQt5.QtSvg import QSvgWidget

from cyberfox.config import CONFIG, CONFIG_DIR
from cyberfox.ui.style import get_icon_svg, COLORS, Theme
from cyberfox.ui.animations import PulseAnimation, WaveAnimation, RadarAnimation
from cyberfox.core.threats import (
    Threat, FileThreat, DarkWebThreat, DataBreachThreat, 
    BrowserThreat, ThreatType, ThreatLevel, ThreatDatabase
)
from cyberfox.core.file_scanner import FileScanner
from cyberfox.core.darkweb_monitor import DarkWebMonitor
from cyberfox.core.breach_checker import BreachChecker
from cyberfox.core.browser_analyzer import BrowserAnalyzer

logger = logging.getLogger(__name__)

class DashboardWidget(QWidget):
    """Dashboard widget showing overview of all threat detection components."""
    
    def __init__(
        self, 
        threat_db: ThreatDatabase,
        file_scanner: FileScanner,
        darkweb_monitor: DarkWebMonitor,
        breach_checker: BreachChecker,
        browser_analyzer: BrowserAnalyzer
    ):
        """
        Initialize the dashboard widget.
        
        Args:
            threat_db: The threat database
            file_scanner: The file scanner instance
            darkweb_monitor: The dark web monitor instance
            breach_checker: The breach checker instance
            browser_analyzer: The browser analyzer instance
        """
        super().__init__()
        
        # Store references to components
        self.threat_db = threat_db
        self.file_scanner = file_scanner
        self.darkweb_monitor = darkweb_monitor
        self.breach_checker = breach_checker
        self.browser_analyzer = browser_analyzer
        
        # Set up the UI
        self.setup_ui()
        
        # Set up update timer (every 2 seconds)
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_dashboard)
        self.update_timer.start(2000)
        
        # Update immediately
        self.update_dashboard()
        
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("System Security Overview")
        header.setObjectName("headingLabel")
        layout.addWidget(header)
        
        description = QLabel(
            "Monitor your system's security status and view recent threats across all detection components."
        )
        description.setObjectName("subheadingLabel")
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Status cards row
        status_layout = QHBoxLayout()
        
        # File Scanner status card
        self.scanner_card = self.create_status_card(
            "File Scanner",
            "Inactive",
            "shield",
            COLORS[CONFIG["ui_settings"]["theme"]]["primary"]
        )
        status_layout.addWidget(self.scanner_card)
        
        # Dark Web Monitor status card
        self.monitor_card = self.create_status_card(
            "Dark Web Monitor",
            "Inactive",
            "eye",
            COLORS[CONFIG["ui_settings"]["theme"]]["primary"]
        )
        status_layout.addWidget(self.monitor_card)
        
        # Breach Checker status card
        self.breach_card = self.create_status_card(
            "Breach Checker",
            "Inactive",
            "search",
            COLORS[CONFIG["ui_settings"]["theme"]]["primary"]
        )
        status_layout.addWidget(self.breach_card)
        
        # Browser Analyzer status card
        self.browser_card = self.create_status_card(
            "Browser Analyzer",
            "Idle",
            "globe",
            COLORS[CONFIG["ui_settings"]["theme"]]["primary"]
        )
        status_layout.addWidget(self.browser_card)
        
        layout.addLayout(status_layout)
        
        # Threat summary card
        threat_summary = QFrame()
        threat_summary.setObjectName("cardWidget")
        threat_summary.setFrameShape(QFrame.StyledPanel)
        threat_summary.setFrameShadow(QFrame.Raised)
        threat_layout = QVBoxLayout(threat_summary)
        
        # Threat summary header
        threat_header = QHBoxLayout()
        
        threat_title = QLabel("Threat Summary")
        threat_title.setObjectName("subheadingLabel")
        threat_header.addWidget(threat_title)
        
        # Create radar animation
        radar_icon_svg = get_icon_svg("activity", COLORS[CONFIG["ui_settings"]["theme"]]["primary"])
        radar_icon_file = os.path.join(CONFIG_DIR, "radar_icon_temp.svg")
        with open(radar_icon_file, "w") as f:
            f.write(radar_icon_svg)
            
        self.radar_widget = RadarAnimation(radar_icon_file, 24, 24)
        threat_header.addWidget(self.radar_widget)
        threat_header.addStretch(1)
        
        threat_layout.addLayout(threat_header)
        
        # Threat stats grid
        threat_grid = QGridLayout()
        
        # Critical threats
        critical_label = QLabel("Critical:")
        critical_label.setStyleSheet(f"color: {COLORS[CONFIG['ui_settings']['theme']]['threat_critical']};")
        threat_grid.addWidget(critical_label, 0, 0)
        
        self.critical_count = QLabel("0")
        self.critical_count.setStyleSheet(f"color: {COLORS[CONFIG['ui_settings']['theme']]['threat_critical']}; font-weight: bold;")
        threat_grid.addWidget(self.critical_count, 0, 1)
        
        # High threats
        high_label = QLabel("High:")
        high_label.setStyleSheet(f"color: {COLORS[CONFIG['ui_settings']['theme']]['threat_high']};")
        threat_grid.addWidget(high_label, 0, 2)
        
        self.high_count = QLabel("0")
        self.high_count.setStyleSheet(f"color: {COLORS[CONFIG['ui_settings']['theme']]['threat_high']}; font-weight: bold;")
        threat_grid.addWidget(self.high_count, 0, 3)
        
        # Medium threats
        medium_label = QLabel("Medium:")
        medium_label.setStyleSheet(f"color: {COLORS[CONFIG['ui_settings']['theme']]['threat_medium']};")
        threat_grid.addWidget(medium_label, 1, 0)
        
        self.medium_count = QLabel("0")
        self.medium_count.setStyleSheet(f"color: {COLORS[CONFIG['ui_settings']['theme']]['threat_medium']}; font-weight: bold;")
        threat_grid.addWidget(self.medium_count, 1, 1)
        
        # Low threats
        low_label = QLabel("Low:")
        low_label.setStyleSheet(f"color: {COLORS[CONFIG['ui_settings']['theme']]['threat_low']};")
        threat_grid.addWidget(low_label, 1, 2)
        
        self.low_count = QLabel("0")
        self.low_count.setStyleSheet(f"color: {COLORS[CONFIG['ui_settings']['theme']]['threat_low']}; font-weight: bold;")
        threat_grid.addWidget(self.low_count, 1, 3)
        
        # Total threats
        total_label = QLabel("Total Threats:")
        total_label.setStyleSheet("font-weight: bold;")
        threat_grid.addWidget(total_label, 2, 0, 1, 3)
        
        self.total_count = QLabel("0")
        self.total_count.setStyleSheet("font-weight: bold;")
        threat_grid.addWidget(self.total_count, 2, 3)
        
        threat_layout.addLayout(threat_grid)
        
        # Threat type breakdown
        type_header = QLabel("Threat Types:")
        type_header.setObjectName("infoLabel")
        threat_layout.addWidget(type_header)
        
        # Progress bars for each threat type
        self.file_bar = QProgressBar()
        self.file_bar.setTextVisible(True)
        self.file_bar.setFormat("File System: %v")
        threat_layout.addWidget(self.file_bar)
        
        self.darkweb_bar = QProgressBar()
        self.darkweb_bar.setTextVisible(True)
        self.darkweb_bar.setFormat("Dark Web: %v")
        threat_layout.addWidget(self.darkweb_bar)
        
        self.breach_bar = QProgressBar()
        self.breach_bar.setTextVisible(True)
        self.breach_bar.setFormat("Data Breaches: %v")
        threat_layout.addWidget(self.breach_bar)
        
        self.browser_bar = QProgressBar()
        self.browser_bar.setTextVisible(True)
        self.browser_bar.setFormat("Browser Issues: %v")
        threat_layout.addWidget(self.browser_bar)
        
        layout.addWidget(threat_summary)
        
        # Recent threats section
        recent_frame = QFrame()
        recent_frame.setObjectName("cardWidget")
        recent_frame.setFrameShape(QFrame.StyledPanel)
        recent_frame.setFrameShadow(QFrame.Raised)
        recent_layout = QVBoxLayout(recent_frame)
        
        recent_header = QLabel("Recent Threats")
        recent_header.setObjectName("subheadingLabel")
        recent_layout.addWidget(recent_header)
        
        # Recent threats tree
        self.recent_tree = QTreeWidget()
        self.recent_tree.setHeaderLabels(["Description", "Type", "Level", "Source", "Detection Time"])
        self.recent_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.recent_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.recent_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.recent_tree.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.recent_tree.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.recent_tree.setAlternatingRowColors(True)
        self.recent_tree.itemDoubleClicked.connect(self.show_threat_details)
        recent_layout.addWidget(self.recent_tree)
        
        layout.addWidget(recent_frame)
        
        # Set stretch factors
        layout.setStretch(2, 1)  # Threat summary
        layout.setStretch(3, 2)  # Recent threats
        
    def create_status_card(self, title: str, status: str, icon_name: str, color: str) -> QFrame:
        """
        Create a status card widget.
        
        Args:
            title: Title of the card
            status: Initial status text
            icon_name: Name of the icon to use
            color: Color for the icon
            
        Returns:
            QFrame containing the status card
        """
        card = QFrame()
        card.setObjectName("cardWidget")
        card.setFrameShape(QFrame.StyledPanel)
        card.setFrameShadow(QFrame.Raised)
        card.setMinimumWidth(200)
        
        layout = QVBoxLayout(card)
        
        # Header with icon
        header = QHBoxLayout()
        
        title_label = QLabel(title)
        title_label.setObjectName("subheadingLabel")
        header.addWidget(title_label)
        
        # Create SVG icon
        icon_svg = get_icon_svg(icon_name, color)
        icon_file = os.path.join(CONFIG_DIR, f"dashboard_{icon_name}_temp.svg")
        with open(icon_file, "w") as f:
            f.write(icon_svg)
            
        icon_widget = QSvgWidget(icon_file)
        icon_widget.setFixedSize(24, 24)
        header.addWidget(icon_widget)
        
        layout.addLayout(header)
        
        # Status with animation
        status_layout = QHBoxLayout()
        
        status_label = QLabel("Status:")
        status_layout.addWidget(status_label)
        
        status_value = QLabel(status)
        status_value.setObjectName("infoLabel")
        status_layout.addWidget(status_value)
        
        # Add pulsing animation
        pulse = PulseAnimation()
        pulse.setFixedSize(12, 12)
        pulse.setColor(QColor(COLORS[CONFIG["ui_settings"]["theme"]]["scanner_inactive"]))
        status_layout.addWidget(pulse)
        
        status_layout.addStretch(1)
        
        layout.addLayout(status_layout)
        
        # Store references for updating
        card.status_label = status_value
        card.pulse_animation = pulse
        card.icon_widget = icon_widget
        card.icon_file = icon_file
        
        return card
        
    def update_dashboard(self):
        """Update the dashboard with current data."""
        # Update scanner card
        scan_stats = self.file_scanner.scan_stats
        if scan_stats["start_time"] and not scan_stats["end_time"]:
            # Scanner is active
            self.scanner_card.status_label.setText("Active")
            self.scanner_card.pulse_animation.setColor(QColor(COLORS[CONFIG["ui_settings"]["theme"]]["scanner_active"]))
            self.scanner_card.pulse_animation.start()
            
            # Update icon
            scanner_icon_svg = get_icon_svg("shield", COLORS[CONFIG["ui_settings"]["theme"]]["scanner_active"])
            with open(self.scanner_card.icon_file, "w") as f:
                f.write(scanner_icon_svg)
            self.scanner_card.icon_widget.load(self.scanner_card.icon_file)
        else:
            # Scanner is inactive
            self.scanner_card.status_label.setText("Inactive")
            self.scanner_card.pulse_animation.setColor(QColor(COLORS[CONFIG["ui_settings"]["theme"]]["scanner_inactive"]))
            self.scanner_card.pulse_animation.stop()
            
            # Update icon
            scanner_icon_svg = get_icon_svg("shield", COLORS[CONFIG["ui_settings"]["theme"]]["primary"])
            with open(self.scanner_card.icon_file, "w") as f:
                f.write(scanner_icon_svg)
            self.scanner_card.icon_widget.load(self.scanner_card.icon_file)
            
        # Update dark web monitor card
        monitor_stats = self.darkweb_monitor.monitoring_stats
        if monitor_stats["status"] == "active":
            # Monitor is active
            self.monitor_card.status_label.setText("Active")
            self.monitor_card.pulse_animation.setColor(QColor(COLORS[CONFIG["ui_settings"]["theme"]]["scanner_active"]))
            self.monitor_card.pulse_animation.start()
            
            # Update icon
            monitor_icon_svg = get_icon_svg("eye", COLORS[CONFIG["ui_settings"]["theme"]]["scanner_active"])
            with open(self.monitor_card.icon_file, "w") as f:
                f.write(monitor_icon_svg)
            self.monitor_card.icon_widget.load(self.monitor_card.icon_file)
        else:
            # Monitor is inactive
            self.monitor_card.status_label.setText("Inactive")
            self.monitor_card.pulse_animation.setColor(QColor(COLORS[CONFIG["ui_settings"]["theme"]]["scanner_inactive"]))
            self.monitor_card.pulse_animation.stop()
            
            # Update icon
            monitor_icon_svg = get_icon_svg("eye", COLORS[CONFIG["ui_settings"]["theme"]]["primary"])
            with open(self.monitor_card.icon_file, "w") as f:
                f.write(monitor_icon_svg)
            self.monitor_card.icon_widget.load(self.monitor_card.icon_file)
            
        # Update breach checker card
        checker_stats = self.breach_checker.checker_stats
        if checker_stats["status"] == "active":
            # Checker is active
            self.breach_card.status_label.setText("Active")
            self.breach_card.pulse_animation.setColor(QColor(COLORS[CONFIG["ui_settings"]["theme"]]["scanner_active"]))
            self.breach_card.pulse_animation.start()
            
            # Update icon
            breach_icon_svg = get_icon_svg("search", COLORS[CONFIG["ui_settings"]["theme"]]["scanner_active"])
            with open(self.breach_card.icon_file, "w") as f:
                f.write(breach_icon_svg)
            self.breach_card.icon_widget.load(self.breach_card.icon_file)
        else:
            # Checker is inactive
            self.breach_card.status_label.setText("Inactive")
            self.breach_card.pulse_animation.setColor(QColor(COLORS[CONFIG["ui_settings"]["theme"]]["scanner_inactive"]))
            self.breach_card.pulse_animation.stop()
            
            # Update icon
            breach_icon_svg = get_icon_svg("search", COLORS[CONFIG["ui_settings"]["theme"]]["primary"])
            with open(self.breach_card.icon_file, "w") as f:
                f.write(breach_icon_svg)
            self.breach_card.icon_widget.load(self.breach_card.icon_file)
            
        # Browser analyzer doesn't have a persistent state, so we'll just keep it at idle
        
        # Update threat counts
        threats_by_severity = self.threat_db.get_by_severity()
        
        critical_count = len(threats_by_severity[ThreatLevel.CRITICAL])
        high_count = len(threats_by_severity[ThreatLevel.HIGH])
        medium_count = len(threats_by_severity[ThreatLevel.MEDIUM])
        low_count = len(threats_by_severity[ThreatLevel.LOW])
        total_count = len(self.threat_db.threats)
        
        self.critical_count.setText(str(critical_count))
        self.high_count.setText(str(high_count))
        self.medium_count.setText(str(medium_count))
        self.low_count.setText(str(low_count))
        self.total_count.setText(str(total_count))
        
        # Animate radar if we have threats
        if total_count > 0:
            self.radar_widget.start_animation()
        else:
            self.radar_widget.stop_animation()
        
        # Calculate threat type counts
        file_threats = len([t for t in self.threat_db.threats if isinstance(t, FileThreat)])
        darkweb_threats = len([t for t in self.threat_db.threats if isinstance(t, DarkWebThreat)])
        breach_threats = len([t for t in self.threat_db.threats if isinstance(t, DataBreachThreat)])
        browser_threats = len([t for t in self.threat_db.threats if isinstance(t, BrowserThreat)])
        
        # Update progress bars
        max_value = max(file_threats, darkweb_threats, breach_threats, browser_threats, 1)
        
        self.file_bar.setMaximum(max_value)
        self.file_bar.setValue(file_threats)
        
        self.darkweb_bar.setMaximum(max_value)
        self.darkweb_bar.setValue(darkweb_threats)
        
        self.breach_bar.setMaximum(max_value)
        self.breach_bar.setValue(breach_threats)
        
        self.browser_bar.setMaximum(max_value)
        self.browser_bar.setValue(browser_threats)
        
        # Update recent threats tree
        self.update_recent_threats()
        
    def update_recent_threats(self):
        """Update the recent threats tree."""
        self.recent_tree.clear()
        
        # Get all threats
        all_threats = self.threat_db.threats.copy()
        
        # Sort by timestamp, newest first
        all_threats.sort(key=lambda t: t.timestamp, reverse=True)
        
        # Take only the 10 most recent
        recent_threats = all_threats[:10]
        
        # Add to tree
        for threat in recent_threats:
            # Determine source based on threat type
            source = "Unknown"
            if isinstance(threat, FileThreat):
                source = "File Scanner"
            elif isinstance(threat, DarkWebThreat):
                source = "Dark Web Monitor"
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
            
            self.recent_tree.addTopLevelItem(item)
            
    def show_threat_details(self, item, column):
        """Signal to show detailed information about a threat."""
        # This is just a pass-through to the main window
        # The actual implementation is in the main window
        pass
