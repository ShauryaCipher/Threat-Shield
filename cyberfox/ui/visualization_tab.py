"""
Visualization tab for the CyberFox application.

This module provides a tab for interactive threat risk visualization
with animated threat levels and risk mapping.
"""

import math
import random
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QSplitter,
    QPushButton, QComboBox, QCheckBox, QTabWidget, QScrollArea,
    QTextEdit, QApplication
)
from PyQt5.QtGui import QColor, QPaintEvent, QMouseEvent, QResizeEvent
from PyQt5.QtCore import Qt, QTimer, QSize

from cyberfox.core.threats import (
    Threat, ThreatLevel, ThreatType, ThreatDatabase,
    FileThreat, DarkWebThreat, DataBreachThreat, BrowserThreat
)
from cyberfox.core.ml_threat_analyzer import MLThreatAnalyzer
from cyberfox.ui.risk_visualizer import (
    ThreatRiskMeter, ThreatMapVisualizer, ThreatTrendGraph
)
from cyberfox.ui.style import COLORS, Theme
from cyberfox.config import CONFIG


class VisualizationTab(QWidget):
    """
    Tab for interactive threat risk visualization and threat mapping.
    """
    
    def __init__(self, threat_db: ThreatDatabase, parent=None):
        """
        Initialize the visualization tab.
        
        Args:
            threat_db: The threat database instance
            parent: Parent widget
        """
        super().__init__(parent)
        self.threat_db = threat_db
        
        # Initialize ML threat analyzer
        self.ml_analyzer = MLThreatAnalyzer(threat_db)
        
        # Will hold our last update time
        self._last_update_time = None
        
        # Track historical threat counts for trend graph
        self._history_timestamps = []
        self._history_critical = []
        self._history_high = []
        self._history_medium = []
        self._history_low = []
        
        # Set up UI
        self.setup_ui()
        
        # Start update timer
        self._update_timer = QTimer(self)
        self._update_timer.timeout.connect(self.update_visualizations)
        self._update_timer.start(5000)  # Update every 5 seconds
        
        # Initial update
        self.update_visualizations()
    
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("Threat Risk Visualization")
        header.setObjectName("headingLabel")
        layout.addWidget(header)
        
        # Top section - Risk Meter and Controls
        top_frame = QFrame()
        top_frame.setObjectName("cardWidget")
        top_frame.setFrameShape(QFrame.StyledPanel)
        top_frame.setFrameShadow(QFrame.Raised)
        top_layout = QHBoxLayout(top_frame)
        
        # Risk meter takes 1/3 of the width
        self.risk_meter = ThreatRiskMeter()
        self.risk_meter.setMinimumHeight(200)
        top_layout.addWidget(self.risk_meter, 1)
        
        # Controls section takes 2/3 of width
        controls_frame = QFrame()
        controls_layout = QVBoxLayout(controls_frame)
        
        # Risk breakdown header
        breakdown_header = QLabel("Threat Risk Breakdown")
        breakdown_header.setObjectName("subheadingLabel")
        controls_layout.addWidget(breakdown_header)
        
        # Risk statistics
        stats_layout = QHBoxLayout()
        
        # Critical risks
        critical_frame = self._create_risk_stat_card(
            "Critical", 
            "0", 
            QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_critical'])
        )
        stats_layout.addWidget(critical_frame)
        
        # High risks
        high_frame = self._create_risk_stat_card(
            "High", 
            "0", 
            QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_high'])
        )
        stats_layout.addWidget(high_frame)
        
        # Medium risks
        medium_frame = self._create_risk_stat_card(
            "Medium", 
            "0", 
            QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_medium'])
        )
        stats_layout.addWidget(medium_frame)
        
        # Low risks
        low_frame = self._create_risk_stat_card(
            "Low", 
            "0", 
            QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_low'])
        )
        stats_layout.addWidget(low_frame)
        
        controls_layout.addLayout(stats_layout)
        
        # Add visualization controls
        controls_header = QLabel("Visualization Controls")
        controls_header.setObjectName("subheadingLabel")
        controls_layout.addWidget(controls_header)
        
        # Filter options
        filter_layout = QHBoxLayout()
        
        # Time range selector
        filter_layout.addWidget(QLabel("Time Range:"))
        self.time_range_combo = QComboBox()
        self.time_range_combo.addItems([
            "Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"
        ])
        self.time_range_combo.setCurrentIndex(1)  # Default to Last 24 Hours
        self.time_range_combo.currentIndexChanged.connect(self.update_visualizations)
        filter_layout.addWidget(self.time_range_combo)
        
        filter_layout.addSpacing(20)
        
        # Threat type filter checkboxes
        filter_layout.addWidget(QLabel("Show:"))
        
        self.show_file_threats = QCheckBox("File Threats")
        self.show_file_threats.setChecked(True)
        self.show_file_threats.stateChanged.connect(self.update_visualizations)
        filter_layout.addWidget(self.show_file_threats)
        
        self.show_darkweb_threats = QCheckBox("Dark Web")
        self.show_darkweb_threats.setChecked(True)
        self.show_darkweb_threats.stateChanged.connect(self.update_visualizations)
        filter_layout.addWidget(self.show_darkweb_threats)
        
        self.show_breach_threats = QCheckBox("Data Breaches")
        self.show_breach_threats.setChecked(True)
        self.show_breach_threats.stateChanged.connect(self.update_visualizations)
        filter_layout.addWidget(self.show_breach_threats)
        
        self.show_browser_threats = QCheckBox("Browser Issues")
        self.show_browser_threats.setChecked(True)
        self.show_browser_threats.stateChanged.connect(self.update_visualizations)
        filter_layout.addWidget(self.show_browser_threats)
        
        filter_layout.addStretch(1)
        
        controls_layout.addLayout(filter_layout)
        
        # Add Refresh button
        refresh_layout = QHBoxLayout()
        refresh_layout.addStretch(1)
        
        refresh_button = QPushButton("Refresh Visualizations")
        refresh_button.clicked.connect(self.update_visualizations)
        refresh_button.setMinimumWidth(200)
        refresh_layout.addWidget(refresh_button)
        
        controls_layout.addLayout(refresh_layout)
        
        # Add controls to top layout
        top_layout.addWidget(controls_frame, 2)
        
        layout.addWidget(top_frame)
        
        # Middle section - Split between Threat Map and Trend Graph
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setHandleWidth(1)
        self.splitter.setChildrenCollapsible(False)
        
        # Threat map on left
        map_frame = QFrame()
        map_frame.setObjectName("cardWidget")
        map_frame.setFrameShape(QFrame.StyledPanel)
        map_frame.setFrameShadow(QFrame.Raised)
        map_layout = QVBoxLayout(map_frame)
        
        map_header = QLabel("Threat Relationship Map")
        map_header.setObjectName("subheadingLabel")
        map_layout.addWidget(map_header)
        
        self.threat_map = ThreatMapVisualizer(self.threat_db)
        self.threat_map.setMinimumHeight(300)
        map_layout.addWidget(self.threat_map)
        
        self.splitter.addWidget(map_frame)
        
        # Trend graph on right
        trend_frame = QFrame()
        trend_frame.setObjectName("cardWidget")
        trend_frame.setFrameShape(QFrame.StyledPanel)
        trend_frame.setFrameShadow(QFrame.Raised)
        trend_layout = QVBoxLayout(trend_frame)
        
        trend_header = QLabel("Threat History Trend")
        trend_header.setObjectName("subheadingLabel")
        trend_layout.addWidget(trend_header)
        
        self.trend_graph = ThreatTrendGraph()
        self.trend_graph.setMinimumHeight(300)
        trend_layout.addWidget(self.trend_graph)
        
        self.splitter.addWidget(trend_frame)
        
        # Set initial splitter sizes (50/50 split)
        self.splitter.setSizes([500, 500])
        
        layout.addWidget(self.splitter)
        
        # Bottom section - ML Analysis Insights
        ml_frame = QFrame()
        ml_frame.setObjectName("cardWidget")
        ml_frame.setFrameShape(QFrame.StyledPanel)
        ml_frame.setFrameShadow(QFrame.Raised)
        ml_layout = QVBoxLayout(ml_frame)
        
        ml_header = QLabel("Machine Learning Insights")
        ml_header.setObjectName("subheadingLabel")
        ml_layout.addWidget(ml_header)
        
        # Insights Text Area
        self.ml_insights_text = QTextEdit()
        self.ml_insights_text.setReadOnly(True)
        self.ml_insights_text.setMinimumHeight(150)
        self.ml_insights_text.setStyleSheet("background-color: rgba(0, 0, 0, 0.1); padding: 10px;")
        ml_layout.addWidget(self.ml_insights_text)
        
        # Controls row
        ml_controls_layout = QHBoxLayout()
        
        # Analysis type
        ml_controls_layout.addWidget(QLabel("Analysis:"))
        self.analysis_type_combo = QComboBox()
        self.analysis_type_combo.addItems([
            "Threat Patterns", "Anomaly Detection", "Future Projection"
        ])
        self.analysis_type_combo.currentIndexChanged.connect(self._update_ml_insights)
        ml_controls_layout.addWidget(self.analysis_type_combo)
        
        ml_controls_layout.addSpacing(20)
        
        # Train model button
        self.train_model_button = QPushButton("Train ML Models")
        self.train_model_button.clicked.connect(self._train_ml_models)
        ml_controls_layout.addWidget(self.train_model_button)
        
        # Add analyze button
        self.analyze_button = QPushButton("Run Analysis")
        self.analyze_button.clicked.connect(self._update_ml_insights)
        ml_controls_layout.addWidget(self.analyze_button)
        
        ml_controls_layout.addStretch(1)
        
        ml_layout.addLayout(ml_controls_layout)
        
        layout.addWidget(ml_frame)
        
        # Store references to the risk stat cards for updating
        self.critical_count = critical_frame.findChild(QLabel, "critical_count")
        self.high_count = high_frame.findChild(QLabel, "high_count")
        self.medium_count = medium_frame.findChild(QLabel, "medium_count")
        self.low_count = low_frame.findChild(QLabel, "low_count")
    
    def _create_risk_stat_card(self, title: str, count: str, color: QColor) -> QFrame:
        """
        Create a risk statistic card.
        
        Args:
            title: Title text
            count: Initial count text
            color: Color for the indicator
            
        Returns:
            QFrame containing the card
        """
        frame = QFrame()
        frame.setObjectName("innerCardWidget")
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setFrameShadow(QFrame.Raised)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)
        
        # Color indicator at top
        indicator = QFrame()
        indicator.setMinimumHeight(5)
        indicator.setMaximumHeight(5)
        indicator.setStyleSheet(f"background-color: {color.name()};")
        layout.addWidget(indicator)
        
        # Title
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Count
        count_label = QLabel(count)
        count_label.setObjectName(title.lower() + "_count")  # For finding later
        count_label.setAlignment(Qt.AlignCenter)
        font = count_label.font()
        font.setPointSize(18)
        font.setBold(True)
        count_label.setFont(font)
        count_label.setStyleSheet(f"color: {color.name()};")
        layout.addWidget(count_label)
        
        return frame
    
    def update_visualizations(self):
        """Update all visualizations with current data."""
        # Get current timestamp
        current_time = datetime.now()
        
        # Update last update time if this is the first update
        if self._last_update_time is None:
            self._last_update_time = current_time
            
            # Initialize history with starting point
            self._add_history_point(current_time, [0, 0, 0, 0])
        
        # Apply time filter to threats
        filtered_threats = self._get_filtered_threats()
        
        # Count threats by severity
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for threat in filtered_threats:
            if threat.level == ThreatLevel.CRITICAL:
                critical_count += 1
            elif threat.level == ThreatLevel.HIGH:
                high_count += 1
            elif threat.level == ThreatLevel.MEDIUM:
                medium_count += 1
            elif threat.level == ThreatLevel.LOW:
                low_count += 1
        
        total_count = critical_count + high_count + medium_count + low_count
        
        # Update stat cards
        self.critical_count.setText(str(critical_count))
        self.high_count.setText(str(high_count))
        self.medium_count.setText(str(medium_count))
        self.low_count.setText(str(low_count))
        
        # Update risk meter
        risk_level = self._calculate_risk_level(critical_count, high_count, medium_count, low_count)
        self.risk_meter.set_risk_level(risk_level)
        
        # Update threat map with filtered threats
        self.threat_map.threat_db.threats = filtered_threats  # Update with filtered threats
        self.threat_map.update_threats()
        
        # Add new history point (but not too frequently - at most once per minute)
        if (current_time - self._last_update_time).total_seconds() >= 60:
            self._add_history_point(current_time, [critical_count, high_count, medium_count, low_count])
            self._last_update_time = current_time
        
        # Update trend graph
        self._update_trend_graph()
    
    def _get_filtered_threats(self) -> List[Threat]:
        """
        Get threats filtered by time range and type.
        
        Returns:
            List of filtered threats
        """
        # Get all threats
        all_threats = self.threat_db.threats.copy()
        
        # Filter by time
        time_range = self.time_range_combo.currentText()
        since = None
        
        if time_range == "Last Hour":
            since = datetime.now() - timedelta(hours=1)
        elif time_range == "Last 24 Hours":
            since = datetime.now() - timedelta(days=1)
        elif time_range == "Last 7 Days":
            since = datetime.now() - timedelta(days=7)
        elif time_range == "Last 30 Days":
            since = datetime.now() - timedelta(days=30)
        
        if since:
            all_threats = [t for t in all_threats if t.timestamp >= since]
        
        # Filter by type
        filtered_threats = []
        
        for threat in all_threats:
            if isinstance(threat, FileThreat) and self.show_file_threats.isChecked():
                filtered_threats.append(threat)
            elif isinstance(threat, DarkWebThreat) and self.show_darkweb_threats.isChecked():
                filtered_threats.append(threat)
            elif isinstance(threat, DataBreachThreat) and self.show_breach_threats.isChecked():
                filtered_threats.append(threat)
            elif isinstance(threat, BrowserThreat) and self.show_browser_threats.isChecked():
                filtered_threats.append(threat)
        
        return filtered_threats
    
    def _calculate_risk_level(self, critical: int, high: int, medium: int, low: int) -> float:
        """
        Calculate overall risk level based on threat counts.
        
        Args:
            critical: Number of critical threats
            high: Number of high threats
            medium: Number of medium threats
            low: Number of low threats
            
        Returns:
            Risk level as a float from 0.0 to 1.0
        """
        # If no threats, risk is zero
        total_threats = critical + high + medium + low
        if total_threats == 0:
            return 0.0
        
        # Calculate weighted score
        # Weights: Critical=1.0, High=0.7, Medium=0.4, Low=0.1
        weighted_score = (
            critical * 1.0 + 
            high * 0.7 + 
            medium * 0.4 + 
            low * 0.1
        )
        
        # Normalize to 0.0 - 1.0 using sigmoid-like function
        # This makes it harder to reach the full 1.0 (maximum risk)
        # but still gives a reasonable risk value for small numbers of threats
        normalized_risk = min(1.0, weighted_score / (5.0 + weighted_score))
        
        return normalized_risk
    
    def _add_history_point(self, timestamp: datetime, counts: List[int]):
        """
        Add a point to the threat history.
        
        Args:
            timestamp: The time of the data point
            counts: List of [critical, high, medium, low] counts
        """
        # Limit history size (keep last 100 points max)
        if len(self._history_timestamps) >= 100:
            self._history_timestamps.pop(0)
            self._history_critical.pop(0)
            self._history_high.pop(0)
            self._history_medium.pop(0)
            self._history_low.pop(0)
        
        self._history_timestamps.append(timestamp)
        self._history_critical.append(counts[0])
        self._history_high.append(counts[1])
        self._history_medium.append(counts[2])
        self._history_low.append(counts[3])
    
    def _update_trend_graph(self):
        """Update the trend graph with current history data."""
        if not self._history_timestamps:
            return
            
        # Get appropriate time range based on filter
        time_range = self.time_range_combo.currentText()
        since = None
        
        if time_range == "Last Hour":
            since = datetime.now() - timedelta(hours=1)
        elif time_range == "Last 24 Hours":
            since = datetime.now() - timedelta(days=1)
        elif time_range == "Last 7 Days":
            since = datetime.now() - timedelta(days=7)
        elif time_range == "Last 30 Days":
            since = datetime.now() - timedelta(days=30)
        
        # Filter history by time range
        timestamps = self._history_timestamps
        critical = self._history_critical
        high = self._history_high
        medium = self._history_medium
        low = self._history_low
        
        if since:
            filtered_indices = [i for i, ts in enumerate(timestamps) if ts >= since]
            
            if filtered_indices:
                timestamps = [timestamps[i] for i in filtered_indices]
                critical = [critical[i] for i in filtered_indices]
                high = [high[i] for i in filtered_indices]
                medium = [medium[i] for i in filtered_indices]
                low = [low[i] for i in filtered_indices]
            else:
                # No data points in range, use at least one point (current)
                current_time = datetime.now()
                current_counts = self._get_current_counts()
                
                timestamps = [current_time]
                critical = [current_counts[0]]
                high = [current_counts[1]]
                medium = [current_counts[2]]
                low = [current_counts[3]]
        
        # Add current point if not in history yet
        if timestamps and (datetime.now() - timestamps[-1]).total_seconds() > 10:
            current_time = datetime.now()
            current_counts = self._get_current_counts()
            
            timestamps.append(current_time)
            critical.append(current_counts[0])
            high.append(current_counts[1])
            medium.append(current_counts[2])
            low.append(current_counts[3])
        
        # Ensure we have at least 2 points for trend visualization
        if len(timestamps) == 1:
            # Duplicate the point slightly offset
            timestamps.append(timestamps[0] + timedelta(minutes=1))
            critical.append(critical[0])
            high.append(high[0])
            medium.append(medium[0])
            low.append(low[0])
        
        # Update the trend graph
        self.trend_graph.set_data(timestamps, critical, high, medium, low)
    
    def _get_current_counts(self) -> List[int]:
        """
        Get current threat counts by severity.
        
        Returns:
            List of [critical, high, medium, low] counts
        """
        filtered_threats = self._get_filtered_threats()
        
        critical_count = sum(1 for t in filtered_threats if t.level == ThreatLevel.CRITICAL)
        high_count = sum(1 for t in filtered_threats if t.level == ThreatLevel.HIGH)
        medium_count = sum(1 for t in filtered_threats if t.level == ThreatLevel.MEDIUM)
        low_count = sum(1 for t in filtered_threats if t.level == ThreatLevel.LOW)
        
        return [critical_count, high_count, medium_count, low_count]
    
    def _train_ml_models(self):
        """Train machine learning models with current threat data."""
        # Get a reference to the threat data from the database
        filtered_threats = self._get_filtered_threats()
        
        if len(filtered_threats) < 10:
            self.ml_insights_text.setHtml(
                "<p style='color: #FFA500;'><b>Warning:</b> Not enough threat data for training (minimum 10 required).</p>"
                "<p>Detection and classification of threats requires sufficient historical data. "
                "Continue scanning your system to gather more threat intelligence.</p>"
            )
            return
        
        # Update UI to show training state
        self.ml_insights_text.setHtml("<p><b>Training models...</b> Please wait.</p>")
        QApplication.processEvents()  # Force UI update
        
        # Train the models
        success = self.ml_analyzer.train_models()
        
        if success:
            self.ml_insights_text.setHtml(
                "<p style='color: #4CAF50;'><b>Success:</b> Machine learning models trained successfully!</p>"
                "<p>Models have been updated with the latest threat data. Run analysis to see insights.</p>"
            )
        else:
            self.ml_insights_text.setHtml(
                "<p style='color: #F44336;'><b>Error:</b> Training failed.</p>"
                "<p>Please check log files for more information or try again with more threat data.</p>"
            )
    
    def _update_ml_insights(self):
        """Update the machine learning insights panel based on selected analysis type."""
        # Get all threats or filtered threats based on UI settings
        filtered_threats = self._get_filtered_threats()
        
        if len(filtered_threats) < 5:
            self.ml_insights_text.setHtml(
                "<p style='color: #FFA500;'><b>Warning:</b> Not enough threat data for meaningful analysis.</p>"
                "<p>Machine learning analysis requires at least 5 threat samples. "
                "Continue scanning your system to gather more threat intelligence.</p>"
            )
            return
        
        # Update UI to show processing state
        self.ml_insights_text.setHtml("<p><b>Analyzing threats...</b> Please wait.</p>")
        QApplication.processEvents()  # Force UI update
        
        # Get selected analysis type
        analysis_type = self.analysis_type_combo.currentText()
        
        if analysis_type == "Threat Patterns":
            self._show_threat_patterns()
        elif analysis_type == "Anomaly Detection":
            self._show_anomaly_detection()
        elif analysis_type == "Future Projection":
            self._show_future_projection()
    
    def _show_threat_patterns(self):
        """Show threat patterns analysis results."""
        try:
            # Get analysis results
            analysis = self.ml_analyzer.analyze_threat_patterns()
            
            if "error" in analysis:
                self.ml_insights_text.setHtml(f"<p style='color: #F44336;'><b>Error:</b> {analysis['error']}</p>")
                return
            
            # Build HTML report
            html = "<style>table {border-collapse: collapse; width: 100%;} th, td {padding: 4px 8px; text-align: left;} "
            html += "th {background-color: rgba(0,0,0,0.1);} tr:nth-child(even) {background-color: rgba(0,0,0,0.05);}</style>"
            html += "<h3>Threat Pattern Analysis</h3>"
            
            # Severity distribution
            if "severity_distribution" in analysis:
                html += "<h4>Threat Severity Distribution</h4>"
                html += "<table><tr><th>Severity</th><th>Count</th></tr>"
                for level, count in analysis["severity_distribution"].items():
                    color = "#4CAF50" if level == "low" else "#FFC107" if level == "medium" else "#FF9800" if level == "high" else "#F44336"
                    html += f"<tr><td><span style='color: {color};'>{level.capitalize()}</span></td><td>{count}</td></tr>"
                html += "</table>"
            
            # Type distribution
            if "type_distribution" in analysis:
                html += "<h4>Threat Type Distribution</h4>"
                html += "<table><tr><th>Type</th><th>Count</th></tr>"
                for threat_type, count in analysis["type_distribution"].items():
                    html += f"<tr><td>{threat_type.replace('_', ' ').capitalize()}</td><td>{count}</td></tr>"
                html += "</table>"
            
            # Clusters
            if "clusters" in analysis and analysis["clusters"]:
                html += "<h4>Threat Clusters</h4>"
                html += "<p>Similar threats have been grouped together based on their characteristics:</p>"
                html += "<table><tr><th>Group</th><th>Size</th><th>Common Type</th><th>Avg. Severity</th><th>Recent Example</th></tr>"
                
                for cluster_id, cluster_info in analysis["clusters"].items():
                    html += f"<tr>"
                    html += f"<td>Group {cluster_id + 1}</td>"
                    html += f"<td>{cluster_info['size']}</td>"
                    html += f"<td>{cluster_info['common_type'].replace('_', ' ').capitalize() if cluster_info['common_type'] else 'Mixed'}</td>"
                    
                    severity = cluster_info['avg_severity']
                    color = "#4CAF50" if severity == "low" else "#FFC107" if severity == "medium" else "#FF9800" if severity == "high" else "#F44336"
                    html += f"<td><span style='color: {color};'>{severity.capitalize()}</span></td>"
                    
                    recent = cluster_info['recent_threat']
                    if recent:
                        # Truncate long descriptions
                        if len(recent) > 60:
                            recent = recent[:57] + "..."
                        html += f"<td>{recent}</td>"
                    else:
                        html += "<td>N/A</td>"
                    
                    html += "</tr>"
                html += "</table>"
            
            # Weekly trend
            if "weekly_trend" in analysis and analysis["weekly_trend"]:
                html += "<h4>Weekly Threat Trend</h4>"
                html += "<table><tr><th>Week</th><th>Count</th></tr>"
                
                # Sort by week
                weeks = sorted(analysis["weekly_trend"].keys())
                for week in weeks[-5:]:  # Show last 5 weeks
                    count = analysis["weekly_trend"][week]
                    year, week_num = week.split("-")
                    html += f"<tr><td>Week {week_num}, {year}</td><td>{count}</td></tr>"
                html += "</table>"
            
            self.ml_insights_text.setHtml(html)
            
        except Exception as e:
            self.ml_insights_text.setHtml(f"<p style='color: #F44336;'><b>Error:</b> {str(e)}</p>")
    
    def _show_anomaly_detection(self):
        """Show anomaly detection results."""
        try:
            # Get filtered threats
            filtered_threats = self._get_filtered_threats()
            
            if len(filtered_threats) < 10:
                self.ml_insights_text.setHtml(
                    "<p style='color: #FFA500;'><b>Warning:</b> Not enough threat data for anomaly detection.</p>"
                    "<p>At least 10 threats are required for reliable anomaly detection. "
                    "Continue scanning your system to gather more threat intelligence.</p>"
                )
                return
            
            # Detect anomalies
            anomalies = self.ml_analyzer.detect_anomalies(filtered_threats)
            
            # Get the anomalous threats
            anomalous_threats = [
                filtered_threats[i] for i, is_anomaly in enumerate(anomalies) if is_anomaly
            ]
            
            # Build HTML report
            html = "<h3>Anomaly Detection Results</h3>"
            
            if not any(anomalies):
                html += "<p style='color: #4CAF50;'><b>No anomalies detected!</b></p>"
                html += "<p>All threats follow expected patterns based on historical data. "
                html += "Continue monitoring for new or unusual threat patterns.</p>"
            else:
                html += f"<p style='color: #FFA500;'><b>{len(anomalous_threats)} anomalous threats detected</b> "
                html += f"out of {len(filtered_threats)} total threats.</p>"
                html += "<p>These threats deviate significantly from normal patterns and may require special attention:</p>"
                
                html += "<style>table {border-collapse: collapse; width: 100%;} th, td {padding: 4px 8px; text-align: left;} "
                html += "th {background-color: rgba(0,0,0,0.1);} tr:nth-child(even) {background-color: rgba(0,0,0,0.05);}</style>"
                
                html += "<table><tr><th>Type</th><th>Severity</th><th>Description</th><th>Date/Time</th></tr>"
                
                for threat in anomalous_threats:
                    severity = threat.level.value
                    color = "#4CAF50" if severity == "low" else "#FFC107" if severity == "medium" else "#FF9800" if severity == "high" else "#F44336"
                    
                    # Truncate long descriptions
                    desc = threat.description
                    if len(desc) > 60:
                        desc = desc[:57] + "..."
                    
                    timestamp = threat.timestamp.strftime("%Y-%m-%d %H:%M") if threat.timestamp else "Unknown"
                    
                    html += f"<tr>"
                    html += f"<td>{threat.type.value.replace('_', ' ').capitalize()}</td>"
                    html += f"<td><span style='color: {color};'>{severity.capitalize()}</span></td>"
                    html += f"<td>{desc}</td>"
                    html += f"<td>{timestamp}</td>"
                    html += f"</tr>"
                
                html += "</table>"
                
                html += "<p><b>Why these are anomalies:</b></p>"
                html += "<ul>"
                html += "<li>Unusual combinations of severity and threat type</li>"
                html += "<li>Uncommon characteristics compared to historical threats</li>"
                html += "<li>Rare patterns of appearance or system impact</li>"
                html += "</ul>"
            
            self.ml_insights_text.setHtml(html)
            
        except Exception as e:
            self.ml_insights_text.setHtml(f"<p style='color: #F44336;'><b>Error:</b> {str(e)}</p>")
    
    def _show_future_projection(self):
        """Show future threat projection results."""
        try:
            # Get future predictions
            predictions = self.ml_analyzer.predict_future_threats(days_ahead=7)
            
            if "error" in predictions:
                self.ml_insights_text.setHtml(f"<p style='color: #FFA500;'><b>Warning:</b> {predictions['error']}</p>")
                return
            
            # Build HTML report
            html = "<style>table {border-collapse: collapse; width: 100%;} th, td {padding: 4px 8px; text-align: left;} "
            html += "th {background-color: rgba(0,0,0,0.1);} tr:nth-child(even) {background-color: rgba(0,0,0,0.05);}</style>"
            html += "<h3>Future Threat Projection (Next 7 Days)</h3>"
            
            # Overall risk trend
            if "risk_trend" in predictions:
                trend = predictions["risk_trend"]
                icon = "↗" if trend == "increasing" else "↘" if trend == "decreasing" else "→"
                color = "#F44336" if trend == "increasing" else "#4CAF50" if trend == "decreasing" else "#FFC107"
                
                html += f"<p><b>Overall risk trend:</b> <span style='color: {color};'>{trend.capitalize()} {icon}</span></p>"
            
            # Most likely threat type
            if "most_likely_threat" in predictions:
                most_likely = predictions["most_likely_threat"].replace("_", " ").capitalize()
                html += f"<p><b>Most likely threat type:</b> {most_likely}</p>"
            
            # Forecast table
            if "forecast" in predictions and predictions["forecast"]:
                html += "<h4>Daily Forecast</h4>"
                html += "<table><tr><th>Date</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr>"
                
                for day in predictions["forecast"]:
                    date = day["date"]
                    counts = day["prediction"]
                    
                    critical = round(counts["critical"])
                    high = round(counts["high"])
                    medium = round(counts["medium"])
                    low = round(counts["low"])
                    total = critical + high + medium + low
                    
                    html += f"<tr>"
                    html += f"<td>{date}</td>"
                    html += f"<td><span style='color: #F44336;'>{critical}</span></td>"
                    html += f"<td><span style='color: #FF9800;'>{high}</span></td>"
                    html += f"<td><span style='color: #FFC107;'>{medium}</span></td>"
                    html += f"<td><span style='color: #4CAF50;'>{low}</span></td>"
                    html += f"<td>{total}</td>"
                    html += f"</tr>"
                
                html += "</table>"
            
            # Type trends
            if "trend" in predictions:
                html += "<h4>Threat Type Trends</h4>"
                html += "<table><tr><th>Type</th><th>Trend</th></tr>"
                
                type_trends = {
                    "file": predictions["trend"].get("file", 0),
                    "darkweb": predictions["trend"].get("darkweb", 0),
                    "databreach": predictions["trend"].get("databreach", 0),
                    "browser": predictions["trend"].get("browser", 0)
                }
                
                for threat_type, trend_val in type_trends.items():
                    icon = "↗" if trend_val > 5 else "↘" if trend_val < -5 else "→"
                    color = "#F44336" if trend_val > 5 else "#4CAF50" if trend_val < -5 else "#FFC107"
                    trend_text = f"{trend_val:+.1f}% {icon}"
                    
                    html += f"<tr>"
                    html += f"<td>{threat_type.replace('_', ' ').capitalize()}</td>"
                    html += f"<td><span style='color: {color};'>{trend_text}</span></td>"
                    html += f"</tr>"
                
                html += "</table>"
            
            # Recommendations based on predictions
            html += "<h4>Recommendations</h4>"
            html += "<ul>"
            
            # Check if any critical threats are expected
            has_critical = any(day["prediction"]["critical"] >= 1 for day in predictions["forecast"])
            if has_critical:
                html += "<li><b>Critical threats expected:</b> Schedule a thorough system scan and update all security measures.</li>"
            
            # Check for increasing risk trend
            if predictions.get("risk_trend") == "increasing":
                html += "<li><b>Rising threat level:</b> Increase monitoring frequency and verify security controls.</li>"
            
            # Check which threat type is increasing most
            most_increasing = max(predictions["trend"].items(), key=lambda x: x[1])[0]
            if most_increasing == "file":
                html += "<li><b>Increasing file threats:</b> Monitor suspicious downloads and run more frequent file scans.</li>"
            elif most_increasing == "darkweb":
                html += "<li><b>Increasing dark web mentions:</b> Consider changing passwords and enhancing privacy measures.</li>"
            elif most_increasing == "databreach":
                html += "<li><b>Increasing data breaches:</b> Monitor your accounts and implement additional authentication.</li>"
            elif most_increasing == "browser":
                html += "<li><b>Increasing browser threats:</b> Review privacy settings and consider clearing cookies regularly.</li>"
            
            html += "</ul>"
            
            self.ml_insights_text.setHtml(html)
            
        except Exception as e:
            self.ml_insights_text.setHtml(f"<p style='color: #F44336;'><b>Error:</b> {str(e)}</p>")
    
    def sizeHint(self) -> QSize:
        """Suggest a size for the widget."""
        return QSize(1000, 800)