"""
Interactive threat risk visualization with animated threat levels.

This module provides visualization widgets for threat risk levels with
animated indicators and interactive elements that represent the security 
posture of the system in a graphical way.
"""

import math
import random
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, 
    QGraphicsView, QGraphicsScene, QGraphicsItem, QGraphicsEllipseItem,
    QGraphicsPathItem, QGraphicsTextItem, QSizePolicy, QToolTip
)
from PyQt5.QtGui import (
    QPainter, QColor, QPen, QBrush, QPainterPath, QFont, QRadialGradient,
    QLinearGradient, QPaintEvent, QMouseEvent, QConicalGradient, QCursor
)
from PyQt5.QtCore import (
    Qt, QRectF, QPointF, QTimer, QPropertyAnimation, QEasingCurve, 
    pyqtProperty, QSize, QPoint
)
from PyQt5.QtSvg import QSvgRenderer

from cyberfox.core.threats import Threat, ThreatLevel, ThreatType, ThreatDatabase
from cyberfox.ui.style import COLORS, Theme
from cyberfox.config import CONFIG


class ThreatRiskMeter(QWidget):
    """
    A widget that visualizes the overall risk level as a gauge meter
    with animation and gradient colors.
    """
    
    def __init__(self, parent=None):
        """Initialize the risk meter widget."""
        super().__init__(parent)
        self.setMinimumSize(300, 200)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        self._current_risk = 0.0  # 0.0 - 1.0 scale
        self._target_risk = 0.0
        self._animation_timer = QTimer(self)
        self._animation_timer.timeout.connect(self._update_animation)
        self._animation_timer.start(30)  # 30ms for ~30fps animation
        
        # Animation parameters
        self._animation_speed = 0.02  # How fast to move towards target
        self._needle_angle = 0.0
        self._needle_target_angle = 0.0
        self._needle_oscillation = 0.0
        self._needle_oscillation_speed = 0.1
        
        # Create color gradient for risk levels
        self._colors = [
            QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_low']),
            QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_medium']),
            QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_high']),
            QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_critical'])
        ]
        
        self.setMouseTracking(True)  # Enable mouse tracking for tooltips
    
    def set_risk_level(self, level: float):
        """
        Set the risk level to display.
        
        Args:
            level: Risk level between 0.0 (no risk) and 1.0 (maximum risk)
        """
        self._target_risk = max(0.0, min(1.0, level))
    
    def _update_animation(self):
        """Update the animation state of the gauge."""
        # Move current risk towards target
        diff = self._target_risk - self._current_risk
        if abs(diff) > 0.001:
            self._current_risk += diff * self._animation_speed
            self.update()
        
        # Update needle angle with target based on current risk
        self._needle_target_angle = self._current_risk * 180.0 - 90.0
        angle_diff = self._needle_target_angle - self._needle_angle
        self._needle_angle += angle_diff * 0.1
        
        # Apply oscillation effect
        self._needle_oscillation = math.sin(datetime.now().timestamp() * self._needle_oscillation_speed)
        if abs(diff) > 0.001:
            oscillation_magnitude = max(0.01, min(0.1, abs(diff) * 30.0))
            self._needle_angle += self._needle_oscillation * oscillation_magnitude
        else:
            # Small idle oscillation
            idle_oscillation = 0.05 + (self._current_risk * 0.1)
            self._needle_angle += self._needle_oscillation * idle_oscillation
        
        # Always update for smooth animations
        self.update()
    
    def get_risk_color(self, risk: float) -> QColor:
        """Get the color corresponding to a risk level."""
        if risk <= 0.25:
            # Interpolate between colors[0] and colors[1]
            return self._interpolate_color(self._colors[0], self._colors[1], risk / 0.25)
        elif risk <= 0.5:
            # Interpolate between colors[1] and colors[2]
            return self._interpolate_color(self._colors[1], self._colors[2], (risk - 0.25) / 0.25)
        else:
            # Interpolate between colors[2] and colors[3]
            return self._interpolate_color(self._colors[2], self._colors[3], (risk - 0.5) / 0.5)
    
    def _interpolate_color(self, color1: QColor, color2: QColor, factor: float) -> QColor:
        """Interpolate between two colors."""
        r = color1.red() + factor * (color2.red() - color1.red())
        g = color1.green() + factor * (color2.green() - color1.green())
        b = color1.blue() + factor * (color2.blue() - color1.blue())
        return QColor(int(r), int(g), int(b))
    
    def paintEvent(self, event: QPaintEvent):
        """Paint the risk meter."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        width = self.width()
        height = self.height()
        
        # Draw background
        background_rect = QRectF(0, 0, width, height)
        painter.setPen(Qt.NoPen)
        bg_gradient = QRadialGradient(width / 2, height, height)
        bg_gradient.setColorAt(0, QColor(30, 30, 30))
        bg_gradient.setColorAt(1, QColor(10, 10, 10))
        painter.setBrush(QBrush(bg_gradient))
        painter.drawRect(background_rect)
        
        # Calculate meter dimensions
        center_x = width / 2
        center_y = height * 0.9  # Slightly below center of widget
        radius = min(width, height * 2) * 0.4
        
        # Draw meter arc background
        painter.setPen(QPen(QColor(50, 50, 50), 2))
        meter_rect = QRectF(center_x - radius, center_y - radius, radius * 2, radius * 2)
        # Draw just the top half arc (-180 to 0 degrees)
        painter.drawArc(meter_rect, 180 * 16, -180 * 16)
        
        # Draw colored gradient arc segments
        for i in range(100):
            angle_segment = 180.0 / 100.0
            segment_value = i / 100.0
            segment_color = self.get_risk_color(segment_value)
            
            # Convert to QPainter's angle system (1/16th of a degree, clockwise from 3 o'clock)
            start_angle = int((180 - i * angle_segment) * 16)
            span_angle = -int(angle_segment * 16)
            
            painter.setPen(QPen(segment_color, 5, Qt.SolidLine, Qt.RoundCap))
            painter.drawArc(meter_rect, start_angle, span_angle)
        
        # Calculate current position on the arc
        angle_radians = math.radians(self._needle_angle + 90)
        pointer_length = radius * 0.9
        pointer_x = center_x + pointer_length * math.cos(angle_radians)
        pointer_y = center_y - pointer_length * math.sin(angle_radians)
        
        # Draw pointer line
        pointer_color = self.get_risk_color(self._current_risk)
        painter.setPen(QPen(pointer_color, 3, Qt.SolidLine, Qt.RoundCap))
        painter.drawLine(int(center_x), int(center_y), int(pointer_x), int(pointer_y))
        
        # Draw pointer circle
        painter.setBrush(QBrush(pointer_color))
        pointer_circle_radius = 8
        painter.drawEllipse(QPointF(pointer_x, pointer_y), pointer_circle_radius, pointer_circle_radius)
        
        # Draw center hub
        hub_gradient = QRadialGradient(center_x, center_y, 15)
        hub_gradient.setColorAt(0, QColor(100, 100, 100))
        hub_gradient.setColorAt(1, QColor(30, 30, 30))
        painter.setBrush(QBrush(hub_gradient))
        painter.setPen(QPen(QColor(80, 80, 80), 1))
        painter.drawEllipse(QPointF(center_x, center_y), 12, 12)
        
        # Draw risk level at hub center
        painter.setPen(QColor(255, 255, 255))
        font = painter.font()
        font.setBold(True)
        painter.setFont(font)
        risk_text = f"{int(self._current_risk * 100)}%"
        text_rect = QRectF(center_x - 25, center_y - 8, 50, 16)
        painter.drawText(text_rect, Qt.AlignCenter, risk_text)
        
        # Draw scale marks and labels
        painter.setPen(QColor(200, 200, 200))
        font = painter.font()
        font.setPointSize(8)
        painter.setFont(font)
        
        # Draw major scale marks (0%, 25%, 50%, 75%, 100%)
        for i in range(5):
            percent = i * 25
            mark_angle = math.radians((180 - (percent * 1.8)) + 90)
            mark_length = radius * 0.12
            mark_outer_x = center_x + (radius * 1.05) * math.cos(mark_angle)
            mark_outer_y = center_y - (radius * 1.05) * math.sin(mark_angle)
            mark_inner_x = center_x + (radius * 1.05 - mark_length) * math.cos(mark_angle)
            mark_inner_y = center_y - (radius * 1.05 - mark_length) * math.sin(mark_angle)
            
            painter.setPen(QPen(QColor(180, 180, 180), 2))
            painter.drawLine(QPointF(mark_inner_x, mark_inner_y), QPointF(mark_outer_x, mark_outer_y))
            
            # Draw label
            label_x = center_x + (radius * 1.18) * math.cos(mark_angle)
            label_y = center_y - (radius * 1.18) * math.sin(mark_angle)
            painter.setPen(QColor(200, 200, 200))
            
            label_rect = QRectF(label_x - 15, label_y - 8, 30, 16)
            painter.drawText(label_rect, Qt.AlignCenter, f"{percent}%")
        
        # Draw title
        painter.setPen(QColor(255, 255, 255))
        font = painter.font()
        font.setPointSize(12)
        font.setBold(True)
        painter.setFont(font)
        title_text = "THREAT RISK LEVEL"
        title_rect = QRectF(0, 10, width, 30)
        painter.drawText(title_rect, Qt.AlignCenter, title_text)
        
        # Draw risk level text description
        level_text = "LOW RISK"
        if self._current_risk > 0.25:
            level_text = "MODERATE RISK"
        if self._current_risk > 0.5:
            level_text = "HIGH RISK"
        if self._current_risk > 0.75:
            level_text = "CRITICAL RISK"
        
        level_color = self.get_risk_color(self._current_risk)
        painter.setPen(level_color)
        level_rect = QRectF(0, 35, width, 30)
        painter.drawText(level_rect, Qt.AlignCenter, level_text)
        
        painter.end()
    
    def mouseMoveEvent(self, event: QMouseEvent):
        """Show tooltip when hovering over the meter."""
        # Calculate distance from center
        center_x = self.width() / 2
        center_y = self.height() * 0.9
        radius = min(self.width(), self.height() * 2) * 0.4
        
        dx = event.x() - center_x
        dy = event.y() - center_y
        distance = math.sqrt(dx*dx + dy*dy)
        
        # If near the arc
        if abs(distance - radius) < 20:
            # Calculate angle
            angle = math.degrees(math.atan2(-dy, dx))
            if angle < 0:
                angle += 360
            
            # Convert angle to a risk percentage (180-0 degrees = 0-100%)
            if 180 <= angle <= 360:
                risk_percent = int((360 - angle) / 180 * 100)
                
                # Show tooltip
                tooltip_text = f"Risk level: {risk_percent}%"
                if risk_percent <= 25:
                    tooltip_text += "\nLow risk level"
                elif risk_percent <= 50:
                    tooltip_text += "\nModerate risk level"
                elif risk_percent <= 75:
                    tooltip_text += "\nHigh risk level"
                else:
                    tooltip_text += "\nCritical risk level"
                
                QToolTip.showText(event.globalPos(), tooltip_text)
                return
        
        # Hide tooltip if not over arc
        QToolTip.hideText()
        super().mouseMoveEvent(event)


class ThreatMapVisualizer(QWidget):
    """
    A widget that visualizes threats as animated nodes on a map-like display,
    showing relationships and impact.
    """
    
    def __init__(self, threat_db: ThreatDatabase, parent=None):
        """Initialize the threat map visualizer."""
        super().__init__(parent)
        self.threat_db = threat_db
        self.setMinimumSize(400, 300)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        self._nodes = []
        self._connections = []
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update_animation)
        self._timer.start(50)  # 50ms update interval
        
        self._hovered_node = None
        self.setMouseTracking(True)
        
        # Initialize with some node positions
        self._center_point = None
        self._layout_dirty = True
        
        # Animation parameters
        self._animation_time = 0
        self._pulse_speed = 0.05  # Pulse speed
    
    def update_threats(self):
        """Update the visualization with current threats."""
        self._nodes.clear()
        self._connections.clear()
        
        # First add the protected system node at the center
        self._center_point = Node(
            id="system",
            label="Protected System",
            x=0,
            y=0,
            size=30,
            color=QColor(COLORS[CONFIG['ui_settings']['theme']]['primary']),
            node_type="system"
        )
        self._nodes.append(self._center_point)
        
        # Add threat nodes
        for i, threat in enumerate(self.threat_db.threats):
            # Calculate threat position - random but with some structure
            angle = random.uniform(0, 2 * math.pi)
            distance = random.uniform(120, 200)
            
            # Group by threat type somewhat
            if isinstance(threat, ThreatType):
                # Adjust angle based on threat type
                type_index = list(ThreatType).index(threat.type)
                angle_offset = type_index * (2 * math.pi / len(ThreatType))
                angle += angle_offset
            
            # Adjust distance based on severity
            if threat.level == ThreatLevel.CRITICAL:
                distance *= 0.7  # Closer means more impactful
            elif threat.level == ThreatLevel.HIGH:
                distance *= 0.8
            elif threat.level == ThreatLevel.MEDIUM:
                distance *= 0.9
            
            # Create node
            node_color = self._get_threat_color(threat.level)
            
            x = math.cos(angle) * distance
            y = math.sin(angle) * distance
            
            # Create node
            node = Node(
                id=f"threat_{i}",
                label=threat.description,
                x=x,
                y=y,
                size=self._get_threat_size(threat.level),
                color=node_color,
                node_type="threat",
                data=threat
            )
            self._nodes.append(node)
            
            # Connect to center
            connection = Connection(
                source=node,
                target=self._center_point,
                strength=self._get_threat_connection_strength(threat.level),
                color=node_color.lighter(130)
            )
            self._connections.append(connection)
        
        # Mark layout as dirty to recalculate
        self._layout_dirty = True
        self.update()
    
    def _get_threat_color(self, level: ThreatLevel) -> QColor:
        """Get color for a threat based on its level."""
        if level == ThreatLevel.CRITICAL:
            return QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_critical'])
        elif level == ThreatLevel.HIGH:
            return QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_high'])
        elif level == ThreatLevel.MEDIUM:
            return QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_medium'])
        else:
            return QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_low'])
    
    def _get_threat_size(self, level: ThreatLevel) -> float:
        """Get size for a threat node based on its level."""
        if level == ThreatLevel.CRITICAL:
            return 25
        elif level == ThreatLevel.HIGH:
            return 20
        elif level == ThreatLevel.MEDIUM:
            return 15
        else:
            return 10
    
    def _get_threat_connection_strength(self, level: ThreatLevel) -> float:
        """Get connection strength for a threat based on its level."""
        if level == ThreatLevel.CRITICAL:
            return 0.9
        elif level == ThreatLevel.HIGH:
            return 0.7
        elif level == ThreatLevel.MEDIUM:
            return 0.5
        else:
            return 0.3
    
    def _update_animation(self):
        """Update animation state."""
        self._animation_time += 0.1
        
        # Apply force-directed layout if needed
        if self._layout_dirty and len(self._nodes) > 1:
            self._apply_force_directed_layout()
            self._layout_dirty = False
        
        self.update()
    
    def _apply_force_directed_layout(self, iterations=50):
        """Apply a simple force-directed layout algorithm."""
        # Skip if only one node
        if len(self._nodes) <= 1:
            return
        
        # Fixed center point
        center_node = self._nodes[0]
        center_node.x = 0
        center_node.y = 0
        
        # Run iterations
        for _ in range(iterations):
            # Calculate repulsive forces between nodes
            for i, node1 in enumerate(self._nodes):
                if node1.id == "system":
                    continue  # Skip center node
                    
                # Repulsive force from other threat nodes
                force_x, force_y = 0, 0
                for j, node2 in enumerate(self._nodes):
                    if i == j or node2.id == "system":
                        continue
                    
                    dx = node1.x - node2.x
                    dy = node1.y - node2.y
                    distance = max(0.1, math.sqrt(dx*dx + dy*dy))
                    
                    # Repulsive force inversely proportional to distance
                    repulsion = 5000.0 / (distance * distance)
                    
                    # Normalize direction
                    direction_x = dx / distance if distance > 0 else 0
                    direction_y = dy / distance if distance > 0 else 0
                    
                    force_x += direction_x * repulsion
                    force_y += direction_y * repulsion
                
                # Attractive force to center based on connection
                for conn in self._connections:
                    if conn.source.id == node1.id and conn.target.id == "system":
                        dx = node1.x - center_node.x
                        dy = node1.y - center_node.y
                        distance = max(0.1, math.sqrt(dx*dx + dy*dy))
                        
                        # Attractive force proportional to distance
                        attraction = distance * conn.strength * 0.1
                        
                        # Normalize direction
                        direction_x = dx / distance if distance > 0 else 0
                        direction_y = dy / distance if distance > 0 else 0
                        
                        force_x -= direction_x * attraction
                        force_y -= direction_y * attraction
                
                # Apply forces with damping
                damping = 0.9
                node1.x += force_x * damping
                node1.y += force_y * damping
                
                # Limit maximum distance from center
                distance_from_center = math.sqrt(node1.x*node1.x + node1.y*node1.y)
                max_distance = 250
                if distance_from_center > max_distance:
                    scale = max_distance / distance_from_center
                    node1.x *= scale
                    node1.y *= scale
    
    def paintEvent(self, event: QPaintEvent):
        """Paint the threat map."""
        if not self._nodes:
            return
            
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Set up viewport coordinates
        width = self.width()
        height = self.height()
        
        # Clear background
        painter.fillRect(0, 0, width, height, QColor(20, 20, 30))
        
        # Draw grid lines
        painter.setPen(QPen(QColor(40, 40, 50), 1, Qt.DotLine))
        grid_size = 50
        
        # Draw horizontal grid lines
        for y in range(0, height, grid_size):
            painter.drawLine(0, y, width, y)
        
        # Draw vertical grid lines
        for x in range(0, width, grid_size):
            painter.drawLine(x, 0, x, height)
        
        # Translate to center of widget
        painter.translate(width / 2, height / 2)
        
        # Draw connections first (so they're behind nodes)
        for conn in self._connections:
            self._draw_connection(painter, conn)
        
        # Draw nodes
        for node in self._nodes:
            self._draw_node(painter, node)
        
        painter.end()
    
    def _draw_connection(self, painter: QPainter, connection: 'Connection'):
        """Draw a connection between nodes."""
        # Get source and target positions
        source = connection.source
        target = connection.target
        
        # Calculate curve control points for a nice arc
        dx = target.x - source.x
        dy = target.y - source.y
        distance = math.sqrt(dx*dx + dy*dy)
        
        # Skip very close nodes
        if distance < 0.1:
            return
        
        # Normal vector for curve control
        nx = -dy / distance
        ny = dx / distance
        
        # Adjust source and target positions to node edges
        source_scale = source.size / distance
        target_scale = target.size / distance
        
        source_x = source.x + dx * source_scale
        source_y = source.y + dy * source_scale
        target_x = target.x - dx * target_scale
        target_y = target.y - dy * target_scale
        
        # Create curved path
        curve_amount = min(distance * 0.5, 50)
        cp1x = source_x + dx * 0.33 + nx * curve_amount
        cp1y = source_y + dy * 0.33 + ny * curve_amount
        cp2x = source_x + dx * 0.66 + nx * curve_amount
        cp2y = source_y + dy * 0.66 + ny * curve_amount
        
        path = QPainterPath()
        path.moveTo(source_x, source_y)
        path.cubicTo(cp1x, cp1y, cp2x, cp2y, target_x, target_y)
        
        # Draw with animated flow effect
        pen = QPen(connection.color, 1.5 + connection.strength * 2.0)
        pen.setDashOffset(self._animation_time * 10.0)
        pen.setDashPattern([2, 3]) # Dash pattern for animated flow
        painter.setPen(pen)
        painter.drawPath(path)
        
        # Draw solid base line
        pen.setStyle(Qt.SolidLine)
        pen.setWidth(int(1 + connection.strength * 1.5))
        pen.setColor(connection.color.darker(120))
        painter.setPen(pen)
        painter.drawPath(path)
    
    def _draw_node(self, painter: QPainter, node: 'Node'):
        """Draw a node."""
        x, y = node.x, node.y
        size = node.size
        
        # Calculate pulse effect
        pulse = math.sin(self._animation_time * self._pulse_speed + hash(node.id) % 100) * 0.2 + 0.8
        
        # Adjust size for pulse
        if node.id == "system":
            # System node has a milder pulse
            draw_size = size * (0.9 + pulse * 0.1)
        else:
            # Threat nodes pulse more dramatically
            draw_size = size * pulse
        
        # Draw glow effect
        gradient = QRadialGradient(x, y, size * 1.5)
        glow_color = QColor(node.color)
        glow_color.setAlpha(50)
        gradient.setColorAt(0, glow_color)
        glow_color.setAlpha(0)
        gradient.setColorAt(1, glow_color)
        painter.setBrush(QBrush(gradient))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(x, y), size * 1.5, size * 1.5)
        
        # Draw main circle
        gradient = QRadialGradient(x, y, draw_size)
        gradient.setColorAt(0, node.color.lighter(130))
        gradient.setColorAt(1, node.color)
        
        painter.setBrush(QBrush(gradient))
        
        # If hovered, add highlight
        if node == self._hovered_node:
            painter.setPen(QPen(QColor(255, 255, 255), 2))
        else:
            painter.setPen(QPen(node.color.darker(120), 1))
        
        painter.drawEllipse(QPointF(x, y), draw_size, draw_size)
        
        # Add inner highlight
        painter.setPen(Qt.NoPen)
        gradient = QRadialGradient(x - size * 0.3, y - size * 0.3, size * 0.5)
        gradient.setColorAt(0, QColor(255, 255, 255, 90))
        gradient.setColorAt(1, QColor(255, 255, 255, 0))
        painter.setBrush(QBrush(gradient))
        painter.drawEllipse(QPointF(x - size * 0.1, y - size * 0.1), size * 0.5, size * 0.5)
        
        # For system node, add special marker
        if node.id == "system":
            painter.setPen(QPen(QColor(255, 255, 255), 2))
            painter.drawEllipse(QPointF(x, y), size * 0.4, size * 0.4)
            painter.drawLine(QPointF(x, y - size * 0.6), QPointF(x, y + size * 0.6))
            painter.drawLine(QPointF(x - size * 0.6, y), QPointF(x + size * 0.6, y))
        
        # Draw label if it's the system or a hovered node
        if node.id == "system" or node == self._hovered_node:
            label_font = painter.font()
            if node.id == "system":
                label_font.setBold(True)
                label_font.setPointSize(10)
            else:
                label_font.setPointSize(9)
            painter.setFont(label_font)
            
            # Create background for text
            text_width = painter.fontMetrics().width(node.label)
            text_height = painter.fontMetrics().height()
            text_rect = QRectF(x - text_width / 2 - 5, y + size + 5, text_width + 10, text_height + 6)
            
            # Draw text background
            painter.setPen(Qt.NoPen)
            if node.id == "system":
                bg_color = QColor(0, 0, 0, 180)
            else:
                bg_color = QColor(node.color.red(), node.color.green(), node.color.blue(), 180)
            painter.setBrush(QBrush(bg_color))
            painter.drawRoundedRect(text_rect, 4, 4)
            
            # Draw text
            painter.setPen(QColor(255, 255, 255))
            painter.drawText(text_rect, Qt.AlignCenter, node.label)
            
            # For hovered threats, show more details
            if node != self._center_point and node == self._hovered_node and hasattr(node.data, 'level'):
                detail_text = f"Level: {node.data.level.value.capitalize()}"
                # Add timestamp if available
                if hasattr(node.data, 'timestamp'):
                    detail_text += f" | {node.data.timestamp.strftime('%Y-%m-%d %H:%M')}"
                
                # Draw detail text
                detail_font = label_font
                detail_font.setPointSize(8)
                painter.setFont(detail_font)
                
                detail_width = painter.fontMetrics().width(detail_text)
                detail_height = painter.fontMetrics().height()
                detail_rect = QRectF(x - detail_width / 2 - 5, y + size + text_height + 10, 
                                  detail_width + 10, detail_height + 4)
                
                # Draw detail background
                painter.setPen(Qt.NoPen)
                painter.setBrush(QBrush(QColor(0, 0, 0, 150)))
                painter.drawRoundedRect(detail_rect, 3, 3)
                
                # Draw detail text
                painter.setPen(QColor(200, 200, 200))
                painter.drawText(detail_rect, Qt.AlignCenter, detail_text)
    
    def mouseMoveEvent(self, event: QMouseEvent):
        """Handle mouse movement to detect node hovering."""
        # Convert coords to graph space
        graph_x = event.x() - self.width() / 2
        graph_y = event.y() - self.height() / 2
        
        # Check if hovering over any node
        old_hovered = self._hovered_node
        self._hovered_node = None
        
        for node in self._nodes:
            dx = graph_x - node.x
            dy = graph_y - node.y
            distance = math.sqrt(dx*dx + dy*dy)
            
            if distance <= node.size + 5:  # Add some margin for easier hovering
                self._hovered_node = node
                break
        
        # Only update if hover state changed
        if old_hovered != self._hovered_node:
            self.update()
            
            # Update cursor
            if self._hovered_node:
                self.setCursor(Qt.PointingHandCursor)
            else:
                self.setCursor(Qt.ArrowCursor)
    
    def mousePressEvent(self, event: QMouseEvent):
        """Handle mouse press events to select nodes."""
        if event.button() == Qt.LeftButton and self._hovered_node:
            # Here you could emit a signal with the selected node/threat
            # or display a detailed dialog
            pass


class ThreatTrendGraph(QWidget):
    """
    A widget that displays animated trend graphs of threat levels over time.
    """
    
    def __init__(self, parent=None):
        """Initialize the threat trend graph."""
        super().__init__(parent)
        self.setMinimumSize(400, 200)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        # Initialize data
        self._time_periods = []  # List of dates/times
        self._critical_data = []
        self._high_data = []
        self._medium_data = []
        self._low_data = []
        
        # Animation
        self._animation_progress = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update_animation)
        self._timer.start(30)
        
        # For displaying current values on hover
        self._hovered_point = -1
        self.setMouseTracking(True)
    
    def set_data(self, time_periods: List[datetime], 
                critical_data: List[int], 
                high_data: List[int],
                medium_data: List[int],
                low_data: List[int]):
        """
        Set the data for the trend graph.
        
        Args:
            time_periods: List of datetime objects for the x-axis
            critical_data: List of critical threat counts
            high_data: List of high threat counts
            medium_data: List of medium threat counts
            low_data: List of low threat counts
        """
        self._time_periods = time_periods
        self._critical_data = critical_data
        self._high_data = high_data
        self._medium_data = medium_data
        self._low_data = low_data
        
        # Reset animation
        self._animation_progress = 0.0
        self.update()
    
    def _update_animation(self):
        """Update the animation state."""
        if self._animation_progress < 1.0:
            self._animation_progress += 0.02
            if self._animation_progress > 1.0:
                self._animation_progress = 1.0
            self.update()
    
    def paintEvent(self, event: QPaintEvent):
        """Paint the trend graph."""
        if not self._time_periods:
            # No data to display
            return
        
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        width = self.width()
        height = self.height()
        
        # Define margins
        margin_left = 60
        margin_right = 20
        margin_top = 30
        margin_bottom = 50
        
        graph_width = width - margin_left - margin_right
        graph_height = height - margin_top - margin_bottom
        
        # Draw background
        painter.fillRect(0, 0, width, height, QColor(25, 25, 35))
        
        # Draw title
        painter.setPen(QColor(255, 255, 255))
        font = painter.font()
        font.setPointSize(12)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(QRectF(0, 5, width, 25), Qt.AlignCenter, "Threat Trend Analysis")
        
        # If no data, show message
        if not self._time_periods:
            font.setPointSize(10)
            font.setBold(False)
            painter.setFont(font)
            painter.drawText(QRectF(0, 0, width, height), Qt.AlignCenter, "No threat data available")
            return
        
        # Draw axes
        painter.setPen(QPen(QColor(150, 150, 150), 1))
        
        # X-axis
        painter.drawLine(margin_left, height - margin_bottom, width - margin_right, height - margin_bottom)
        
        # Y-axis
        painter.drawLine(margin_left, margin_top, margin_left, height - margin_bottom)
        
        # Find the maximum value for scaling
        max_value = 0
        for i in range(len(self._time_periods)):
            total = (self._critical_data[i] + self._high_data[i] + 
                    self._medium_data[i] + self._low_data[i])
            max_value = max(max_value, total)
        
        # Ensure we have a reasonable maximum (at least 5)
        max_value = max(5, max_value)
        
        # Draw Y-axis labels and grid lines
        font.setPointSize(8)
        painter.setFont(font)
        painter.setPen(QColor(150, 150, 150))
        
        y_step = max(1, max_value // 5)  # At most 5 labels
        for i in range(0, max_value + y_step, y_step):
            y = height - margin_bottom - (i / max_value * graph_height)
            # Skip if out of bounds
            if y < margin_top:
                continue
                
            # Grid line
            painter.setPen(QPen(QColor(70, 70, 80), 1, Qt.DotLine))
            painter.drawLine(margin_left, y, width - margin_right, y)
            
            # Label
            painter.setPen(QColor(150, 150, 150))
            painter.drawText(QRectF(5, y - 10, margin_left - 10, 20), 
                          Qt.AlignRight | Qt.AlignVCenter, str(i))
        
        # Draw X-axis labels and grid lines
        if len(self._time_periods) > 1:
            time_step = max(1, len(self._time_periods) // 6)  # At most 6 labels
            for i in range(0, len(self._time_periods), time_step):
                x = margin_left + (i / (len(self._time_periods) - 1) * graph_width)
                
                # Grid line
                painter.setPen(QPen(QColor(70, 70, 80), 1, Qt.DotLine))
                painter.drawLine(x, margin_top, x, height - margin_bottom)
                
                # Format the date/time
                time_str = self._time_periods[i].strftime("%H:%M" if len(self._time_periods) <= 24 else "%d %b")
                
                # Label
                painter.setPen(QColor(150, 150, 150))
                painter.drawText(QRectF(x - 50, height - margin_bottom + 5, 100, 20), 
                              Qt.AlignCenter, time_str)
        
        # Prepare to draw the stacked areas
        num_points = len(self._time_periods)
        if num_points < 2:
            return
        
        # Apply animation - we'll only show a portion of the data
        animated_points = max(2, int(num_points * self._animation_progress))
        
        # Draw stacked areas from bottom to top
        def get_x(i):
            return margin_left + (i / (num_points - 1) * graph_width)
        
        def get_y(value):
            return height - margin_bottom - (value / max_value * graph_height)
        
        # Create paths for each threat level
        low_path = QPainterPath()
        low_path.moveTo(get_x(0), height - margin_bottom)
        
        medium_path = QPainterPath()
        medium_path.moveTo(get_x(0), height - margin_bottom)
        
        high_path = QPainterPath()
        high_path.moveTo(get_x(0), height - margin_bottom)
        
        critical_path = QPainterPath()
        critical_path.moveTo(get_x(0), height - margin_bottom)
        
        # Arrays to store the top points of each area for drawing lines later
        low_points = []
        medium_points = []
        high_points = []
        critical_points = []
        
        # Build the paths
        for i in range(animated_points):
            # Calculate cumulative values
            low_val = self._low_data[i]
            medium_val = low_val + self._medium_data[i]
            high_val = medium_val + self._high_data[i]
            critical_val = high_val + self._critical_data[i]
            
            x = get_x(i)
            
            # Calculate y positions
            low_y = get_y(low_val)
            medium_y = get_y(medium_val)
            high_y = get_y(high_val)
            critical_y = get_y(critical_val)
            
            # Store points for line drawing
            low_points.append(QPointF(x, low_y))
            medium_points.append(QPointF(x, medium_y))
            high_points.append(QPointF(x, high_y))
            critical_points.append(QPointF(x, critical_y))
            
            # Add points to paths
            if i == 0:
                low_path.moveTo(x, low_y)
                medium_path.moveTo(x, medium_y)
                high_path.moveTo(x, high_y)
                critical_path.moveTo(x, critical_y)
            else:
                # Use curves for smoother lines
                prev_x = get_x(i - 1)
                control_x = (prev_x + x) / 2
                
                low_path.cubicTo(control_x, low_points[i-1].y(), control_x, low_y, x, low_y)
                medium_path.cubicTo(control_x, medium_points[i-1].y(), control_x, medium_y, x, medium_y)
                high_path.cubicTo(control_x, high_points[i-1].y(), control_x, high_y, x, high_y)
                critical_path.cubicTo(control_x, critical_points[i-1].y(), control_x, critical_y, x, critical_y)
        
        # Complete the paths by adding bottom edges
        x_end = get_x(animated_points - 1)
        critical_path.lineTo(x_end, height - margin_bottom)
        critical_path.lineTo(get_x(0), height - margin_bottom)
        
        high_path.lineTo(x_end, height - margin_bottom)
        high_path.lineTo(get_x(0), height - margin_bottom)
        
        medium_path.lineTo(x_end, height - margin_bottom)
        medium_path.lineTo(get_x(0), height - margin_bottom)
        
        low_path.lineTo(x_end, height - margin_bottom)
        low_path.lineTo(get_x(0), height - margin_bottom)
        
        # Draw the areas
        critical_color = QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_critical'])
        high_color = QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_high'])
        medium_color = QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_medium'])
        low_color = QColor(COLORS[CONFIG['ui_settings']['theme']]['threat_low'])
        
        # Draw areas with gradients
        painter.setPen(Qt.NoPen)
        
        # Critical area gradient
        gradient = QLinearGradient(0, margin_top, 0, height - margin_bottom)
        gradient.setColorAt(0, critical_color)
        gradient.setColorAt(1, critical_color.darker(150))
        painter.setBrush(QBrush(gradient))
        painter.drawPath(critical_path)
        
        # High area gradient
        gradient = QLinearGradient(0, margin_top, 0, height - margin_bottom)
        gradient.setColorAt(0, high_color)
        gradient.setColorAt(1, high_color.darker(150))
        painter.setBrush(QBrush(gradient))
        painter.drawPath(high_path)
        
        # Medium area gradient
        gradient = QLinearGradient(0, margin_top, 0, height - margin_bottom)
        gradient.setColorAt(0, medium_color)
        gradient.setColorAt(1, medium_color.darker(150))
        painter.setBrush(QBrush(gradient))
        painter.drawPath(medium_path)
        
        # Low area gradient
        gradient = QLinearGradient(0, margin_top, 0, height - margin_bottom)
        gradient.setColorAt(0, low_color)
        gradient.setColorAt(1, low_color.darker(150))
        painter.setBrush(QBrush(gradient))
        painter.drawPath(low_path)
        
        # Draw the lines on top
        painter.setPen(QPen(critical_color.lighter(150), 2))
        for i in range(1, len(critical_points)):
            painter.drawLine(critical_points[i-1], critical_points[i])
        
        painter.setPen(QPen(high_color.lighter(150), 2))
        for i in range(1, len(high_points)):
            painter.drawLine(high_points[i-1], high_points[i])
        
        painter.setPen(QPen(medium_color.lighter(150), 2))
        for i in range(1, len(medium_points)):
            painter.drawLine(medium_points[i-1], medium_points[i])
        
        painter.setPen(QPen(low_color.lighter(150), 2))
        for i in range(1, len(low_points)):
            painter.drawLine(low_points[i-1], low_points[i])
        
        # Draw legend
        legend_x = margin_left + 10
        legend_y = margin_top + 15
        legend_size = 12
        
        # Critical
        painter.setPen(Qt.NoPen)
        painter.setBrush(critical_color)
        painter.drawRect(legend_x, legend_y, legend_size, legend_size)
        painter.setPen(QColor(255, 255, 255))
        font.setPointSize(9)
        painter.setFont(font)
        painter.drawText(QRectF(legend_x + legend_size + 5, legend_y, 100, legend_size), 
                      Qt.AlignLeft | Qt.AlignVCenter, "Critical")
        
        # High
        legend_y += legend_size + 10
        painter.setPen(Qt.NoPen)
        painter.setBrush(high_color)
        painter.drawRect(legend_x, legend_y, legend_size, legend_size)
        painter.setPen(QColor(255, 255, 255))
        painter.drawText(QRectF(legend_x + legend_size + 5, legend_y, 100, legend_size), 
                      Qt.AlignLeft | Qt.AlignVCenter, "High")
        
        # Medium
        legend_y += legend_size + 10
        painter.setPen(Qt.NoPen)
        painter.setBrush(medium_color)
        painter.drawRect(legend_x, legend_y, legend_size, legend_size)
        painter.setPen(QColor(255, 255, 255))
        painter.drawText(QRectF(legend_x + legend_size + 5, legend_y, 100, legend_size), 
                      Qt.AlignLeft | Qt.AlignVCenter, "Medium")
        
        # Low
        legend_y += legend_size + 10
        painter.setPen(Qt.NoPen)
        painter.setBrush(low_color)
        painter.drawRect(legend_x, legend_y, legend_size, legend_size)
        painter.setPen(QColor(255, 255, 255))
        painter.drawText(QRectF(legend_x + legend_size + 5, legend_y, 100, legend_size), 
                      Qt.AlignLeft | Qt.AlignVCenter, "Low")
        
        # Draw hover information
        if self._hovered_point >= 0 and self._hovered_point < animated_points:
            i = self._hovered_point
            x = get_x(i)
            
            # Draw vertical line at hovered point
            painter.setPen(QPen(QColor(255, 255, 255, 150), 1, Qt.DashLine))
            painter.drawLine(x, margin_top, x, height - margin_bottom)
            
            # Format date
            date_str = self._time_periods[i].strftime("%Y-%m-%d %H:%M")
            
            # Calculate totals
            low_val = self._low_data[i]
            medium_val = self._medium_data[i]
            high_val = self._high_data[i]
            critical_val = self._critical_data[i]
            total = low_val + medium_val + high_val + critical_val
            
            # Prepare info box
            info_width = 160
            info_height = 120
            info_x = x + 10
            
            # Make sure info box is fully visible
            if info_x + info_width > width - margin_right:
                info_x = x - info_width - 10
            
            info_y = margin_top + 10
            
            # Draw info box
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(0, 0, 0, 180))
            painter.drawRoundedRect(info_x, info_y, info_width, info_height, 5, 5)
            
            # Draw info content
            painter.setPen(QColor(255, 255, 255))
            font.setPointSize(9)
            font.setBold(True)
            painter.setFont(font)
            
            painter.drawText(QRectF(info_x + 5, info_y + 5, info_width - 10, 20), 
                          Qt.AlignCenter, date_str)
            
            font.setBold(False)
            painter.setFont(font)
            
            text_y = info_y + 30
            
            # Critical
            painter.setPen(Qt.NoPen)
            painter.setBrush(critical_color)
            painter.drawRect(info_x + 10, text_y, 12, 12)
            painter.setPen(QColor(255, 255, 255))
            painter.drawText(QRectF(info_x + 30, text_y, info_width - 40, 15), 
                          Qt.AlignLeft | Qt.AlignVCenter, f"Critical: {critical_val}")
            
            # High
            text_y += 20
            painter.setPen(Qt.NoPen)
            painter.setBrush(high_color)
            painter.drawRect(info_x + 10, text_y, 12, 12)
            painter.setPen(QColor(255, 255, 255))
            painter.drawText(QRectF(info_x + 30, text_y, info_width - 40, 15), 
                          Qt.AlignLeft | Qt.AlignVCenter, f"High: {high_val}")
            
            # Medium
            text_y += 20
            painter.setPen(Qt.NoPen)
            painter.setBrush(medium_color)
            painter.drawRect(info_x + 10, text_y, 12, 12)
            painter.setPen(QColor(255, 255, 255))
            painter.drawText(QRectF(info_x + 30, text_y, info_width - 40, 15), 
                          Qt.AlignLeft | Qt.AlignVCenter, f"Medium: {medium_val}")
            
            # Low
            text_y += 20
            painter.setPen(Qt.NoPen)
            painter.setBrush(low_color)
            painter.drawRect(info_x + 10, text_y, 12, 12)
            painter.setPen(QColor(255, 255, 255))
            painter.drawText(QRectF(info_x + 30, text_y, info_width - 40, 15), 
                          Qt.AlignLeft | Qt.AlignVCenter, f"Low: {low_val}")
            
            # Total
            text_y += 20
            painter.setPen(QColor(255, 255, 255))
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(QRectF(info_x + 10, text_y, info_width - 20, 15), 
                          Qt.AlignRight | Qt.AlignVCenter, f"Total: {total}")
        
        painter.end()
    
    def mouseMoveEvent(self, event: QMouseEvent):
        """Handle mouse movement to detect hovering over data points."""
        if not self._time_periods:
            return
            
        width = self.width()
        height = self.height()
        
        # Define margins
        margin_left = 60
        margin_right = 20
        margin_top = 30
        margin_bottom = 50
        
        graph_width = width - margin_left - margin_right
        
        # Check if mouse is in graph area
        if (event.x() >= margin_left and event.x() <= width - margin_right and
            event.y() >= margin_top and event.y() <= height - margin_bottom):
            
            # Calculate which data point we're closest to
            animated_points = max(2, int(len(self._time_periods) * self._animation_progress))
            if animated_points < 2:
                return
                
            x_pos = (event.x() - margin_left) / graph_width
            
            # Convert to index
            point_index = int(x_pos * (animated_points - 1) + 0.5)
            point_index = max(0, min(point_index, animated_points - 1))
            
            self._hovered_point = point_index
            self.update()
        else:
            # Mouse not in graph area
            if self._hovered_point != -1:
                self._hovered_point = -1
                self.update()


class Node:
    """
    Represents a node in the threat visualization.
    """
    
    def __init__(self, id: str, label: str, x: float, y: float, size: float, 
                color: QColor, node_type: str, data: Any = None):
        """
        Initialize a node.
        
        Args:
            id: Unique identifier
            label: Display label
            x, y: Position coordinates
            size: Node size
            color: Node color
            node_type: Type of node ('threat', 'system', etc.)
            data: Optional associated data (e.g., Threat object)
        """
        self.id = id
        self.label = label
        self.x = x
        self.y = y
        self.size = size
        self.color = color
        self.node_type = node_type
        self.data = data


class Connection:
    """
    Represents a connection between nodes.
    """
    
    def __init__(self, source: Node, target: Node, strength: float, color: QColor):
        """
        Initialize a connection.
        
        Args:
            source: Source node
            target: Target node
            strength: Connection strength (0.0 to 1.0)
            color: Connection color
        """
        self.source = source
        self.target = target
        self.strength = strength
        self.color = color