"""
Animation components for the CyberFox UI.
"""
import os
import math
from typing import Optional

from PyQt5.QtWidgets import QWidget
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPoint, QSize, QRectF, pyqtProperty
from PyQt5.QtGui import QPainter, QColor, QPen, QBrush, QPainterPath
from PyQt5.QtSvg import QSvgRenderer, QSvgWidget

class PulseAnimation(QWidget):
    """A pulsing dot animation."""
    
    def __init__(self, color: QColor = None, parent: QWidget = None):
        """
        Initialize the pulse animation.
        
        Args:
            color: Color of the pulse (default: red)
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.setMinimumSize(12, 12)
        self.color = color or QColor(255, 0, 0)  # Default to red
        self.opacity = 1.0
        self.animation = QPropertyAnimation(self, b"opacity")
        self.animation.setDuration(1000)  # 1 second
        self.animation.setStartValue(0.3)
        self.animation.setEndValue(1.0)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
        self.animation.setLoopCount(-1)  # Infinite loop
        
    def setColor(self, color: QColor):
        """
        Set the color of the pulse.
        
        Args:
            color: New color for the pulse
        """
        self.color = color
        self.update()
        
    def getOpacity(self) -> float:
        """
        Get the current opacity.
        
        Returns:
            Current opacity value
        """
        return self.opacity
        
    def setOpacity(self, opacity: float):
        """
        Set the opacity.
        
        Args:
            opacity: New opacity value
        """
        self.opacity = opacity
        self.update()
        
    # Define the opacity property for animation
    opacity = pyqtProperty(float, getOpacity, setOpacity)
    
    def paintEvent(self, event):
        """Paint the pulse."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Set opacity for the pulse effect
        painter.setOpacity(self.opacity)
        
        # Draw the circle
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(self.color))
        
        # Calculate radius to fit within the widget
        radius = min(self.width(), self.height()) / 2
        center_x = self.width() / 2
        center_y = self.height() / 2
        
        painter.drawEllipse(QPoint(int(center_x), int(center_y)), int(radius), int(radius))
        
    def start(self):
        """Start the animation."""
        self.animation.start()
        
    def stop(self):
        """Stop the animation."""
        self.animation.stop()
        self.opacity = 0.3
        self.update()

class WaveAnimation(QWidget):
    """A wave animation that emanates from a central point."""
    
    def __init__(self, color: QColor = None, parent: QWidget = None):
        """
        Initialize the wave animation.
        
        Args:
            color: Color of the waves (default: blue)
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.setMinimumSize(100, 100)
        self.color = color or QColor(0, 120, 255)  # Default to blue
        
        # Wave properties
        self.wave_count = 3
        self.waves = [0.0] * self.wave_count  # Phase of each wave (0.0 to 1.0)
        
        # Start the timer for animation
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_waves)
        self.is_running = False
        
    def setColor(self, color: QColor):
        """
        Set the color of the waves.
        
        Args:
            color: New color for the waves
        """
        self.color = color
        self.update()
        
    def update_waves(self):
        """Update the wave phases for animation."""
        for i in range(self.wave_count):
            self.waves[i] = (self.waves[i] + 0.05) % 1.0
        self.update()
        
    def paintEvent(self, event):
        """Paint the waves."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Calculate center and max radius
        center_x = self.width() / 2
        center_y = self.height() / 2
        max_radius = min(center_x, center_y)
        
        # Draw waves
        for i, phase in enumerate(self.waves):
            # Calculate radius based on phase
            radius = max_radius * phase
            
            # Calculate opacity (fade out as radius increases)
            opacity = 1.0 - phase
            
            # Set pen color with opacity
            pen_color = QColor(self.color)
            pen_color.setAlphaF(opacity)
            
            painter.setPen(QPen(pen_color, 2))
            painter.setBrush(Qt.NoBrush)
            
            # Draw circle
            painter.drawEllipse(QPoint(int(center_x), int(center_y)), int(radius), int(radius))
        
        # Draw center point
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(self.color))
        painter.drawEllipse(QPoint(int(center_x), int(center_y)), 5, 5)
        
    def start(self):
        """Start the animation."""
        if not self.is_running:
            self.timer.start(50)  # 20 FPS
            self.is_running = True
        
    def stop(self):
        """Stop the animation."""
        if self.is_running:
            self.timer.stop()
            self.is_running = False
            self.waves = [0.0] * self.wave_count
            self.update()
            
    def sizeHint(self):
        """Suggest a size for the widget."""
        return QSize(100, 100)

class RadarAnimation(QWidget):
    """A radar sweep animation."""
    
    def __init__(self, svg_path: str = None, width: int = 100, height: int = 100, parent: QWidget = None):
        """
        Initialize the radar animation.
        
        Args:
            svg_path: Path to SVG icon to display in center (optional)
            width: Width of the widget
            height: Height of the widget
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.setMinimumSize(width, height)
        self.setMaximumSize(width, height)
        
        # Radar properties
        self.angle = 0.0  # Current sweep angle in degrees
        self.color = QColor(0, 200, 100)  # Default to green
        
        # SVG icon
        self.svg_renderer = QSvgRenderer() if svg_path else None
        if svg_path:
            self.svg_renderer.load(svg_path)
        
        # Start the timer for animation
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_radar)
        self.is_running = False
        
    def set_svg(self, svg_path: str):
        """
        Set the SVG icon.
        
        Args:
            svg_path: Path to SVG icon
        """
        if not self.svg_renderer:
            self.svg_renderer = QSvgRenderer()
        self.svg_renderer.load(svg_path)
        self.update()
        
    def setColor(self, color: QColor):
        """
        Set the color of the radar sweep.
        
        Args:
            color: New color for the radar
        """
        self.color = color
        self.update()
        
    def update_radar(self):
        """Update the radar angle for animation."""
        self.angle = (self.angle + 10.0) % 360.0
        self.update()
        
    def paintEvent(self, event):
        """Paint the radar."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Calculate center and radius
        center_x = self.width() / 2
        center_y = self.height() / 2
        radius = min(center_x, center_y) - 2  # Leave a 2px margin
        
        # Draw background circle
        painter.setPen(QPen(self.color.darker(150), 1))
        painter.setBrush(Qt.NoBrush)
        painter.drawEllipse(QPoint(int(center_x), int(center_y)), int(radius), int(radius))
        
        # Draw sweep
        sweep_path = QPainterPath()
        sweep_path.moveTo(center_x, center_y)
        sweep_path.arcTo(QRectF(center_x - radius, center_y - radius, radius * 2, radius * 2), 
                         0, -self.angle)
        sweep_path.lineTo(center_x, center_y)
        
        # Use a gradient for the sweep
        sweep_color = QColor(self.color)
        sweep_color.setAlphaF(0.3)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(sweep_color))
        painter.drawPath(sweep_path)
        
        # Draw sweep line
        line_color = QColor(self.color)
        painter.setPen(QPen(line_color, 2))
        painter.setBrush(Qt.NoBrush)
        
        angle_rad = math.radians(self.angle)
        end_x = center_x + radius * math.cos(angle_rad)
        end_y = center_y - radius * math.sin(angle_rad)
        
        painter.drawLine(QPoint(int(center_x), int(center_y)), QPoint(int(end_x), int(end_y)))
        
        # Draw center icon if we have an SVG
        if self.svg_renderer and self.svg_renderer.isValid():
            icon_size = radius * 0.6  # Icon will be 60% of radius
            icon_rect = QRectF(center_x - icon_size/2, center_y - icon_size/2, icon_size, icon_size)
            self.svg_renderer.render(painter, icon_rect)
        
    def start_animation(self):
        """Start the animation."""
        if not self.is_running:
            self.timer.start(100)  # 10 FPS
            self.is_running = True
        
    def stop_animation(self):
        """Stop the animation."""
        if self.is_running:
            self.timer.stop()
            self.is_running = False
            self.angle = 0.0
            self.update()
            
    def sizeHint(self):
        """Suggest a size for the widget."""
        return QSize(self.width(), self.height())

class AnimatedIcon(QSvgWidget):
    """An animated SVG icon."""
    
    def __init__(self, svg_path: str, width: int = 24, height: int = 24, parent: QWidget = None):
        """
        Initialize the animated icon.
        
        Args:
            svg_path: Path to SVG icon
            width: Width of the widget
            height: Height of the widget
            parent: Parent widget
        """
        super().__init__(svg_path, parent)
        
        self.setFixedSize(width, height)
        
        # Animation properties
        self.rotation = 0.0
        self.rotation_animation = QPropertyAnimation(self, b"rotation")
        self.rotation_animation.setDuration(2000)  # 2 seconds
        self.rotation_animation.setStartValue(0.0)
        self.rotation_animation.setEndValue(360.0)
        self.rotation_animation.setEasingCurve(QEasingCurve.Linear)
        self.rotation_animation.setLoopCount(-1)  # Infinite loop
        
    def getRotation(self) -> float:
        """
        Get the current rotation.
        
        Returns:
            Current rotation angle
        """
        return self.rotation
        
    def setRotation(self, angle: float):
        """
        Set the rotation angle.
        
        Args:
            angle: New rotation angle
        """
        self.rotation = angle
        
        # Apply rotation transform
        transform = self.transform()
        transform.reset()
        transform.translate(self.width() / 2, self.height() / 2)
        transform.rotate(angle)
        transform.translate(-self.width() / 2, -self.height() / 2)
        
        self.setTransform(transform)
        
    # Define the rotation property for animation
    rotation = pyqtProperty(float, getRotation, setRotation)
    
    def start_animation(self):
        """Start the animation."""
        self.rotation_animation.start()
        
    def stop_animation(self):
        """Stop the animation."""
        self.rotation_animation.stop()
        self.setRotation(0.0)
        
    def set_svg(self, svg_path: str):
        """
        Set a new SVG image.
        
        Args:
            svg_path: Path to SVG file
        """
        self.load(svg_path)
