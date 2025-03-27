"""
Resources for the CyberFox UI.
"""
import os
import tempfile
from pathlib import Path

from PyQt5.QtCore import QDir
from PyQt5.QtGui import QIcon

from cyberfox.config import CONFIG_DIR
from cyberfox.ui.style import ICONS, get_icon_svg, COLORS, Theme

def initialize_resources():
    """Initialize resources for the application."""
    # Create icon directory if it doesn't exist
    icon_dir = Path(CONFIG_DIR) / "icons"
    icon_dir.mkdir(exist_ok=True)
    
    # Generate icon files from SVG definitions
    for name, svg in ICONS.items():
        # Create colored versions
        for theme_name in ["dark", "light"]:
            # Default color
            color = COLORS[theme_name]["primary"]
            
            # Generate SVG file
            svg_path = icon_dir / f"{name}_{theme_name}.svg"
            colored_svg = svg.replace('stroke="currentColor"', f'stroke="{color}"')
            
            with open(svg_path, "w") as f:
                f.write(colored_svg)

def get_icon(name: str, theme: Theme = Theme.DARK) -> QIcon:
    """
    Get an icon by name.
    
    Args:
        name: Name of the icon
        theme: Theme to use for the icon
        
    Returns:
        QIcon object
    """
    # Check if the icon exists in our resources
    icon_path = Path(CONFIG_DIR) / "icons" / f"{name}_{theme.value}.svg"
    
    if icon_path.exists():
        return QIcon(str(icon_path))
    
    # If not found, create it on the fly
    svg = ICONS.get(name)
    if not svg:
        # Return a default icon if the requested one doesn't exist
        svg = ICONS.get("info")
    
    color = COLORS[theme.value]["primary"]
    colored_svg = svg.replace('stroke="currentColor"', f'stroke="{color}"')
    
    # Save to a temporary file
    temp_file = tempfile.NamedTemporaryFile(suffix=".svg", delete=False)
    temp_file.write(colored_svg.encode('utf-8'))
    temp_file.close()
    
    icon = QIcon(temp_file.name)
    
    # Clean up (we can delay the deletion since the icon loads the file)
    os.unlink(temp_file.name)
    
    return icon
