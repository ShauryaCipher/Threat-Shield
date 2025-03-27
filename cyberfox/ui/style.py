"""
Stylesheet and theme definitions for the CyberFox UI.
"""
from enum import Enum
from typing import Dict

class Theme(Enum):
    DARK = "dark"
    LIGHT = "light"
    
# Color palettes
COLORS = {
    "dark": {
        "primary": "#2979ff",
        "secondary": "#5c6bc0",
        "success": "#00c853",
        "warning": "#ffd600",
        "danger": "#ff3d00",
        "info": "#00b0ff",
        "background": "#121212",
        "card": "#1e1e1e",
        "text": "#ffffff",
        "text_secondary": "#b0b0b0",
        "border": "#333333",
        "hover": "#2d2d2d",
        "scanner_active": "#00c853",
        "scanner_inactive": "#b0b0b0",
        "threat_critical": "#ff3d00",
        "threat_high": "#ff9100",
        "threat_medium": "#ffd600",
        "threat_low": "#00b0ff",
    },
    "light": {
        "primary": "#2962ff",
        "secondary": "#304ffe",
        "success": "#00c853",
        "warning": "#ffc400",
        "danger": "#dd2c00",
        "info": "#0091ea",
        "background": "#f5f5f5",
        "card": "#ffffff",
        "text": "#212121",
        "text_secondary": "#757575",
        "border": "#e0e0e0",
        "hover": "#eeeeee",
        "scanner_active": "#00c853",
        "scanner_inactive": "#757575",
        "threat_critical": "#dd2c00",
        "threat_high": "#ff6d00",
        "threat_medium": "#ffc400",
        "threat_low": "#0091ea",
    }
}

def get_stylesheet(theme: Theme = Theme.DARK) -> str:
    """
    Get the stylesheet for the specified theme.
    
    Args:
        theme: The theme to use
        
    Returns:
        CSS stylesheet as a string
    """
    theme_name = theme.value
    colors = COLORS[theme_name]
    
    return f"""
    /* Global Styles */
    QWidget {{
        background-color: {colors["background"]};
        color: {colors["text"]};
        font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif;
        font-size: 10pt;
    }}
    
    /* Main Window */
    QMainWindow {{
        background-color: {colors["background"]};
    }}
    
    /* Menu Bar */
    QMenuBar {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        border-bottom: 1px solid {colors["border"]};
    }}
    
    QMenuBar::item {{
        background-color: transparent;
        padding: 8px 12px;
    }}
    
    QMenuBar::item:selected {{
        background-color: {colors["hover"]};
    }}
    
    /* Menus */
    QMenu {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        border: 1px solid {colors["border"]};
        border-radius: 4px;
        padding: 4px;
    }}
    
    QMenu::item {{
        padding: 6px 24px 6px 12px;
        border-radius: 2px;
    }}
    
    QMenu::item:selected {{
        background-color: {colors["hover"]};
    }}
    
    /* Tab Widget */
    QTabWidget::pane {{
        border: 1px solid {colors["border"]};
        border-radius: 4px;
        background-color: {colors["card"]};
        top: -1px;
    }}
    
    QTabBar::tab {{
        background-color: {colors["background"]};
        color: {colors["text_secondary"]};
        border: 1px solid {colors["border"]};
        border-bottom: none;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
        padding: 8px 16px;
        min-width: 100px;
    }}
    
    QTabBar::tab:selected {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        border-bottom: none;
        margin-bottom: -1px;
    }}
    
    QTabBar::tab:!selected:hover {{
        background-color: {colors["hover"]};
    }}
    
    /* Scroll Areas */
    QScrollArea {{
        border: none;
        background-color: transparent;
    }}
    
    /* Scroll Bar */
    QScrollBar:vertical {{
        background-color: {colors["background"]};
        width: 10px;
        margin: 0px;
        border-radius: 5px;
    }}
    
    QScrollBar::handle:vertical {{
        background-color: {colors["border"]};
        min-height: 20px;
        border-radius: 5px;
    }}
    
    QScrollBar::handle:vertical:hover {{
        background-color: {colors["primary"]};
    }}
    
    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {{
        height: 0px;
    }}
    
    QScrollBar:horizontal {{
        background-color: {colors["background"]};
        height: 10px;
        margin: 0px;
        border-radius: 5px;
    }}
    
    QScrollBar::handle:horizontal {{
        background-color: {colors["border"]};
        min-width: 20px;
        border-radius: 5px;
    }}
    
    QScrollBar::handle:horizontal:hover {{
        background-color: {colors["primary"]};
    }}
    
    QScrollBar::add-line:horizontal,
    QScrollBar::sub-line:horizontal {{
        width: 0px;
    }}
    
    /* Buttons */
    QPushButton {{
        background-color: {colors["primary"]};
        color: white;
        border: none;
        border-radius: 4px;
        padding: 8px 16px;
        min-width: 80px;
        font-weight: bold;
    }}
    
    QPushButton:hover {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                          stop:0 {colors["primary"]}, stop:1 #{colors["primary"][1:]}aa);
    }}
    
    QPushButton:pressed {{
        background-color: #{colors["primary"][1:]}cc;
    }}
    
    QPushButton:disabled {{
        background-color: {colors["border"]};
        color: {colors["text_secondary"]};
    }}
    
    QPushButton#dangerButton {{
        background-color: {colors["danger"]};
    }}
    
    QPushButton#dangerButton:hover {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                          stop:0 {colors["danger"]}, stop:1 #{colors["danger"][1:]}aa);
    }}
    
    QPushButton#dangerButton:pressed {{
        background-color: #{colors["danger"][1:]}cc;
    }}
    
    QPushButton#successButton {{
        background-color: {colors["success"]};
    }}
    
    QPushButton#successButton:hover {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                          stop:0 {colors["success"]}, stop:1 #{colors["success"][1:]}aa);
    }}
    
    QPushButton#successButton:pressed {{
        background-color: #{colors["success"][1:]}cc;
    }}
    
    QPushButton#warningButton {{
        background-color: {colors["warning"]};
        color: #212121;
    }}
    
    QPushButton#warningButton:hover {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                         stop:0 {colors["warning"]}, stop:1 #{colors["warning"][1:]}aa);
    }}
    
    QPushButton#warningButton:pressed {{
        background-color: #{colors["warning"][1:]}cc;
    }}
    
    /* Line Edit */
    QLineEdit {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        border: 1px solid {colors["border"]};
        border-radius: 4px;
        padding: 8px;
    }}
    
    QLineEdit:focus {{
        border: 1px solid {colors["primary"]};
    }}
    
    /* Group Box */
    QGroupBox {{
        border: 1px solid {colors["border"]};
        border-radius: 4px;
        margin-top: 16px;
        padding-top: 16px;
        font-weight: bold;
    }}
    
    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 8px;
        padding: 0 5px;
    }}
    
    /* Labels */
    QLabel {{
        color: {colors["text"]};
    }}
    
    QLabel#headingLabel {{
        font-size: 18pt;
        font-weight: bold;
    }}
    
    QLabel#subheadingLabel {{
        font-size: 14pt;
        color: {colors["text_secondary"]};
    }}
    
    QLabel#infoLabel {{
        color: {colors["info"]};
    }}
    
    QLabel#warningLabel {{
        color: {colors["warning"]};
    }}
    
    QLabel#errorLabel {{
        color: {colors["danger"]};
    }}
    
    QLabel#successLabel {{
        color: {colors["success"]};
    }}
    
    /* Progress Bar */
    QProgressBar {{
        border: 1px solid {colors["border"]};
        border-radius: 4px;
        text-align: center;
        background-color: {colors["card"]};
        height: 20px;
    }}
    
    QProgressBar::chunk {{
        background-color: {colors["primary"]};
        border-radius: 3px;
    }}
    
    QProgressBar#scanProgressBar::chunk {{
        background-color: {colors["scanner_active"]};
    }}
    
    /* Text Edit and Plain Text Edit */
    QTextEdit, QPlainTextEdit {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        border: 1px solid {colors["border"]};
        border-radius: 4px;
        padding: 4px;
    }}
    
    /* List Widget */
    QListWidget {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        border: 1px solid {colors["border"]};
        border-radius: 4px;
        outline: none;
        padding: 4px;
    }}
    
    QListWidget::item {{
        border-radius: 2px;
        padding: 8px;
        margin: 2px 0;
    }}
    
    QListWidget::item:selected {{
        background-color: {colors["primary"]};
        color: white;
    }}
    
    QListWidget::item:hover:!selected {{
        background-color: {colors["hover"]};
    }}
    
    /* Tree Widget */
    QTreeWidget {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        border: 1px solid {colors["border"]};
        border-radius: 4px;
        outline: none;
    }}
    
    QTreeWidget::item {{
        min-height: 30px;
        border-radius: 2px;
        padding: 4px;
    }}
    
    QTreeWidget::item:selected {{
        background-color: {colors["primary"]};
        color: white;
    }}
    
    QTreeWidget::item:hover:!selected {{
        background-color: {colors["hover"]};
    }}
    
    /* Table Widget */
    QTableWidget {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        border: 1px solid {colors["border"]};
        border-radius: 4px;
        gridline-color: {colors["border"]};
        outline: none;
    }}
    
    QTableWidget::item {{
        padding: 8px;
    }}
    
    QTableWidget::item:selected {{
        background-color: {colors["primary"]};
        color: white;
    }}
    
    QHeaderView::section {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        padding: 8px;
        border: 1px solid {colors["border"]};
        border-top-width: 0;
        border-left-width: 0;
        border-right-width: 1px;
        border-bottom-width: 1px;
    }}
    
    /* Check Box */
    QCheckBox {{
        spacing: 8px;
    }}
    
    QCheckBox::indicator {{
        width: 18px;
        height: 18px;
        border: 1px solid {colors["border"]};
        border-radius: 2px;
    }}
    
    QCheckBox::indicator:unchecked {{
        background-color: {colors["card"]};
    }}
    
    QCheckBox::indicator:checked {{
        background-color: {colors["primary"]};
        image: url(":/icons/check.svg");
    }}
    
    /* Radio Button */
    QRadioButton {{
        spacing: 8px;
    }}
    
    QRadioButton::indicator {{
        width: 18px;
        height: 18px;
        border: 1px solid {colors["border"]};
        border-radius: 9px;
    }}
    
    QRadioButton::indicator:unchecked {{
        background-color: {colors["card"]};
    }}
    
    QRadioButton::indicator:checked {{
        background-color: {colors["primary"]};
        image: url(":/icons/circle.svg");
    }}
    
    /* Combo Box */
    QComboBox {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        border: 1px solid {colors["border"]};
        border-radius: 4px;
        padding: 8px;
        min-width: 120px;
    }}
    
    QComboBox:editable {{
        background-color: {colors["card"]};
    }}
    
    QComboBox:!editable, QComboBox::drop-down:editable {{
        background-color: {colors["card"]};
    }}
    
    QComboBox:!editable:on, QComboBox::drop-down:editable:on {{
        background-color: {colors["hover"]};
    }}
    
    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: center right;
        width: 24px;
        border-left: 1px solid {colors["border"]};
    }}
    
    QComboBox::down-arrow {{
        image: url(":/icons/chevron-down.svg");
        width: 16px;
        height: 16px;
    }}
    
    QComboBox QAbstractItemView {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        border: 1px solid {colors["border"]};
        selection-background-color: {colors["primary"]};
        selection-color: white;
        border-radius: 4px;
    }}
    
    /* Tool Button */
    QToolButton {{
        background-color: transparent;
        border-radius: 4px;
        padding: 4px;
    }}
    
    QToolButton:hover {{
        background-color: {colors["hover"]};
    }}
    
    QToolButton:pressed {{
        background-color: {colors["border"]};
    }}
    
    /* Dialogs */
    QDialog {{
        background-color: {colors["background"]};
        color: {colors["text"]};
    }}
    
    /* Status Bar */
    QStatusBar {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        border-top: 1px solid {colors["border"]};
    }}
    
    /* Tooltip */
    QToolTip {{
        background-color: {colors["card"]};
        color: {colors["text"]};
        border: 1px solid {colors["border"]};
        padding: 6px;
        border-radius: 2px;
    }}
    
    /* Custom Widgets */
    QWidget#cardWidget {{
        background-color: {colors["card"]};
        border-radius: 8px;
        border: 1px solid {colors["border"]};
    }}
    
    QWidget#threatCard {{
        border-left: 5px solid {colors["primary"]};
        background-color: {colors["card"]};
        border-top-right-radius: 8px;
        border-bottom-right-radius: 8px;
        border-top: 1px solid {colors["border"]};
        border-right: 1px solid {colors["border"]};
        border-bottom: 1px solid {colors["border"]};
    }}
    
    QWidget#threatCard[threat_level="critical"] {{
        border-left: 5px solid {colors["threat_critical"]};
    }}
    
    QWidget#threatCard[threat_level="high"] {{
        border-left: 5px solid {colors["threat_high"]};
    }}
    
    QWidget#threatCard[threat_level="medium"] {{
        border-left: 5px solid {colors["threat_medium"]};
    }}
    
    QWidget#threatCard[threat_level="low"] {{
        border-left: 5px solid {colors["threat_low"]};
    }}
    """

# SVG Icons
ICONS = {
    "shield": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-shield"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>""",
    "shield-off": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-shield-off"><path d="M19.69 14a6.9 6.9 0 0 0 .31-2V5l-8-3-3.16 1.18"></path><path d="M4.73 4.73L4 5v7c0 6 8 10 8 10a20.29 20.29 0 0 0 5.62-4.38"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>""",
    "alert-triangle": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-alert-triangle"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>""",
    "alert-circle": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-alert-circle"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>""",
    "activity": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-activity"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>""",
    "settings": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-settings"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>""",
    "file": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-file"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>""",
    "globe": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-globe"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>""",
    "hard-drive": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-hard-drive"><line x1="22" y1="12" x2="2" y2="12"></line><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path><line x1="6" y1="16" x2="6.01" y2="16"></line><line x1="10" y1="16" x2="10.01" y2="16"></line></svg>""",
    "trash": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-trash"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>""",
    "refresh-cw": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-refresh-cw"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>""",
    "eye": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-eye"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>""",
    "eye-off": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-eye-off"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>""",
    "search": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>""",
    "check": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-check"><polyline points="20 6 9 17 4 12"></polyline></svg>""",
    "x": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-x"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>""",
    "info": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-info"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>""",
    "mail": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-mail"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>""",
    "home": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-home"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>""",
    "user": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-user"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>""",
    "zap": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-zap"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>""",
    "lock": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-lock"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>""",
    "unlock": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-unlock"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg>""",
    "wifi": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-wifi"><path d="M5 12.55a11 11 0 0 1 14.08 0"></path><path d="M1.42 9a16 16 0 0 1 21.16 0"></path><path d="M8.53 16.11a6 6 0 0 1 6.95 0"></path><line x1="12" y1="20" x2="12.01" y2="20"></line></svg>""",
    "wifi-off": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-wifi-off"><line x1="1" y1="1" x2="23" y2="23"></line><path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55"></path><path d="M5 12.55a10.94 10.94 0 0 1 5.17-2.39"></path><path d="M10.71 5.05A16 16 0 0 1 22.58 9"></path><path d="M1.42 9a15.91 15.91 0 0 1 4.7-2.88"></path><path d="M8.53 16.11a6 6 0 0 1 6.95 0"></path><line x1="12" y1="20" x2="12.01" y2="20"></line></svg>""",
    "download": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-download"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>""",
    "upload": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-upload"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>""",
    "plus": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-plus"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>""",
    "minus": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-minus"><line x1="5" y1="12" x2="19" y2="12"></line></svg>""",
    "circle": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-circle"><circle cx="12" cy="12" r="10"></circle></svg>""",
    "chevron-down": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-chevron-down"><polyline points="6 9 12 15 18 9"></polyline></svg>""",
    "chevron-up": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-chevron-up"><polyline points="18 15 12 9 6 15"></polyline></svg>""",
    "chevron-right": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-chevron-right"><polyline points="9 18 15 12 9 6"></polyline></svg>""",
    "chevron-left": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-chevron-left"><polyline points="15 18 9 12 15 6"></polyline></svg>""",
}

# Logo as SVG
LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200">
    <style>
        @keyframes pulse {
            0% { transform: scale(1); opacity: 0.8; }
            50% { transform: scale(1.05); opacity: 1; }
            100% { transform: scale(1); opacity: 0.8; }
        }
        .pulse {
            animation: pulse 2s infinite ease-in-out;
        }
        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        .rotate {
            animation: rotate 8s linear infinite;
            transform-origin: center;
        }
    </style>
    
    <!-- Outer shield shape -->
    <path class="rotate" d="M100 20c-44.1 0-80 35.9-80 80s35.9 80 80 80 80-35.9 80-80-35.9-80-80-80zm0 150c-38.6 0-70-31.4-70-70s31.4-70 70-70 70 31.4 70 70-31.4 70-70 70z" fill="#2979ff"/>
    
    <!-- Inner shield -->
    <path class="pulse" d="M100 40L60 55v45c0 35.3 17 51.3 40 60 23-8.7 40-24.7 40-60V55l-40-15z" fill="#5c6bc0"/>
    
    <!-- Fox ears -->
    <path d="M80 85l-20-35 30 20-10 15zM120 85l20-35-30 20 10 15z" fill="#ff7043"/>
    
    <!-- Fox face -->
    <path d="M100 110c-16.6 0-30-13.4-30-30s13.4-30 30-30 30 13.4 30 30-13.4 30-30 30z" fill="#ff9e80"/>
    
    <!-- Fox eyes -->
    <circle cx="85" cy="75" r="5" fill="#263238"/>
    <circle cx="115" cy="75" r="5" fill="#263238"/>
    
    <!-- Fox nose -->
    <path d="M100 85l-5 10h10l-5-10z" fill="#263238"/>
</svg>
"""

# Splash screen animation
SPLASH_ANIMATION = """<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300" viewBox="0 0 400 300">
    <style>
        @keyframes fadeIn {
            0% { opacity: 0; }
            100% { opacity: 1; }
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        @keyframes pulse {
            0% { transform: scale(1); opacity: 0.8; }
            50% { transform: scale(1.05); opacity: 1; }
            100% { transform: scale(1); opacity: 0.8; }
        }
        @keyframes dash {
            0% { stroke-dashoffset: 1000; }
            100% { stroke-dashoffset: 0; }
        }
        .logo {
            animation: fadeIn 1s ease-out forwards;
        }
        .shield-outer {
            animation: spin 8s linear infinite;
            transform-origin: 200px 150px;
        }
        .shield-inner {
            animation: pulse 2s infinite ease-in-out;
        }
        .text {
            animation: fadeIn 2s ease-out forwards;
            opacity: 0;
            animation-delay: 0.5s;
        }
        .scan-line {
            stroke-dasharray: 1000;
            stroke-dashoffset: 1000;
            animation: dash 3s linear infinite;
        }
    </style>

    <!-- Background -->
    <rect width="400" height="300" rx="20" fill="#121212"/>
    
    <!-- Logo -->
    <g class="logo">
        <!-- Outer shield -->
        <circle class="shield-outer" cx="200" cy="150" r="80" fill="none" stroke="#2979ff" stroke-width="5"/>
        
        <!-- Inner shield -->
        <path class="shield-inner" d="M200 100l-40 15v45c0 35.3 17 45.3 40 54 23-8.7 40-18.7 40-54v-45l-40-15z" fill="#5c6bc0"/>
        
        <!-- Fox elements -->
        <path d="M180 145l-20-35 30 20-10 15z" fill="#ff7043"/> <!-- Left ear -->
        <path d="M220 145l20-35-30 20 10 15z" fill="#ff7043"/> <!-- Right ear -->
        <path d="M200 170c-16.6 0-30-13.4-30-30s13.4-30 30-30 30 13.4 30 30-13.4 30-30 30z" fill="#ff9e80"/> <!-- Face -->
        <circle cx="185" cy="135" r="5" fill="#263238"/> <!-- Left eye -->
        <circle cx="215" cy="135" r="5" fill="#263238"/> <!-- Right eye -->
        <path d="M200 145l-5 10h10l-5-10z" fill="#263238"/> <!-- Nose -->
        
        <!-- Scanning effect -->
        <line class="scan-line" x1="120" y1="150" x2="280" y2="150" stroke="#00c853" stroke-width="2"/>
    </g>
    
    <!-- Text -->
    <g class="text">
        <text x="200" y="240" fill="#ffffff" font-family="Arial" font-size="24" text-anchor="middle" font-weight="bold">CyberFox</text>
        <text x="200" y="265" fill="#b0b0b0" font-family="Arial" font-size="14" text-anchor="middle">Advanced Threat Detection</text>
    </g>
</svg>
"""

def get_icon_svg(icon_name: str, color: str = None) -> str:
    """
    Get an SVG icon with optional color.
    
    Args:
        icon_name: Name of the icon to retrieve
        color: Color to apply to the icon
        
    Returns:
        SVG string for the icon
    """
    if icon_name not in ICONS:
        return ICONS["alert-circle"]
        
    svg = ICONS[icon_name]
    
    if color:
        # Replace the stroke color
        svg = svg.replace('stroke="currentColor"', f'stroke="{color}"')
        
    return svg

def get_logo_svg() -> str:
    """Get the logo SVG."""
    return LOGO_SVG

def get_splash_animation() -> str:
    """Get the splash screen animation SVG."""
    return SPLASH_ANIMATION
