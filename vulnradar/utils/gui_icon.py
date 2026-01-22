# vulnradar/utils/gui_icon
import platform
from pathlib import Path
from typing import Optional
import tkinter as tk

def _get_icon_path() -> Optional[Path]:
    """Get path to appropriate icon file for current platform"""
    
    # Icon directory
    icon_dir = Path(__file__).parent.parent.parent / "assets" / "icons"
    
    system = platform.system()
    
    if system == "Windows":
        icon_path = icon_dir / "logo.ico"
    else:
        # Linux and macOS
        icon_path = icon_dir / "logo.png"
    
    if icon_path.exists():
        return icon_path
    
    # Fallback to any available icon
    for ext in ['.ico', '.png', '.gif']:
        fallback = icon_dir / f"icon{ext}"
        if fallback.exists():
            return fallback
    
    return None

def set_window_icon(window: tk.Tk) -> bool:
    """
    Set custom icon for Tkinter window.
    
    Args:
        window: Tkinter window
        
    Returns:
        True if successful, False otherwise
    """
    try:
        icon_path = _get_icon_path()
        
        if not icon_path:
            print("Warning: No icon file found")
            return False
        
        system = platform.system()
        
        if system == "Windows":
            # Windows uses .ico files
            window.iconbitmap(str(icon_path))
        else:
            # Linux/Mac use PhotoImage
            icon = tk.PhotoImage(file=str(icon_path))
            window.iconphoto(True, icon)
        
        return True
        
    except Exception as e:
        print(f"Warning: Could not set icon: {e}")
        return False