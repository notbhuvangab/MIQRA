#!/usr/bin/env python3
"""
MAESTRO Threat Assessment Framework - GUI Launcher
Simple script to launch the Streamlit web interface
"""

import os
import sys
import subprocess

def main():
    """Launch the MAESTRO Streamlit GUI"""
    
    print("🚀 Starting MAESTRO Threat Assessment Framework GUI...")
    print("=" * 60)
    
    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Path to the Streamlit app
    app_path = os.path.join(script_dir, "src", "maestro_threat_assessment", "web", "streamlit_app.py")
    
    # Check if the app file exists
    if not os.path.exists(app_path):
        print(f"❌ Error: Streamlit app not found at {app_path}")
        print("Please ensure the GUI files are properly installed.")
        return 1
    
    # Launch Streamlit
    try:
        print(f"📱 Launching web interface at: http://localhost:8501")
        print("🌐 The browser should open automatically...")
        print("🛑 Press Ctrl+C to stop the server")
        print("=" * 60)
        
        # Run streamlit
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", app_path,
            "--server.port", "8501",
            "--server.address", "localhost",
            "--browser.gatherUsageStats", "false"
        ])
        
    except KeyboardInterrupt:
        print("\n🛑 MAESTRO GUI stopped by user")
        return 0
    except Exception as e:
        print(f"❌ Error launching GUI: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 