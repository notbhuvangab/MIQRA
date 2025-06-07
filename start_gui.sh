#!/bin/bash

# MAESTRO Threat Assessment Framework - GUI Launcher Script
# This script ensures the virtual environment is activated before launching the GUI

echo "🚀 Starting MAESTRO Threat Assessment Framework GUI..."
echo "============================================================"

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Error: Virtual environment not found."
    echo "Please run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Check if streamlit is installed
if ! python -c "import streamlit" 2>/dev/null; then
    echo "❌ Error: Streamlit not found. Installing dependencies..."
    pip install -r requirements.txt
fi

# Launch the GUI
echo "📱 Launching web interface at: http://localhost:8501"
echo "🌐 The browser should open automatically..."
echo "🛑 Press Ctrl+C to stop the server"
echo "============================================================"

python run_gui.py 