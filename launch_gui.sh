#!/bin/bash
# Launch Password Security Toolkit GUI

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔐 Starting Password Security Toolkit..."
echo "   GUI will open at http://localhost:8501"
echo ""

# Use virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate

    # Check if streamlit is installed in venv
    if ! python -c "import streamlit" 2>/dev/null; then
        echo "Installing dependencies in virtual environment..."
        pip install -r requirements.txt
    fi

    cd src
    streamlit run app.py --server.headless true
else
    echo "Setting up virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

    cd src
    streamlit run app.py --server.headless true
fi
