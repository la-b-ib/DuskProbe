#!/bin/bash
# DuskProbe v4.5 - Installation Script
# Author: Labib Bin Shahed

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_colored() {
    echo -e "${1}${2}${NC}"
}

print_colored $CYAN "🛡️  DuskProbe v4.5 - Installation Script"
print_colored $CYAN "======================================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    print_colored $RED "❌ Python 3 is not installed!"
    print_colored $YELLOW "Please install Python 3.8 or higher from https://python.org"
    exit 1
fi

# Check Python version
python_version=$(python3 -c "import sys; print('.'.join(map(str, sys.version_info[:2])))")
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    print_colored $RED "❌ Python 3.8+ required, found $python_version"
    exit 1
fi

print_colored $GREEN "✅ Python $python_version found"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    print_colored $RED "❌ pip3 is not installed!"
    print_colored $YELLOW "Installing pip..."
    python3 -m ensurepip --upgrade
fi

print_colored $GREEN "✅ pip3 found"

# Install required dependencies
print_colored $BLUE "📦 Installing required dependencies..."
pip3 install -r requirements.txt

# Check if Tor is available (optional)
if command -v tor &> /dev/null; then
    print_colored $GREEN "✅ Tor found - anonymity features available"
else
    print_colored $YELLOW "⚠️  Tor not found - anonymity features will be disabled"
    print_colored $YELLOW "   Install Tor for enhanced privacy:"
    print_colored $YELLOW "   - macOS: brew install tor"
    print_colored $YELLOW "   - Ubuntu/Debian: sudo apt-get install tor"
    print_colored $YELLOW "   - CentOS/RHEL: sudo yum install tor"
fi

# Make the script executable
chmod +x duskprobe.py

print_colored $GREEN "✅ Installation completed successfully!"
print_colored $CYAN ""
print_colored $CYAN "Usage examples:"
print_colored $CYAN "  ./duskprobe.py https://example.com"
print_colored $CYAN "  ./duskprobe.py https://example.com --crawl --output-format json"
print_colored $CYAN "  ./duskprobe.py --batch urls.txt --quiet --export"
print_colored $CYAN "  ./duskprobe.py --help"
print_colored $CYAN ""
print_colored $YELLOW "⚠️  IMPORTANT: Only scan websites you own or have explicit permission to test!"
print_colored $CYAN ""