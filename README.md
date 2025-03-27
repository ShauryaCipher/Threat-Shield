# CyberFox

![CyberFox Logo](generated-icon.png)

A comprehensive desktop threat detection tool with dark web monitoring, file system scanning, and an animated graphical interface.

## Features

- **Advanced File System Scanning:** Detect malicious files and suspicious patterns on your system with intelligent threat assessment
- **Real-time System Protection:** Monitor file system activities, process creation, network connections, and USB devices in real-time for proactive threat defense
- **Sophisticated Dark Web Monitoring:** Access hidden Tor services to monitor for leaked data and credentials with enhanced anonymity features and circuit isolation
- **Comprehensive Data Breach Detection:** Check emails against known data breaches via Have I Been Pwned with detailed risk assessment
- **Intelligent Browser Analysis:** Detect tracking cookies and suspicious browser data with categorized threat levels
- **Machine Learning Threat Analysis:** Leverage ML algorithms for anomaly detection and threat pattern recognition
- **Interactive Animated UI:** Modern, attractive interface with rich animations and data visualizations
- **Real-time Alerts and Risk Assessment:** Get immediate notifications with detailed threat intelligence when potential risks are detected

## Screenshots

*Note: Screenshots will be added here once you have the application running locally.*

## Installation

### Prerequisites

- Python 3.8 or higher
- Required Python packages (automatically installed via pip):
  - PyQt5 (for the graphical interface)
  - stem (for Tor integration)
  - python-magic (for file type detection)
  - psutil (for system information)
  - pyyaml (for configuration)
  - requests (for API communication)
  - trafilatura (for web scraping)
  - pysocks (for SOCKS proxy support)

### Option 1: Run from Source

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/cyberfox.git
   cd cyberfox
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python run.py
   ```

### Option 2: Install from Executable (Windows)

1. Download the latest executable from the [Releases](https://github.com/yourusername/cyberfox/releases) page.
2. Run the `CyberFox.exe` file.

## Building the Executable

To build an executable yourself:

1. Install all required dependencies:
   ```
   pip install PyQt5 stem python-magic requests pyyaml trafilatura psutil pysocks pyinstaller
   ```

2. Run the build script:
   ```
   python build_exe.py
   ```

3. The executable will be created in the `executable` directory.

4. To share the application with friends, share the entire `executable` directory which contains:
   - The CyberFox.exe file
   - A "Run CyberFox.bat" file for easy launching on Windows
   - The README.md file with usage instructions
   - The application icon

## Using CyberFox

### File Scanning

1. Navigate to the Scan tab
2. Choose between Quick Scan, Full Scan, or Custom Scan
3. View detected threats in the threat log

### Dark Web Monitoring

1. Go to the Dark Web tab
2. Add keywords or email addresses to monitor
3. Start monitoring to receive alerts when your data is found
4. Sophisticated analysis provides detailed threat intelligence including:
   - Language detection and content analysis
   - Sentiment analysis and context extraction
   - Enhanced security with circuit isolation technology
   - Tor-specific optimizations for .onion sites

### Data Breach Checking

1. Open the Breach tab
2. Enter an email address to check
3. View results showing which breaches the email appeared in

### Browser Analysis

1. Navigate to the Browser tab
2. Click "Scan Browsers" to analyze installed browsers
3. Review detected tracking cookies and suspicious data

### Real-time Protection

1. Access the Protection menu from the menu bar
2. Select "Start Real-time Protection" to enable continuous monitoring
3. The system will monitor for:
   - Suspicious file system operations
   - Potentially malicious processes
   - Unusual network connections
   - USB device connections
4. When a threat is detected, you'll receive an immediate alert
5. Real-time protection status is visible in the status bar

## Configuration

Configuration settings are stored in a YAML file and can be modified through the settings interface or by directly editing the file.

## Security Considerations

- **Enhanced Tor Integration**: CyberFox uses Tor for dark web access with advanced features:
  - Circuit isolation technology to enhance anonymity
  - Tor Browser profile mimicking to reduce fingerprinting
  - Intelligent handling of .onion sites
  - Randomized request patterns to avoid detection
- **Comprehensive Metadata Collection**: Detailed metadata is gathered for superior threat intelligence without compromising privacy
- **Sophisticated Content Analysis**: Advanced algorithms perform sentiment analysis and context extraction
- **Elevated Permission Management**: The application requires elevated permissions to scan certain system locations, with careful privilege handling
- **Minimal External Communication**: No data is sent to external servers except for specific API queries (such as Have I Been Pwned)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- The Have I Been Pwned API for data breach information
- Tor Project for providing secure access to dark web services
- Python and PyQt5 teams for the development frameworks