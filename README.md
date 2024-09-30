# Domain Enumeration and Security Scanner

This project performs domain enumeration, subdomain discovery, port scanning, web app detection, and security analysis on domains and subdomains. It integrates multiple tools like HTTPX and Nuclei to identify open ports, gather information about web applications, and check for common vulnerabilities.

## Features

- **Subdomain Enumeration**: Discover subdomains of the given domain.
- **Port Scanning**: Enumerate open ports for each domain and subdomain.
- **Web Application Detection**: Identify web applications running on domains and subdomains.
- **Security Scanning**: Use Nuclei to run security checks on detected web applications.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/your-username/your-project.git
    ```

2. Install the required Python dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Ensure you have **Nmap** installed for port scanning:

    On Linux/macOS:
    ```bash
    sudo apt-get install nmap
    ```
    
    On macOS with Homebrew:
    ```bash
    brew install nmap
    ```

    On Windows:
    [Download Nmap](https://nmap.org/download.html) and follow the installation instructions.

## Usage

To run the script, you need to provide an input file containing domains. The input file should contain a list of domains, one per line.

```bash
python main.py <input_file> [options]


### Command-Line Options

| Option              | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `--no-subdomain`     | Skip subdomain enumeration.                                                  |
| `--no-httpx`         | Skip HTTPX web app detection.                                                |
| `--no-port-scan`     | Skip port scanning.                                                          |
| `--full-port`        | Perform a full port scan (the default scans only top ports).                 |
| `--no-nuclei`        | Skip security scanning with Nuclei.                                          |
| `--no-ip`            | Exclude IP addresses from the final result (replace with domain descriptions).|
| `-h, --help`         | Show this help message and exit.                                             |




This project is licensed under the MIT License.

