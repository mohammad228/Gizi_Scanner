import sys
import os
import zipfile
import urllib.request
import shutil
import hashlib
from database_manager import DatabaseManager
from file_processor import FileProcessor
from script_executor import ScriptExecutor
from report_generator import ReportGenerator
import socket
import zipfile
from datetime import datetime


def calculate_checksum(file_path):
    """
    Calculate the SHA256 checksum of a file.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def download_tool(url, destination):
    """
    Download a file from the given URL and save it to the specified destination.
    """
    socket.setdefaulttimeout(300)

    try:
        print(f"[INFO] Downloading {url.split('/')[-1]}...")
        urllib.request.urlretrieve(url, destination)
        print(f"[INFO] Downloaded {url.split('/')[-1]} successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to download {url.split('/')[-1]}: {e}")

def extract_zip(zip_path, extract_to):
    """
    Extract a ZIP file to the specified directory.
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        print(f"[INFO] Extracted {zip_path} to {extract_to}")
        os.remove(zip_path)
    except Exception as e:
        print(f"[ERROR] Failed to extract {zip_path}: {e}")


def verify_and_setup_tool(tool, url, binary_path, destination, checksum):
    """
    Verify the existence and checksum of the binary tool. Download and extract if necessary.
    """
    if os.path.exists(binary_path):
        print(f"[INFO] {tool} binary already exists. Verifying checksum...")
        
        if calculate_checksum(binary_path) == checksum:
            print(f"[INFO] {tool} binary checksum verified successfully.")
            return
        else:
            print(f"[ERROR] {tool} binary checksum verification failed. Exiting program.")
            sys.exit(1)

    print(f"[INFO] {tool} binary not found. Downloading...")
    download_tool(url, destination)
    extract_zip(destination, os.path.dirname(binary_path))

    if os.path.exists(binary_path) and calculate_checksum(binary_path) == checksum:
        print(f"[INFO] {tool} downloaded, extracted, and verified successfully.")
        os.chmod(binary_path, 0o755)  # rwxr-xr-x permissions
        print(f"[INFO] Executable permission granted for {binary_path}")
    else:
        print(f"[ERROR] {tool} failed checksum verification after extraction. Exiting program.")
        sys.exit(1)


def setup_tools():
    """
    Download and set up required tools in the 'utils' directory.
    """
    utils_dir = 'utils'
    os.makedirs(utils_dir, exist_ok=True)

    tools = {
        "httpx": {
            "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_linux_amd64.zip",
            "checksum": "e023fd4cac81608fbab2ca783f3ec85d86cea21117ade13f34d199f4c6ea739c"
        },
        "subfinder": {
            "url": "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip",
            "checksum": "7b789e46a30a8a2b9342bfab99b8ae73b0fe2d632ca547766cdf0a0984cb1995"
        },
        "naabu": {
            "url": "https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip",
            "checksum": "e36c3fa44f6b9d91696a03dd180b340ad62aa18777ce9839ece7317b639b1e2a"
        },
        "nuclei": {
            "url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.2/nuclei_3.3.2_linux_amd64.zip",
            "checksum": "29e7e3f486f428916cf43dca588070a64a6059fcabeb7be30431dfdf42592b13"
        }
    }

    for tool, info in tools.items():
        binary_path = os.path.join(utils_dir, tool)
        zip_path = os.path.join(utils_dir, f"{tool}.zip")
        verify_and_setup_tool(tool, info["url"], binary_path, zip_path, info["checksum"])

    if shutil.which("nmap") is None:
        print("[WARNING] 'nmap' is not installed. Please install 'nmap' to use this tool properly.")


def zip_and_cleanup_result_directory(result_dir='result'):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    zip_file = f"{result_dir}_{timestamp}.zip"
        
    with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(result_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, result_dir)  
                zipf.write(file_path, arcname)
    
    print(f"[INFO] All files in '{result_dir}' have been zipped into {zip_file}")

    for root, dirs, files in os.walk(result_dir):
        for file in files:
            if not file.startswith('.')and not file.endswith('.html'):  
                file_path = os.path.join(root, file)
                os.remove(file_path) 
                print(f"[INFO] Removed file: {file_path}")
    
    print(f"[INFO] All non-hidden files in '{result_dir}' have been removed but the directory structure is preserved.")



def main(input_file, options):
    setup_tools()  

    db_file = "result/scan_results.db"
    db_manager = DatabaseManager(db_file)
    db_manager.create_tables()

    file_processor = FileProcessor(input_file)
    domains_with_descriptions = file_processor.process_file()

    print("\n[DEBUG] Domains with Descriptions:")
    for domain, description in domains_with_descriptions:
        print(f"Domain: {domain}, Description: {description}")
    # print(options)
    script_executor = ScriptExecutor(db_manager, options)
    script_executor.execute(domains_with_descriptions)

    nmap_results = db_manager.get_all_results()

    

    httpx_results = db_manager.get_all_httpx_results()

    

    vulnerabilities = db_manager.get_all_vulnerabilities()

    
    print(domains_with_descriptions)
    report_generator = ReportGenerator()
    report_generator.generate_html_report(nmap_results, httpx_results, vulnerabilities, options, domains_with_descriptions)

    db_manager.close()
    zip_and_cleanup_result_directory()


if __name__ == "__main__":
    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv:
        print("Usage: python main.py <input_file> [options]")
        print("Options:")
        print("  --no-subdomain        Skip subdomain enumeration")
        print("  --no-httpx            Skip HTTPX scan")
        print("  --no-port-scan        Skip port scan")
        print("  --full-port           Perform full port scan (default is top ports)")
        print("  --no-nuclei           Skip nuclei scan")
        print("  --no-ip               Exclude IP addresses from the final result")
        print("  -h, --help            Show this help message and exit")

        sys.exit(1)

    input_file = sys.argv[1]

    options = {
        'subdomain': '--no-subdomain' not in sys.argv,
        'httpx': '--no-httpx' not in sys.argv,
        'port_scan': '--no-port-scan' not in sys.argv,
        'full_port_scan': '--full-port' in sys.argv,
        'nuclei': '--no-nuclei' not in sys.argv,
        'exclude_ip': '--no-ip' in sys.argv

    }

    main(input_file, options)
