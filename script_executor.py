import subprocess
import os
import re  
import time
import json
from CORScanner.cors_scan import cors_check

class ScriptExecutor:
    def __init__(self, db_manager, options):
        self.subfinder_path = os.path.join("utils", "subfinder")
        self.naabu_path = os.path.join("utils", "naabu")
        self.result_dir = "result"
        self.naabu_output_file = os.path.expanduser("result/all_naabu_results.txt")
        self.nmap_output_file = os.path.expanduser("result/all_nmap_results.txt")
        self.db_manager = db_manager
        self.options = options

        if not os.path.exists(self.result_dir):
            os.makedirs(self.result_dir)

        if not os.path.exists(os.path.dirname(self.naabu_output_file)):
            os.makedirs(os.path.dirname(self.naabu_output_file))

    def execute(self, domains_with_descriptions):
        for domain, description in domains_with_descriptions:
            try:
                domain_id = self.db_manager.insert_domain(domain, description)
                output_file = os.path.join(self.result_dir, f"{domain}_result.txt")
                
                with open(output_file, 'w') as file:
                    file.write(f"{domain}\n")
                
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                    print(f"[INFO] Detected IP address format for {domain}. Skipping subdomain enumeration.")
                
                else:
                    
                    if self.options['subdomain']:
                        subfinder_command = [self.subfinder_path, "-all", "-d", domain, "-o", output_file]
                        subprocess.run(subfinder_command, capture_output=True, text=True)
                        print(f"Subfinder completed for domain {domain}")
                    else:
                        print("[INFO] Skipping subdomain enumeration.")

                if self.options['port_scan']:
                    if self.options['full_port_scan']:
                        self.run_nmap_on_results(domain_id, output_file)
                    else:
                        self.run_naabu_on_results(domain_id, output_file)
                else:
                    print("[INFO] Skipping port scan.")

                if self.options['httpx']:
                    self.run_httpx_on_results(domain_id, output_file)
                else:
                    print("[INFO] Skipping HTTPX scan.")
                
                

            except Exception as e:
                print(f"Failed to execute commands for domain {domain}: {e}")
        self.check_cors_misconfigurations()
        
        if self.options['nuclei']:
            self.run_nuclei_scan_on_httpx_results()
        else:
            print("[INFO] Skipping Nuclei scan.")

    def run_naabu_on_results(self, domain_id, result_file):
        try:
            with open(result_file, 'r') as file:
                for domain in file:
                    domain = domain.strip()
                    if domain:
                        naabu_command = [self.naabu_path, "-top-ports", "1000", "--host", domain]
                        result = subprocess.run(naabu_command, capture_output=True, text=True)
                        naabu_output = result.stdout

                        with open(self.naabu_output_file, 'a') as naabu_file:
                            naabu_file.write(f"Results for domain {domain}:\n")
                            naabu_file.write(naabu_output)
                            naabu_file.write("\n\n")

                        print(f"Naabu completed for domain {domain} and saved to {self.naabu_output_file}")

                        # Check if the naabu_output contains open ports
                        self.db_manager.insert_results(domain_id, domain, naabu_output.strip(), "N/A")
                        
        except Exception as e:
            print(f"Failed to run Naabu on results from {result_file}: {e}")

    def run_nmap_on_results(self, domain_id, result_file):
        try:
            combined_output_file = f"{self.result_dir}/all_domains_nmap_combined.txt"

            with open(result_file, 'r') as file:
                for domain in file:
                    domain = domain.strip()
                    if domain:
                        scan_types = {
                            "SYN Scan": "-sS",
                            "TCP Connect Scan": "-sT",
                            "UDP Scan": "-sU",
                            "FIN Scan": "-sF",
                            "ACK Scan": "-sA"
                        }
                        
                        accumulated_nmap_output = f"Results for domain {domain}:\n"

                        found_open_ports = False

                        for scan_name, scan_flag in scan_types.items():
                            time.sleep(1)
                            nmap_command = [
                                "nmap", scan_flag, "-T5", domain
                            ]
                            result = subprocess.run(nmap_command, capture_output=True, text=True)
                            nmap_output = result.stdout
                            
                            accumulated_nmap_output += f"\nScan Type: {scan_name}\n"
                            accumulated_nmap_output += nmap_output + "\n"

                            print(f"Nmap {scan_name} completed for domain {domain}.")
                            
                            port_service_pairs = self.parse_nmap_output(nmap_output)

                            if port_service_pairs:
                                found_open_ports = True
                                for port, service in port_service_pairs:
                                    self.db_manager.insert_results(domain_id, domain, port, service)

                        if not found_open_ports:
                            self.db_manager.insert_results(domain_id, domain, "No open ports found", None)

                        with open(combined_output_file, 'a') as nmap_file:
                            nmap_file.write(accumulated_nmap_output)
                            nmap_file.write("\n" + "="*50 + "\n")

                        print(f"Nmap results for domain {domain} accumulated in {combined_output_file}")

        except Exception as e:
            print(f"Failed to run Nmap on results from {result_file}: {e}")



    def parse_nmap_output(self, nmap_output):
        """
        Parse the Nmap output and extract the ports and services.
        Return a list of tuples containing port and service pairs.
        """
        port_service_pattern = re.compile(r"(\d+/\w+)\s+open\s+(\S+)")
        matches = port_service_pattern.findall(nmap_output)

        if matches:
            print("\n[Parsed Nmap Results]")
            for port, service in matches:
                print(f"Port: {port}, Service: {service}")
            return matches
        else:
            print("No open ports found in the Nmap output.")
            return []





    def run_httpx_on_results(self, domain_id, result_file):
        try:
            with open(result_file, 'r') as file:
                
                httpx_dir = os.path.join(self.result_dir, "httpx")
                os.makedirs(httpx_dir, exist_ok=True)
                for domain in file:
                    domain = domain.strip()
                    if domain:

                        httpx_output_file = os.path.join(self.result_dir + "/httpx", f"{domain}_httpx.json")
                        httpx_command = [
                            "utils/httpx", "-u", domain, "-delay", "1s", "-silent", "-j", "-o", httpx_output_file,
                            "-fr", "-ip", "-sc", "200,302,301,404,402,403,401"
                        ]
                        result = subprocess.run(httpx_command, capture_output=True, text=True)

                        if result.returncode == 0:
                            httpx_output = result.stdout

                            try:
                                httpx_data = json.loads(httpx_output)

                                port = httpx_data.get("port", "N/A")
                                webserver = httpx_data.get("webserver", "N/A")
                                url = httpx_data.get("url", "N/A")
                                final_url = httpx_data.get("final_url") or url
                                host = httpx_data.get("host", "N/A")
                                tech = ", ".join(httpx_data.get("tech", []))

                                print(f"\n[HTTPX Results for {domain}]")
                                print(f"Port: {port}")
                                print(f"Webserver: {webserver}")
                                print(f"Final URL: {final_url}")
                                print(f"Host: {host}")
                                print(f"Tech: {tech}")

                                self.db_manager.insert_httpx(domain_id, domain, port, webserver, final_url, host, tech, False)

                            except json.JSONDecodeError as e:
                                print(f"Failed to decode JSON for domain {domain}: {e}")
                        else:
                            print(f"HTTPX failed for domain {domain}")

        except Exception as e:
            print(f"Failed to run HTTPX on results from {result_file}: {e}")


    def run_vulnerability_scan_on_httpx_results(self):
        try:
            httpx_results = self.db_manager.get_all_httpx_results()

            for result in httpx_results:
                domain = result[2]
                
                if domain:
                    print(f"\n[INFO] Running Nmap DoS scan on {domain}...")

                    nmap_command = [
                        "nmap", "--script", "dos", "-Pn", domain
                    ]
                    result = subprocess.run(nmap_command, capture_output=True, text=True)

                    if result.returncode == 0:
                        nmap_output = result.stdout
                        print(f"\n[Nmap DoS Scan Results for {domain}]\n{nmap_output}")

                        nmap_output_file = os.path.join(self.result_dir, f"{domain}_nmap_dos_scan.txt")
                        with open(nmap_output_file, 'w') as output_file:
                            output_file.write(nmap_output)

                    else:
                        print(f"Nmap DoS scan failed for domain {domain}")

        except Exception as e:
            print(f"Failed to run Nmap DoS scan on HTTPX results: {e}")


    def check_cors_misconfigurations(self):
        try:
            httpx_results = self.db_manager.get_all_httpx_results()

            for row in httpx_results:
                domain_id = row[1]
                subdomain = row[2]
                final_url = row[5]
                print(final_url)
                if final_url:
                    print(f"\n[INFO] Checking CORS misconfiguration for {final_url}...")

                    ret = cors_check(final_url, None)

                    if ret:
                        vulnerability = "CORS Misconfiguration"
                        severity = "Medium"

                        if ret.get("credentials") == "true":
                            severity = "High"

                        self.db_manager.insert_vulnerability(subdomain, final_url, vulnerability, severity, "CORS")

                        print(f"[CORS Misconfiguration Detected] {final_url} is vulnerable with severity: {severity}.")
                    else:
                        print(f"[No CORS Misconfiguration] {final_url} appears to be safe.")
                else:
                    print(f"[Skipped] No final URL found for subdomain: {subdomain}")
            self.db_manager.get_all_vulnerabilities()
        except Exception as e:
            print(f"Failed to check CORS misconfigurations: {e}")



    def run_nuclei_scan_on_httpx_results(self):
            """
            Run Nuclei scans on all subdomains from the HTTPX results table.
            """
            try:
                httpx_results = self.db_manager.get_all_httpx_results()
                # print("Nucleiiiiiiiiiii Scan")
                for result in httpx_results:
                    domain = result[2]
                    domain_id = result[0]
                    # scanned = result[8]
                    # if scanned:
                    #     print(f"\n[Debug] Skipping Nuclei scan for {domain} as it has already been scanned.")
                    #     continue
                    if domain:
                        
                        output_file_path = os.path.join(self.result_dir, f"{domain}_nuclei_output.jsonl")
                        # print("OutPuttttttttttttttttt filee", output_file_path)
                        print(f"[INFO] Running Nuclei scan for domain: {domain}")

                        nuclei_command = [
                            "utils/nuclei", "-dc", "-fr", "-u", domain, "-rl", "50", "-ni", "-j", "-o", output_file_path
                        ]
                        
                        result = subprocess.run(nuclei_command, capture_output=True, text=True)

                        if result.returncode == 0:
                            print(f"[INFO] Nuclei scan completed successfully for domain: {domain}")
                            self.parse_nuclei_output(domain, output_file_path)
                            # self.db_manager.update_scanned_status(domain_id)
                        else:
                            print(f"[ERROR] Nuclei scan failed for domain {domain}: {result.stderr}")

            except Exception as e:
                print(f"Failed to run Nuclei scan on HTTPX results: {e}")

    def parse_nuclei_output(self, domain, output_file_path):
        """
        Parse the Nuclei output JSONL file and extract necessary information.
        """
        try:
            extracted_data = []

            with open(output_file_path, 'r') as file:
                for line in file:
                    try:
                        data = json.loads(line.strip())

                        template_id = data.get("template-id", "N/A")
                        info = data.get("info", {})
                        tags = info.get("tags", [])
                        description = info.get("description", "N/A")
                        severity = info.get("severity", "N/A")
                        matched_at = data.get("matched-at", "N/A")

                        tags_str = ", ".join(tags)

                        extracted_data.append({
                            "template-id": template_id,
                            "tags": tags_str,
                            "description": description,
                            "severity": severity,
                            "matched-at": matched_at
                        })
                        
                        self.db_manager.insert_vulnerability(domain, matched_at, tags_str, severity, description)
                    
                    except json.JSONDecodeError as e:
                        print(f"[ERROR] Error decoding JSON in file {output_file_path}: {e}")

            print("\n[INFO] Extracted Nuclei output:")
            for entry in extracted_data:
                print(entry)

        except FileNotFoundError:
            print(f"[ERROR] Output file {output_file_path} not found.")
        except Exception as e:
            print(f"[ERROR] Failed to parse Nuclei output: {e}")
