import os
from datetime import datetime

class ReportGenerator:
    def generate_html_report(self, nmap_results, httpx_results, vulnerabilities, options, domains_with_descriptions):
        """
        Generate an HTML report using Nmap/Naabu results, HTTPX results, and vulnerabilities.
        """
        domains_dict = dict(domains_with_descriptions)

        try:
            nmap_grouped_by_domain = self.group_results_by_domain(nmap_results, options, domains_with_descriptions)
            httpx_grouped_by_domain = self.group_results_by_domain(httpx_results, options, domains_with_descriptions)

            html_content = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Security Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    .section-title { font-size: 18px; font-weight: bold; margin-top: 20px; }
                    .domain-title { font-size: 16px; font-weight: bold; margin-top: 10px; }
                </style>
            </head>
            <body>
                <h1>Security Report</h1>
            """

            html_content += "<div class='section-title'>Nmap/Naabu Results</div>"
            for domain, results in nmap_grouped_by_domain.items():
                # html_content += f"<div class='domain-title'>Domain: {domain}</div>"
                if options.get('exclude_ip', False):
                    description = domains_dict.get(domain, domain)  # Default to domain if no description found
                    html_content += f"<div class='domain-title'>Description: {description}</div>"
                else:
                    html_content += f"<div class='domain-title'>Domain: {domain}</div>"
                
                html_content += "<table><tr><th>Port</th><th>Service</th></tr>"
                for result in results:
                    ports = ','.join([entry.split(':')[1] for entry in result[3].split() if ':' in entry])
                    html_content += f"<tr><td>{ports}</td><td>{result[4]}</td></tr>"  # Only print extracted Ports and Service
                html_content += "</table>"


            httpx_section_content = ""

            for domain, results in httpx_grouped_by_domain.items():
                valid_results = []
                
                for result in results:
                    if not all(value is None for value in result[2:8]):
                        valid_results.append(result)

                if valid_results:
                    if options.get('exclude_ip', False):
                        description = domains_dict.get(domain, domain)
                        httpx_section_content += f"<div class='domain-title'>Domain: {description}</div>"
                    else:
                        httpx_section_content += f"<div class='domain-title'>Domain: {domain}</div>"    
                    httpx_section_content += "<table><tr><th>Subdomain</th><th>Port</th><th>Webserver</th><th>Final URL</th><th>Host</th><th>Tech</th></tr>"
                    for result in valid_results:
                        if options.get('exclude_ip', False) and domains_dict.get(result[2]):
                            # print("----------------------------",result[2])
                            description = domains_dict.get(result[2])
                            httpx_section_content += f"<tr><td>{description}</td><td>{result[3]}</td><td>{result[4]}</td><td>{result[5]}</td><td>{result[6]}</td><td>{result[7]}</td></tr>"
                        else:
                            httpx_section_content += f"<tr><td>{result[2]}</td><td>{result[3]}</td><td>{result[4]}</td><td>{result[5]}</td><td>{result[6]}</td><td>{result[7]}</td></tr>"
                    httpx_section_content += "</table>"

            # Only print the HTTPX section if there were any valid results
            if httpx_section_content:
                html_content += "<div class='section-title'>HTTPX Results</div>"
                html_content += httpx_section_content


            html_content += "<div class='section-title'>Vulnerabilities</div>"
            html_content += "<table><tr><th>Subdomain</th><th>URL</th><th>Vulnerability</th><th>Severity</th><th>Description</th></tr>"
            for row in vulnerabilities:
                if options.get('exclude_ip', False) and domains_dict.get(row[0]):
                    description = domains_dict.get(row[0])
                    html_content += f"<tr><td>{description}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td><td>{row[4]}</td></tr>"
                else:
                    html_content += f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td><td>{row[4]}</td></tr>"
            html_content += "</table>"

            html_content += """
            </body>
            </html>
            """

            result_dir = "result"
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            html_report_path = os.path.join(result_dir, f'security_report_{timestamp}.html')

            # Ensure the result directory exists
            os.makedirs(result_dir, exist_ok=True)

            # Use the path from `html_report_path` to write the file to the `result` directory
            with open(html_report_path, 'w') as report_file:
                report_file.write(html_content)

            print(f"[INFO] HTML report generated successfully: {html_report_path}")


        except Exception as e:
            print(f"[ERROR] Failed to generate HTML report: {e}")

    def group_results_by_domain(self, results, options, domains_with_descriptions):
        """
        Group results by domain. If the --no-ip option is provided, replace IP with the description.
        """
        grouped_results = {}
        
        for row in results:
            domain = row[0]
            
            if domain not in grouped_results:
                grouped_results[domain] = []
            grouped_results[domain].append(row)
        
        return grouped_results
