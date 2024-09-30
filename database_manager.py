import sqlite3

class DatabaseManager:
    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = None
        self.cursor = None
        self.connect()

    def connect(self):
        self.conn = sqlite3.connect(self.db_file)
        self.cursor = self.conn.cursor()
    def create_tables(self):
        create_domains_table = """
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY,
            domain TEXT NOT NULL,
            description TEXT
        )
        """
        create_results_table = """
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY,
            domain_id INTEGER,
            subdomain TEXT,
            port TEXT,
            service TEXT,
            FOREIGN KEY(domain_id) REFERENCES domains(id)
        )
        """
        create_httpx_table = """
        CREATE TABLE IF NOT EXISTS httpx (
            id INTEGER PRIMARY KEY,
            domain_id INTEGER,
            subdomain TEXT,
            port TEXT,
            webserver TEXT,
            final_url TEXT,
            host TEXT,
            tech TEXT,
            scanned BOOLEAN,
            FOREIGN KEY(domain_id) REFERENCES domains(id)
        )
        """
        create_vulnerabilities_table = """
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY,
            subdomain TEXT,
            url TEXT,
            vulnerability TEXT,
            severity TEXT,
            description TEXT
        )
        """
        self.cursor.execute(create_domains_table)
        self.cursor.execute(create_results_table)
        self.cursor.execute(create_httpx_table)
        self.cursor.execute(create_vulnerabilities_table)
        self.conn.commit()


    def get_all_httpx_results(self):
        query = """
        SELECT d.domain, d.description, h.subdomain, h.port, h.webserver, h.final_url, h.host, h.tech ,h.scanned
        FROM domains d
        LEFT JOIN httpx h ON d.id = h.domain_id
        """
        self.cursor.execute(query)
        rows = self.cursor.fetchall()

        # print("\n[DEBUG] HTTPX Rows fetched from the database:")
        # for row in rows:
        #     print(row)

        return rows
    def update_scanned_status(self, domain_id):
        update_query = """
        UPDATE httpx
        SET scanned = TRUE
        WHERE domain_id = %s
        """
        self.cursor.execute(update_query, (domain_id,))
        self.connection.commit()
        print(f"\n[INFO] Updated scanned status for domain_id {domain_id}")
        
    
    def insert_httpx(self, domain_id, subdomain, port, webserver, final_url, host, tech, scanned):
        insert_query = """
        INSERT INTO httpx (domain_id, subdomain, port, webserver, final_url, host, tech, scanned)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.cursor.execute(insert_query, (domain_id, subdomain, port, webserver, final_url, host, tech, scanned))
        self.conn.commit()

    def insert_domain(self, domain, description):
        insert_query = """
        INSERT INTO domains (domain, description)
        VALUES (?, ?)
        """
        self.cursor.execute(insert_query, (domain, description))
        self.conn.commit()
        return self.cursor.lastrowid

    def insert_results(self, domain_id, subdomain, port, service):
        insert_query = """
        INSERT INTO results (domain_id, subdomain, port, service)
        VALUES (?, ?, ?, ?)
        """
        self.cursor.execute(insert_query, (domain_id, subdomain, port, service))
        self.conn.commit()

    def update_port_scan_results(self, domain_id, subdomain, port, service):
        """Update the port scan results for a specific subdomain."""
        update_query = """
        UPDATE results
        SET port = ?, service = ?
        WHERE domain_id = ? AND subdomain = ?
        """
        self.cursor.execute(update_query, (port, service, domain_id, subdomain))
        self.conn.commit()

    def get_all_results(self):
        query = """
        SELECT d.domain, d.description, r.subdomain, r.port, r.service
        FROM domains d
        LEFT JOIN results r ON d.id = r.domain_id
        """
        self.cursor.execute(query)
        rows = self.cursor.fetchall()

        # print("\n[DEBUG] Rows fetched from the database:")
        # for row in rows:
        #     print(row)

        return rows

    def close(self):
        if self.conn:
            self.conn.close()


    def insert_vulnerability(self, subdomain, url, vulnerability, severity, description):
        """
        Insert a new vulnerability record into the vulnerabilities table.
        """
        insert_query = """
        INSERT INTO vulnerabilities (subdomain, url, vulnerability, severity, description)
        VALUES (?, ?, ?, ?, ?)
        """
        self.cursor.execute(insert_query, (subdomain, url, vulnerability, severity, description))
        self.conn.commit()

    def get_all_vulnerabilities(self):
        """
        Retrieve all records from the vulnerabilities table.
        """
        select_query = """
        SELECT v.subdomain, v.url, v.vulnerability, v.severity, v.description
        FROM vulnerabilities v
        """
        self.cursor.execute(select_query)
        rows = self.cursor.fetchall()

        # print("\n[DEBUG] Vulnerabilities fetched from the database:")
        # for row in rows:
        #     print(row)

        return rows
