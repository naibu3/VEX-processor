"""
This module implements a class to parse VEX files in CSAF format.
"""

import json
import logging

logging.basicConfig(level=logging.INFO)

class CSAFParser:

    def __init__(self):
        self.statements = []

    def get_statements(self):
        return self.statements

    def parse(self, document):
        """
        Parse a CSAF VEX document and return a list of VEX statements.
        
        Args:

        Returns:
        """
        data = json.loads(document)
        statements = []

        # Extract TIMESTAMP from the tracking field
        timestamp = data.get("document", {}).get("tracking", {}).get("current_release_date")

        # Extract VULNS and their info
        for vuln in data.get("vulnerabilities", []):
            
            vuln_id = vuln.get("cve")
            
            if not vuln_id:
                logging.warning("Skipping vulnerability with missing CVE ID.")
                continue

            # Extract lists with each status
            statuses = vuln.get("product_status", {})
            
            for status, products in statuses.items():

                for product in products:

                    print(status + " -> " + products[1])

                    statements.append({
                        "product_id": product,
                        "vulnerability_id": vuln_id,
                        "status": status,
                        "timestamp": timestamp
                        #"recommendations": recommended  # Add recommendations
                    })

        # If no vulnerabilities are defined, check for CVE metadata in the tracking field
        if not statements and "document" in data and "tracking" in data.get("document", {}):
            cve_id = data.get("document", {}).get("tracking", {}).get("id")
            if cve_id:
                statements.append({
                    "product_id": "unknown",  # Placeholder, as product info is not available
                    "vulnerability_id": cve_id,
                    "status": "affected",  # Default status
                    "timestamp": timestamp,
                    "recommendations": []  # No recommendations available
                })

        # If no valid data is found, raise an error
        if not statements:
            raise ValueError("No valid VEX data found in the document.")

        self.statements = statements