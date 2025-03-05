"""
This module extends vex_parser class to parse VEX files in CSAF format.
"""

import json
import logging
from .vex_parser import VEX_Parser

logging.basicConfig(level=logging.INFO)

class CSAFParser(VEX_Parser):

    def parse(self, document):
        """
        Parse a CSAF VEX document and store in self `statements` attribute a list of VEX statements.
        
        Args:
            document (file descriptor): The document to be parsed.
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

                if status != "recommended":
                    for product in products:
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