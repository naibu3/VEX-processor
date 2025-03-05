"""
This module implements a base class to parse VEX files.
"""
import logging

logging.basicConfig(level=logging.INFO)

class VEX_Parser:

    def __init__(self):
        self.statements = []

    def get_statements(self):
        """
        Gets parsed data.

        Returns:
            dict: A dictionary with VEX statements.
        """
        return self.statements

    def get_affected_products(self):
        products = []
        for statement in self.statements:
            products.append(statement["product_id"])
        
        return products

    def get_vulnerabilities(self):
        vulns = []
        for statement in self.statements:
            vulns.append(statement["vulnerability_id"])
        
        return vulns

    def get_statement(self, product_id):
        for statement in self.statements:
            if statement["product_id"] == product_id:
                return statement
        
        logging.warning(f"No information was found in VEX file for {product_id}")
        return None