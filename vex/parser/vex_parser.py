"""
This module implements a base class to parse VEX files.
"""
import logging
import json


logging.basicConfig(level=logging.INFO)

class VEX_Parser:

    def __init__(self):

        self.metadata = {}
        self.product = {}
        self.vulns = []

    def parse(self, filename):
        try:
            with open(filename, "r") as f:
                self.document = f.read()
        except:
            raise FileNotFoundError
        
        self.vex_data = json.load(self.document)
        self.metadata = {}
        self.product = {}
        self.vulns = []

        self._extract_metadata()
        self._extract_product()
        self._extract_vulns()
        
    def get_metadata(self):
        return self.metadata

    def get_product(self):
        return self.product

    def get_vulnerabilities(self):
        return self.vulnerabilities
