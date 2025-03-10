import json
import logging
from vex.parser.csaf_parser import CSAFParser
from vex.parser.cyclonedx_parser import CycloneDXParser

def detect_vex_format(file_path):
    """
    Detects if the file is in CSAF, CycloneDX, or OpenVEX format and creates the propper parser.
    
    Args:
        file_path (str): Path to the file to be checked.
    
    Returns:
        vex_parser: A parser object for the detected format.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()

            # Try parsing as JSON (CSAF, CycloneDX, and OpenVEX are JSON-based)
            try:
                data = json.loads(content)
                # Check for CSAF
                if 'document' in data and 'category' in data['document'] and data['document']['category'] == 'csaf':
                    logging.info("CSAF format detected.")
                    return CSAFParser()
                # Check for CycloneDX (JSON format)
                if 'bomFormat' in data and data['bomFormat'] == 'CycloneDX':
                    logging.info("CycloneDX format detected.")
                    return CycloneDXParser()
                # Check for OpenVEX
                if '@context' in data and 'https://openvex.dev/ns' in data['@context']:
                    logging.info("OpenVEX format detected.")
                    return "openvex"
            except json.JSONDecodeError:
                pass

    except Exception as e:
        print(f"Error reading file: {e}")

    logging.warning("No format detected.")
    return "Unknown"

def display_vulnerability(vuln):
    """Show vuln info."""
    print("")
    print(f"Vulnerability Details for {vuln['id']}")

    if "description" in vuln:
        print(f"  Description: {vuln['description']}")
    
    if "known_affected" in vuln:
        print("[known_affected]")
        for product in vuln['known_affected']:
            print("- " + product)

    if "known_not_affected" in vuln:
        print("[known_not_affected]")
        for product in vuln['known_not_affected']:
            print("- " + product)