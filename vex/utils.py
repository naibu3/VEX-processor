import json
from vex.parser.csaf_parser import CSAFParser
from vex.parser.cyclonedx_parser import CycloneDXParser

def detect_vex_format(file_path):
    """
    Detects if the file is in CSAF, CycloneDX, or OpenVEX format.
    
    Args:
        file_path (str): Path to the file to be checked.
    
    Returns:
        str: The format of the file ("CSAF", "CycloneDX", "OpenVEX", or "Unknown").
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()

            # Try parsing as JSON (CSAF, CycloneDX, and OpenVEX are JSON-based)
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    # Check for CSAF
                    if 'document' in data and 'category' in data['document'] and data['document']['category'] == 'csaf':
                        return CSAFParser(file_path)
                    # Check for CycloneDX (JSON format)
                    if 'bomFormat' in data and data['bomFormat'] == 'CycloneDX':
                        return CycloneDXParser(file_path)
                    # Check for OpenVEX
                    if '@context' in data and 'https://openvex.dev/ns' in data['@context']:
                        return "openvex"
            except json.JSONDecodeError:
                pass

    except Exception as e:
        print(f"Error reading file: {e}")

    return "Unknown"
