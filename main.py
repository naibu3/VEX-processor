import argparse
import logging

from vex.parser.csaf_parser import CSAFParser
from vex.parser.cyclonedx_parser import CycloneDXParser
#from vex.parser.openvex_parser import OpenVEXParser

from vex.utils import detect_vex_format

#from vex.db.operations import save_vex_statements

logging.basicConfig(level=logging.INFO)

def show_vulnerability(vuln):
    """Show vuln info."""
    print(f"Vulnerability Details for {vuln['cve']}")
    print(f"  Title: {vuln['title']}")
    #print(f"  Source: {vuln.source}")
    #print(f"  Description: {vuln.description}")
    #print(f"  Severity: {vuln.severity}")
    #print(f"  Published Date: {vuln.published_date}")
    #print(f"  References: {', '.join(vuln.references) if vuln.references else 'None'}")

def main():
    parser = argparse.ArgumentParser(description="VEX Parser")
    parser.add_argument("-f", "--file", required=True, help="Path to the VEX document")
    parser.add_argument("-x", "--format", required=False, choices=["csaf", "cyclonedx", "openvex"], help="VEX format", default="")
    args = parser.parse_args()

    if args.format == "csaf":
        parser = CSAFParser()
        logging.info("CSAF format selected.")
    elif args.format == "cyclonedx":
        parser = CycloneDXParser()
        logging.info("CycloneDX format selected.")
    elif args.format == "openvex":
        #parser = OpenVEXParser()
        logging.info("OpenVEX format selected.")
        pass
    else:
        logging.info("No format specified, trying to auto-detection.")
        parser = detect_vex_format(args.file)


    parser.parse(args.file)
    vulns =  parser.get_vulnerabilities()

    print(vulns)

if __name__ == "__main__":
    main()