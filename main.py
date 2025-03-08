import argparse
import logging
from vex.parser.csaf_parser import CSAFParser
from vex.parser.cyclonedx_parser import CycloneDXParser
from vex.utils import detect_vex_format

#from vex.parser.openvex_parser import OpenVEXParser
#from vex.db.operations import save_vex_statements

def main():
    parser = argparse.ArgumentParser(description="VEX Parser")
    parser.add_argument("-f", "--file", required=True, help="Path to the VEX document")
    parser.add_argument("-x", "--format", required=False, choices=["csaf", "cyclonedx", "openvex"], help="VEX format", default="csaf")
    args = parser.parse_args()

    if args.format == "csaf":
        parser = CSAFParser(args.file)
    elif args.format == "cyclonedx":
        parser = CycloneDXParser(args.file)
        pass
    elif args.format == "openvex":
        #parser = OpenVEXParser(args.file)
        pass
    else:
        parser = detect_vex_format(args.file)


    parser.parse()
    #save_vex_statements(statements)

    statements =  parser.get_statements();

    for statement in statements:
        print(statement["product_id"] + " [" + statement["status"]+ "] by " + statement["vulnerability_id"])
    logging.info("Statuses: " + str(len(statement)) )
    logging.info("Vulns: " + str(len(parser.get_vulnerabilities())) )
    logging.info("Products: " + str(len(parser.get_affected_products())) )

if __name__ == "__main__":
    main()