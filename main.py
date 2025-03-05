import argparse
from vex.parser.csaf_parser import CSAFParser
#from vex.parser.cyclonedx_parser import CycloneDXParser
#from vex.parser.openvex import OpenVEXParser
#from vex.db.operations import save_vex_statements

def main():
    parser = argparse.ArgumentParser(description="VEX Parser")
    parser.add_argument("-f", "--file", required=True, help="Path to the VEX document")
    parser.add_argument("-x", "--format", required=False, choices=["csaf", "cyclonedx", "openvex"], help="VEX format", default="csaf")
    args = parser.parse_args()

    with open(args.file, "r") as f:
        document = f.read()

    if args.format == "csaf":
        parser = CSAFParser()
    elif args.format == "cyclonedx":
        #parser = CycloneDXParser()
        pass
    elif args.format == "openvex":
        #parser = OpenVEXParser()
        pass

    parser.parse(document)
    #save_vex_statements(statements)
    for statement in parser.get_statements():
        print(statement["product_id"] + " [" + statement["status"]+ "] by " + statement["vulnerability_id"])

if __name__ == "__main__":
    main()