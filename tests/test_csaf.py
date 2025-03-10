
from vex.parser.csaf_parser import CSAFParser

class TestCSAFParser:
    def test_parse(self):
        document = "./tests/test_files/csaf/cve-2022-35256.json"
        parser = CSAFParser()

        parser.parse(document)
        vulns = parser.get_vulnerabilities()

        assert len(vulns) == 1
        assert vulns[0]['id'] == "CVE-2022-35256"
        

if __name__ == "__main__":
    test = TestCSAFParser()
    test.test_parse()