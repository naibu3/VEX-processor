import unittest
from vex.parser.csaf_parser import CSAFParser

class TestCSAFParser(unittest.TestCase):
    def test_parse(self):
        document = '''
        '''
        parser = CSAFParser()

        parser.parse(document)
        statements = parser.get_statements()

        self.assertEqual(len(statements), 61)
        #self.assertEqual(statements[0]["product_id"], "pkg:maven/org.example/library@1.0.0")
        #self.assertEqual(statements[0]["vulnerability_id"], "CVE-2023-1234")

if __name__ == "__main__":
    unittest.main()