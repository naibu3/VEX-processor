import unittest
from vex.parser.csaf import CSAFParser

class TestCSAFParser(unittest.TestCase):
    def test_parse(self):
        document = '''
        {
            "document": {
                "tracking": {
                    "timestamp": "2023-10-01T00:00:00Z"
                }
            },
            "product_tree": {
                "branches": [
                    {
                        "product": {
                            "product_id": "pkg:maven/org.example/library@1.0.0"
                        }
                    }
                ]
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2023-1234",
                    "status": "affected"
                }
            ]
        }
        '''
        parser = CSAFParser()
        statements = parser.parse(document)
        self.assertEqual(len(statements), 1)
        self.assertEqual(statements[0]["product_id"], "pkg:maven/org.example/library@1.0.0")
        self.assertEqual(statements[0]["vulnerability_id"], "CVE-2023-1234")