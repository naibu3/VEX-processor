from vex.utils import detect_vex_format
from vex.parser.csaf_parser import CSAFParser

class TestFileFormat:

   def test_csaf_format(self):
        
        csaf_format = detect_vex_format("./test_files/csaf/cve-2022-35256.json")

        assert csaf_format != "Unknown"
        assert type(csaf_format) == CSAFParser

if __name__ == "__main__":
    test = TestFileFormat
    test.test_csaf_format()