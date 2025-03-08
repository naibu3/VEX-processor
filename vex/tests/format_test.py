import unittest
from vex.utils import detect_vex_format

class TestFileFormat(unittest.TestCase):

   def csaf_format_test(self):
        
        csaf_format = detect_vex_format("./test_files/csaf/cve-2022-35256.json")

        self.assertEqual(csaf_format, "csaf")

if __name__ == "__main__":
    unittest.main()