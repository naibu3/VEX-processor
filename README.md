# VEX Processor

## VEX formats

VEX files are normally found in one of these three formats:

- **CSAF**
- **OpenVEX**
- **CycloneDX**

The processor convert files to a python dictionary with the following information:

- `product_id`, ID of the affected product
- `vulnerability_id`, CVE ID
- `status`, vulnerability status
- `timestamp`
- `recommendations`, not available yet

Once parsed the information is returned in a list of dictionaries for each affected product for a vulnerability.