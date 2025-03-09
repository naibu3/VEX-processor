# VEX Processor

This utility is able to parse VEX (Vulnerability Exploitability eXchange) files.

## VEX formats

VEX files are normally found in one of these three formats:

- **CSAF**
- **OpenVEX**
- **CycloneDX**

The processor convert files to a python dictionary with the following information:

- `product_id`, ID of the affected product
- `vulnerability_id`, ID of the CVE
- `status`, vulnerability status (`known_not_affected`, `known_affected`, ...)
- `timestamp`, timestamp of the file
- `recommendations`, not available yet

Once parsed the information is returned in a list of dictionaries for each affected product for a vulnerability.

## Instalation

It is reccomended to install a virtual environment:

```
python -m venv vex_processor

source vex_processor/bin/activate # linux
vex_processor\Scripts\activate # Windows
```

Then we install the followinng packages:

```bash
pip install lib4sbom packageurl-python
```

## TODOs

- [ ] Fix format detection
- [ ] Enhance info. display
- [x] Implement CSAF parsing
    + [ ] Parse extra information about vulns
- [ ] Implement CycloneDX parsing
- [ ] Implement OpenVEX parsing