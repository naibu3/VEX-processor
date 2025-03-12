# VEX Processor

This utility is able to parse VEX (Vulnerability Exploitability eXchange) files.

## VEX formats

VEX files are normally found in one of these three formats:

- **CSAF**
- **OpenVEX**
- **CycloneDX**

The processor convert files to three lists for **Metadata**, **Products** and **Vulnerabilities**.

### Metadata 

Information about the file.

### Products

List of products mentioned without regarding the state.

### Vulnerabilities

List of described vulnerabilities (here the products are sorted by state). The vulns are described by [Vulnerability lib4sbom objects](https://github.com/anthonyharrison/lib4sbom/blob/main/lib4sbom/data/vulnerability.py) which can be returned as a python dictionary.

## Instalation

It is reccomended to install the tool in a virtual environment:

```
python3 -m venv venv

source venv/bin/activate # linux
venv\Scripts\activate # Windows
```

Then we install the followinng packages:

```bash
pip install lib4sbom packageurl-python
```

## Testing

To run tests, [pytest](https://docs.pytest.org/en/stable/getting-started.html) is required:

```bash
pip install pytest
```

Then just execute the tests:

```bash
pytest
```

## TODOs

- [x] Fix format detection
- [ ] Enhance info. display
- [x] Implement CSAF parsing
    + [x] Parse remediations for `known_affected`
    + [ ] Parse extra info for remediations
    + [ ] Parse justification for `known_not_affected`
    + [ ] Parse scores
- [ ] Implement CycloneDX parsing
- [ ] Implement OpenVEX parsing