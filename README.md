# VEX Processor

This utility is able to parse VEX (Vulnerability Exploitability eXchange) files.


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

## VEX formats

VEX files are normally found in one of these four formats:

- **CSAF**
- **OpenVEX**
- **CycloneDX**
- **SPDX**

The processor implements a *Parser* object with a `Parse` method that saves the file information into three lists: **metadata**, **products** and **vulnerabilities**.

### Metadata 

It is the file's self information. Includes how, when or who generated the file.

### Products

Is the list of all mentioned products without regarding their affectedness status.

### Vulnerabilities

List of described vulnerabilities (here the products are sorted by state). The vulns are described by **Vulnerability** objects (derived from [li4sbom vuln objects](https://github.com/anthonyharrison/lib4sbom/blob/main/lib4sbom/data/vulnerability.py)) which can be accessed as a python dictionary.

Inside a vulnerability there are the follwing fields:

| Field | Description |
|---|---|
| id | CVE identifier |
| name | Vulnerability name |
| description | CVE description |
| status* | Lists for each status with a list of products |
| remediations | List of remediations for affected products |
| justifications | List of justifications for not affected products |

**Remediations** and **justifications** are their own object type, allowing to set and get their attributes and product lists.

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
- [x] Enhance info. display
- [x] Implement CSAF parsing
    + [x] Parse remediations for `known_affected`
    + [x] Parse extra info for remediations
    + [x] Parse justification for `known_not_affected`
    + [ ] Parse scores (optional)
- [ ] Implement CSAF tests

- [ ] Implement CycloneDX parsing (optional)
- [ ] Implement OpenVEX parsing (optional)
- [ ] Persist data in postgres
- [ ] Implement downloading system