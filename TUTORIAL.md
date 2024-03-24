# Lib4VEX Tutorial

Lib4VEX is a library to parse and generate VEX documents. It supports VEX documents created in the [OpenVEX](https://openvex.dev),
[CycloneDX](https://www.cyclonedx.org) or [CSAF](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) specifications.

It has been developed on the assumption that having a generic abstraction of vulnerability regardless of the underlying format will be useful to developers.

# Overview

This tutorial will follow a simple lifecycle following the generation of a Software Bill of Materials (SBOM). The SBOM can
be in ether [SPDX](https://www.spdx.org) or [CycloneDX](https://www.cyclonedx.org) formats.

For this tutorial, the VEX document will be produced in [CSAF](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) format.

The lifecycle followed by the tutorial is as follows:

1. (Outside the scope of Lib4VEX) An SBOM for a release of a product is created and made available.

2. (Outside the scope of Lib4VEX) The SBOM is scanned for vulnerabilities to identify vulnerabilities with the product. 

3. All vulnerabilities are added to a VEX document with an initial status to indicate that each one is _under investigation_.

4. The status of a vulnerability within the VEX document is updated to indicate that the vulnerability is not exploitable. The VEX document is updated to reflect the new status.

5. A new vulnerability is detected and an updated VEX document is created.

6. The status of a vulnerability within the VEX document is updated again to indicate that the product is impacted by the vulnerability and that remediation is required. A new VEX document is created.

7. (Outside the scope of Lib4VEX) The product is updated to update the component to address the vulnerability. A new SBOM is generated and a scan is performed to identify any vulnerabilities.

### 1 Create SBOM

The creation of the SBOM is outside the scope of Lib4VEX, but the following SBOM (example.json) is to be used in this tutorial.

```bash
{
  "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:b355491d-a6e7-499e-a273-071b2ef3d086",
  "version": 1,
  "metadata": {
    "timestamp": "2024-03-10T18:13:19Z",
    "tools": {
      "components": [
        {
          "name": "sbom4python",
          "version": "0.10.3",
          "type": "application"
        }
      ]
    },
    "component": {
      "type": "application",
      "bom-ref": "CDXRef-DOCUMENT",
      "name": "VEX Example"
    }
  },
  "components": [
    {
      "type": "application",
      "bom-ref": "1-vexapp",
      "name": "vexapp",
      "version": "0.1.0",
      "supplier": {
        "name": "Anthony Harrison"
      },
      "cpe": "cpe:2.3:a:anthony_harrison:lib4vex:0.1.0:*:*:*:*:*:*:*",
      "description": "VEX Demonstration Application",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0",
            "url": "https://www.apache.org/licenses/LICENSE-2.0"
          }
        }
      ],
      "purl": "pkg:pypi/lib4vex@0.1.0"
    },
    {
      "type": "library",
      "bom-ref": "2-packageurl-python",
      "name": "packageurl-python",
      "version": "0.11.2",
      "supplier": {
        "name": "the purl authors"
      },
      "cpe": "cpe:2.3:a:the_purl_authors:packageurl-python:0.11.2:*:*:*:*:*:*:*",
      "description": "A purl aka. Package URL parser and builder",
      "licenses": [
        {
          "license": {
            "id": "MIT",
            "url": "https://opensource.org/licenses/MIT"
          }
        }
      ],
      "purl": "pkg:pypi/packageurl-python@0.11.2"
    },
    {
      "type": "library",
      "bom-ref": "3-defusedxml",
      "name": "defusedxml",
      "version": "0.7.1",
      "supplier": {
        "name": "Christian Heimes"
      },
      "cpe": "cpe:2.3:a:christian_heimes:defusedxml:0.7.1:*:*:*:*:*:*:*",
      "description": "XML bomb protection for Python stdlib modules",
      "licenses": [
        {
          "license": {
            "id": "PSF-2.0",
            "url": "https://opensource.org/licenses/Python-2.0"
          }
        }
      ],
      "purl": "pkg:pypi/defusedxml@0.7.1"
    },
    {
      "type": "library",
      "bom-ref": "4-pyyaml",
      "name": "pyyaml",
      "version": "6.0.1",
      "supplier": {
        "name": "Kirill Simonov"
      },
      "cpe": "cpe:2.3:a:kirill_simonov:pyyaml:6.0.1:*:*:*:*:*:*:*",
      "description": "YAML parser and emitter for Python",
      "licenses": [
        {
          "license": {
            "id": "MIT",
            "url": "https://opensource.org/licenses/MIT"
          }
        }
      ],
      "purl": "pkg:pypi/pyyaml@6.0.1"
    }
  ],
  "dependencies": [
    {
      "ref": "CDXRef-DOCUMENT",
      "dependsOn": [
        "1-vexapp"
      ]
    },
    {
      "ref": "1-vexapp",
      "dependsOn": [
        "2-packageurl-python",
        "3-defusedxml",
        "4-pyyaml"
      ]
    }
  ]
}

```

A summary of the components within the product are as follows

```bash
╭─────────────────╮
│ Package Summary │
╰─────────────────╯
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Name              ┃ Version ┃ Type        ┃ Supplier         ┃ License    ┃Ecosystem ┃ 
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩━━━━━━━━━━┩
│ vexapp            │ 0.1.0   │ APPLICATION │ Anthony Harrison │ Apache-2.0 │pypi      │
│ packageurl-python │ 0.11.2  │ LIBRARY     │ the purl authors │ MIT        │pypi      │
│ defusedxml        │ 0.7.1   │ LIBRARY     │ Christian Heimes │ PSF-2.0    │pypi      │
│ pyyaml            │ 6.0.1   │ LIBRARY     │ Kirill Simonov   │ MIT        │pypi      │
└───────────────────┴─────────┴─────────────┴──────────────────┴────────────┘──────────┘

```

### 2. SBOM Scan

The following vulnerabilities are identified for components in the SBOM:

| Vulnerability Id | Component  | Version | PURL Identifier           |
|------------------|------------|---------|---------------------------|
| CVE-2023-12345   | pyaml      | 6.0.1   | pkg:pypi/pyyaml@6.0.1     |
| CVE-2024-1234    | defusedxml | 0.7.1   | pkg:pypi/defusedxml@0.7.1 |

An additional vulnerability (CVE-2024-0987) is also identified for a component which is not included in the product. This is to consider a scenario
where a component was included in a previous release of the product but has been removed in the current release of the product.

| Vulnerability Id | Component  | Version | PURL Identifier           |
|------------------|------------|---------|---------------------------|
| CVE-2024-0987    | Spring     | 3.2.1   | pkg:maven/spring@3.2.1    |

A scenario could be envisaged where a superset of all vulnerabilities across multiple releases of a product are assembled, before the respective VEX
documents are produced for each product release.

### 3. Create Initial VEX Document

The following code sample (_**example_1.py**_) shows the creation of the initial VEX document. The VEX is created in CSAF format and
references the SBOM (example.json). The vulnerable components can be specified as a product/version pair or as a PURL reference.
Note that as an SBOM is specified when the VEX document is being created, only vulnerabilities for components included in the SBOM will be included in the VEX document.

```python
from lib4vex.generator import VEXGenerator
from lib4sbom.data.vulnerability import Vulnerability

vextype="csaf"

vexgen = VEXGenerator(vex_type=vextype, author="APH_Division")
vexgen.set_product(name="ACME-Infusion", release="1.0", sbom="samples/example.json")

metadata={}
metadata["id"]="ACME-INFUSION-1.0-VEX"
metadata["title"]="ACME-INFUSION-1.0-VEX Use Case complete"
metadata["comment"]="ACME INFUSION PoC II VEX document. Unofficial content for demonstration purposes only."
metadata["supplier"]="Fred Flintstone"
metadata["supplier_url"]="fredflintstone@acme.com"
metadata["author_url"]="http://www.hospitalproducts.acme"
metadata["status"]="draft"

# Create initial VEX
vulnerability = Vulnerability(validation=vextype)
vulnerabilities = []
# Specifiy vulnerability by product name/version
vulnerability.initialise()
vulnerability.set_id("CVE-2023-12345")
vulnerability.set_name("pyyaml")
vulnerability.set_release("6.0.1")
vulnerability.set_status("under_investigation")
vulnerabilities.append(vulnerability.get_vulnerability())
# Specifiy vulnerability by PURL
vulnerability.initialise()
vulnerability.set_id("CVE-2024-1234")
vulnerability.set_value("purl", "pkg:pypi/defusedxml@0.7.1")
vulnerability.set_status("under_investigation")
vulnerabilities.append(vulnerability.get_vulnerability())
# This vulnerability doesn't apply to the product as component not included in this version of the SBOM
vulnerability.initialise()
vulnerability.set_id("CVE-2024-0987")
vulnerability.set_name("Spring")
vulnerability.set_release("3.2.1")
vulnerability.set_status("under_investigation")
vulnerabilities.append(vulnerability.get_vulnerability())

# Generate VEX document
vexgen.generate(project_name="ACME_Infusion", vex_data = vulnerabilities, metadata = metadata, filename=f"samples/{vextype}/acme_1.0_vex.json")

```

Executing the script to create the VEX document.

```bash
$ python examples/example_1.py
```
The resulting VEX document (acme_1.0_vex.json) shows that there are two vulnerabilities currently under investigation for the product.

```bash
{
  "document": {
    "category": "csaf_vex",
    "csaf_version": "2.0",
    "notes": [
      {
        "category": "other",
        "title": "Author Comment",
        "text": "ACME INFUSION PoC II VEX document. Unofficial content for demonstration purposes only."
      }
    ],
    "publisher": {
      "category": "vendor",
      "name": "APH_Division",
      "namespace": "http://www.hospitalproducts.acme",
      "contact_details": "Fred Flintstone, fredflintstone@acme.com"
    },
    "title": "ACME-INFUSION-1.0-VEX Use Case complete",
    "tracking": {
      "current_release_date": "2024-03-20T21-05-40Z",
      "generator": {
        "date": "2024-03-20T21-05-40Z",
        "engine": {
          "name": "csaf-tool",
          "version": "0.2.1"
        }
      },
      "id": "ACME-INFUSION-1.0-VEX",
      "initial_release_date": "2024-03-20T21-05-40Z",
      "revision_history": [
        {
          "date": "2024-03-20T21-05-40Z",
          "number": "1",
          "summary": "Initial version"
        }
      ],
      "status": "draft",
      "version": "1"
    }
  },
  "product_tree": {
    "branches": [
      {
        "category": "vendor",
        "name": "APH_Division",
        "branches": [
          {
            "category": "product_name",
            "name": "ACME-Infusion",
            "branches": [
              {
                "category": "product_version",
                "name": "1.0",
                "product": {
                  "name": "APH_Division ACME-Infusion 1.0",
                  "product_id": "CSAFPID_0001",
                  "product_identification_helper": {
                    "sbom_urls": "file:///root/Documents/git_repo/lib4vex/samples/example.json"
                  }
                }
              }
            ]
          }
        ]
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2023-12345",
      "notes": [
        {
          "category": "description",
          "title": "CVE description",
          "text": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
        }
      ],
      "product_status": {
        "under_investigation": [
          "CSAFPID_0001"
        ]
      },
      "flags": [
        {
          "date": "2024-03-20T21-05-40Z",
          "product_ids": [
            "CSAFPID_0001"
          ]
        }
      ]
    },
    {
      "cve": "CVE-2024-1234",
      "notes": [
        {
          "category": "description",
          "title": "CVE description",
          "text": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
        }
      ],
      "product_status": {
        "under_investigation": [
          "CSAFPID_0001"
        ]
      },
      "flags": [
        {
          "date": "2024-03-20T21-05-40Z",
          "product_ids": [
            "CSAFPID_0001"
          ]
        }
      ]
    }
  ]
}


```

Extraction of the data within the VEX document can be obtained by running the following code.:

```bash
$ python
>>> from lib4vex.parser import VEXParser
>>> vexparser = VEXParser(vex_type="csaf")
>>> vexparser.parse("samples/csaf/acme_1.0_vex.json")
>>> vexparser.get_metadata()
{'version': '2.0', 'title': 'ACME-INFUSION-1.0-VEX Use Case complete', 'category': 'csaf_vex', 'date': '2024-03-20T21-05-40Z', 'notes': [{'title': 'Author Comment', 'text': 'ACME INFUSION PoC II VEX document. Unofficial content for demonstration purposes only.', 'category': 'other'}], 'publisher': 'APH_Division http://www.hospitalproducts.acme', 'author': 'APH_Division', 'author_url': 'http://www.hospitalproducts.acme', 'contact_details': 'Fred Flintstone, fredflintstone@acme.com', 'generator': 'csaf-tool version 0.2.1', 'id': 'ACME-INFUSION-1.0-VEX', 'initial_release_date': '2024-03-20T21-05-40Z', 'revision': [{'date': '2024-03-20T21-05-40Z', 'number': '1', 'summary': 'Initial version'}], 'tracking_status': 'draft', 'tracking_version': '1'}
>>> vexparser.get_product()
{'CSAFPID_0001': {'vendor': 'APH_Division', 'product': 'ACME-Infusion', 'version': '1.0', 'family': ''}}
>>> vexparser.get_vulnerabilities()
[{'id': 'CVE-2023-12345', 'description': 'https://nvd.nist.gov/vuln/detail/CVE-2023-12345', 'created': '2024-03-20T21-05-40Z', 'Product': 'CSAFPID_0001', 'status': 'under_investigation'}, {'id': 'CVE-2024-1234', 'description': 'https://nvd.nist.gov/vuln/detail/CVE-2024-1234', 'created': '2024-03-20T21-05-40Z', 'Product': 'CSAFPID_0001', 'status': 'under_investigation'}]
>>> 
```

This shows that there are 2 vulnerabilities associated with the product and both are under investigation. The metadata and product information are also
provided.

### 4. VEX Update (1)

The following code sample (_**example_2.py**_) shows the creation of the updated VEX document. The metadata in the existing VEX document is reused
although a reason for the update to the document should be specified. The status of the speciified vulnerability is updated, the other vulmerability is unmodified.

```python
from lib4vex.generator import VEXGenerator
from lib4sbom.data.vulnerability import Vulnerability

vextype="csaf"

vexgen = VEXGenerator(vex_type=vextype, author="APH_Division")
vexgen.set_product(name="ACME-Infusion", release="1.0", sbom="samples/example.json")

metadata={}
# Only updated metadata
metadata["revision_reason"] = "Product Review initiated."

# Update VEX Statement
vulnerability = Vulnerability(validation=vextype)
vulnerabilities = []
# Specify vulnerability by product name/version
vulnerability.initialise()
vulnerability.set_id("CVE-2023-12345")
vulnerability.set_name("pyyaml")
vulnerability.set_release("6.0.1")
vulnerability.set_status("known_not_affected")
# Justify decision
vulnerability.set_justification("vulnerable_code_not_in_execute_path")
vulnerabilities.append(vulnerability.get_vulnerability())

# Generate VEX document. As VEX already exists, file will be updated
vexgen.generate(project_name="ACME_Infusion", vex_data = vulnerabilities, metadata = metadata, filename=f"samples/{vextype}/acme_1.0_vex.json")
```

```bash
$ python examples/example_2.py
```
The resulting VEX document (acme_1.0_vex_csaf.json) is as follows:

```bash
{
  "document": {
    "category": "csaf_vex",
    "csaf_version": "2.0",
    "notes": [
      {
        "category": "other",
        "title": "Author Comment",
        "text": "ACME INFUSION PoC II VEX document. Unofficial content for demonstration purposes only."
      }
    ],
    "publisher": {
      "category": "vendor",
      "name": "APH_Division",
      "namespace": "http://www.hospitalproducts.acme",
      "contact_details": "Fred Flintstone, fredflintstone@acme.com"
    },
    "title": "ACME-INFUSION-1.0-VEX Use Case complete",
    "tracking": {
      "current_release_date": "2024-03-20T21-05-45Z",
      "generator": {
        "date": "2024-03-20T21-05-45Z",
        "engine": {
          "name": "csaf-tool",
          "version": "0.2.1"
        }
      },
      "id": "ACME-INFUSION-1.0-VEX",
      "initial_release_date": "2024-03-20T21-05-40Z",
      "revision_history": [
        {
          "date": "2024-03-20T21-05-40Z",
          "number": "1",
          "summary": "Initial version"
        },
        {
          "date": "2024-03-20T21-05-45Z",
          "number": "2",
          "summary": "Product Review initiated."
        }
      ],
      "status": "draft",
      "version": "2.0"
    }
  },
  "product_tree": {
    "branches": [
      {
        "category": "vendor",
        "name": "APH_Division",
        "branches": [
          {
            "category": "product_name",
            "name": "ACME-Infusion",
            "branches": [
              {
                "category": "product_version",
                "name": "1.0",
                "product": {
                  "name": "APH_Division ACME-Infusion 1.0",
                  "product_id": "CSAFPID_0001",
                  "product_identification_helper": {
                    "sbom_urls": "file:///root/Documents/git_repo/lib4vex/samples/example.json"
                  }
                }
              }
            ]
          }
        ]
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2023-12345",
      "notes": [
        {
          "category": "description",
          "title": "CVE description",
          "text": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
        }
      ],
      "product_status": {
        "known_not_affected": [
          "CSAFPID_0001"
        ]
      },
      "flags": [
        {
          "date": "2024-03-20T21-05-45Z",
          "label": "component_not_present",
          "product_ids": [
            "CSAFPID_0001"
          ]
        }
      ]
    },
    {
      "cve": "CVE-2024-1234",
      "notes": [
        {
          "category": "description",
          "title": "CVE description",
          "text": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
        }
      ],
      "product_status": {
        "under_investigation": [
          "CSAFPID_0001"
        ]
      },
      "flags": [
        {
          "date": "2024-03-20T21-05-40Z",
          "product_ids": [
            "CSAFPID_0001"
          ]
        }
      ]
    }
  ]
}

```

A summary of the VEX document can be obtained by running the following command:

As previously, extraction of the data within the VEX document can be obtained by running the following code.:

```bash
$ python
>>> from lib4vex.parser import VEXParser
>>> vexparser = VEXParser(vex_type="csaf")
>>> vexparser.parse("samples/csaf/acme_1.0_vex.json")
>>> vexparser.get_metadata()
{'version': '2.0', 'title': 'ACME-INFUSION-1.0-VEX Use Case complete', 'category': 'csaf_vex', 'date': '2024-03-20T21-05-45Z', 'notes': [{'title': 'Author Comment', 'text': 'ACME INFUSION PoC II VEX document. Unofficial content for demonstration purposes only.', 'category': 'other'}], 'publisher': 'APH_Division http://www.hospitalproducts.acme', 'author': 'APH_Division', 'author_url': 'http://www.hospitalproducts.acme', 'contact_details': 'Fred Flintstone, fredflintstone@acme.com', 'generator': 'csaf-tool version 0.2.1', 'id': 'ACME-INFUSION-1.0-VEX', 'initial_release_date': '2024-03-20T21-05-40Z', 'revision': [{'date': '2024-03-20T21-05-40Z', 'number': '1', 'summary': 'Initial version'}, {'date': '2024-03-20T21-05-45Z', 'number': '2', 'summary': 'Product Review initiated.'}], 'tracking_status': 'draft', 'tracking_version': '2.0'}
>>> vexparser.get_product()
{'CSAFPID_0001': {'vendor': 'APH_Division', 'product': 'ACME-Infusion', 'version': '1.0', 'family': ''}}
>>> vexparser.get_vulnerabilities()
[{'id': 'CVE-2023-12345', 'description': 'https://nvd.nist.gov/vuln/detail/CVE-2023-12345', 'justification': 'component_not_present', 'created': '2024-03-20T21-05-45Z', 'Product': 'CSAFPID_0001', 'status': 'known_not_affected'}, {'id': 'CVE-2024-1234', 'description': 'https://nvd.nist.gov/vuln/detail/CVE-2024-1234', 'created': '2024-03-20T21-05-40Z', 'Product': 'CSAFPID_0001', 'status': 'under_investigation'}]
>>> 
```

This shows that there are 2 vulnerabilities associated with the product with one indicating that the vulnerability does not affect the product.

### 5. VEX Update (2)

A new vulnerability is detected. The following code sample (_**example_3.py**_) shows the creation of the updated VEX document. 

```python
from lib4vex.generator import VEXGenerator
from lib4sbom.data.vulnerability import Vulnerability

vextype="csaf"

vexgen = VEXGenerator(vex_type=vextype, author="APH_Division")
vexgen.set_product(name="ACME-Infusion", release="1.0", sbom="samples/example.json")

metadata={}
metadata["revision_reason"] = "New vulnerability CVE-2024-6789 detected."

# Update VEX Statement
vulnerability = Vulnerability(validation=vextype)
vulnerabilities = []
# Specifiy vulnerability by product name/version
vulnerability.initialise()
vulnerability.set_id("CVE-2024-6789")
vulnerability.set_name("pyyaml")
vulnerability.set_release("6.0.1")
vulnerability.set_status("under_investigation")
vulnerabilities.append(vulnerability.get_vulnerability())

# Generate VEX document. As VEX already exists, file will be updated
vexgen.generate(project_name="ACME_Infusion", vex_data = vulnerabilities, metadata = metadata, filename=f"samples/{vextype}/acme_1.0_vex.json")

```

```bash
$ python examples/example_3.py
```

The resulting VEX document

```bash

  "document": {
    "category": "csaf_vex",
    "csaf_version": "2.0",
    "notes": [
      {
        "category": "other",
        "title": "Author Comment",
        "text": "ACME INFUSION PoC II VEX document. Unofficial content for demonstration purposes only."
      }
    ],
    "publisher": {
      "category": "vendor",
      "name": "APH_Division",
      "namespace": "http://www.hospitalproducts.acme",
      "contact_details": "Fred Flintstone, fredflintstone@acme.com"
    },
    "title": "ACME-INFUSION-1.0-VEX Use Case complete",
    "tracking": {
      "current_release_date": "2024-03-20T21-05-48Z",
      "generator": {
        "date": "2024-03-20T21-05-48Z",
        "engine": {
          "name": "csaf-tool",
          "version": "0.2.1"
        }
      },
      "id": "ACME-INFUSION-1.0-VEX",
      "initial_release_date": "2024-03-20T21-05-40Z",
      "revision_history": [
        {
          "date": "2024-03-20T21-05-40Z",
          "number": "1",
          "summary": "Initial version"
        },
        {
          "date": "2024-03-20T21-05-45Z",
          "number": "2",
          "summary": "Product Review initiated."
        },
        {
          "date": "2024-03-20T21-05-48Z",
          "number": "3",
          "summary": "New vulnerability CVE-2024-6789 detected."
        }
      ],
      "status": "draft",
      "version": "2.0"
    }
  },
  "product_tree": {
    "branches": [
      {
        "category": "vendor",
        "name": "APH_Division",
        "branches": [
          {
            "category": "product_name",
            "name": "ACME-Infusion",
            "branches": [
              {
                "category": "product_version",
                "name": "1.0",
                "product": {
                  "name": "APH_Division ACME-Infusion 1.0",
                  "product_id": "CSAFPID_0001",
                  "product_identification_helper": {
                    "sbom_urls": "file:///root/Documents/git_repo/lib4vex/samples/example.json"
                  }
                }
              }
            ]
          }
        ]
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2024-6789",
      "notes": [
        {
          "category": "description",
          "title": "CVE description",
          "text": "https://nvd.nist.gov/vuln/detail/CVE-2024-6789"
        }
      ],
      "product_status": {
        "under_investigation": [
          "CSAFPID_0001"
        ]
      },
      "flags": [
        {
          "date": "2024-03-20T21-05-48Z",
          "product_ids": [
            "CSAFPID_0001"
          ]
        }
      ]
    },
    {
      "cve": "CVE-2023-12345",
      "notes": [
        {
          "category": "description",
          "title": "CVE description",
          "text": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
        }
      ],
      "product_status": {
        "known_not_affected": [
          "CSAFPID_0001"
        ]
      },
      "flags": [
        {
          "date": "2024-03-20T21-05-45Z",
          "label": "component_not_present",
          "product_ids": [
            "CSAFPID_0001"
          ]
        }
      ]
    },
    {
      "cve": "CVE-2024-1234",
      "notes": [
        {
          "category": "description",
          "title": "CVE description",
          "text": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
        }
      ],
      "product_status": {
        "under_investigation": [
          "CSAFPID_0001"
        ]
      },
      "flags": [
        {
          "date": "2024-03-20T21-05-40Z",
          "product_ids": [
            "CSAFPID_0001"
          ]
        }
      ]
    }
  ]
}

```

This shows that there are now 3 vulnerabilities associated with the product, with two under investigation.

### 6. VEX Update (3)

The latest vulnerability is assessed which is confirmed as affecting the product. The following code sample (_**example_4.py**_) shows the creation of the updated VEX document. 

```python
from lib4vex.generator import VEXGenerator
from lib4sbom.data.vulnerability import Vulnerability

vextype="csaf"

vexgen = VEXGenerator(vex_type=vextype, author="APH_Division")
vexgen.set_product(name="ACME-Infusion", release="1.0", sbom="samples/example.json")

metadata={}
metadata["revision_reason"] = "Confirmed that vulnerability CVE-2024-6789 is exploitable"

# Update VEX Statement
vulnerability = Vulnerability(validation=vextype)
vulnerabilities = []
# Specify vulnerability by product name/version
vulnerability.initialise()
vulnerability.set_id("CVE-2024-6789")
vulnerability.set_name("pyyaml")
vulnerability.set_release("6.0.1")
vulnerability.set_status("known_affected")
vulnerability.set_comment("The payload could be manipulated leading to a DDOS attack on the product.")
vulnerabilities.append(vulnerability.get_vulnerability())

# Generate VEX document. As VEX already exists, file will be updated
vexgen.generate(project_name="ACME_Infusion", vex_data = vulnerabilities, metadata = metadata, filename=f"samples/{vextype}/acme_1.0_vex.json")

```

```bash
$ python examples/example_4.py
```

The resulting VEX document

```bash
{
  "document": {
    "category": "csaf_vex",
    "csaf_version": "2.0",
    "notes": [
      {
        "category": "other",
        "title": "Author Comment",
        "text": "ACME INFUSION PoC II VEX document. Unofficial content for demonstration purposes only."
      }
    ],
    "publisher": {
      "category": "vendor",
      "name": "APH_Division",
      "namespace": "http://www.hospitalproducts.acme",
      "contact_details": "Fred Flintstone, fredflintstone@acme.com"
    },
    "title": "ACME-INFUSION-1.0-VEX Use Case complete",
    "tracking": {
      "current_release_date": "2024-03-20T21-05-52Z",
      "generator": {
        "date": "2024-03-20T21-05-52Z",
        "engine": {
          "name": "csaf-tool",
          "version": "0.2.1"
        }
      },
      "id": "ACME-INFUSION-1.0-VEX",
      "initial_release_date": "2024-03-20T21-05-40Z",
      "revision_history": [
        {
          "date": "2024-03-20T21-05-40Z",
          "number": "1",
          "summary": "Initial version"
        },
        {
          "date": "2024-03-20T21-05-45Z",
          "number": "2",
          "summary": "Product Review initiated."
        },
        {
          "date": "2024-03-20T21-05-48Z",
          "number": "3",
          "summary": "New vulnerability CVE-2024-6789 detected."
        },
        {
          "date": "2024-03-20T21-05-52Z",
          "number": "4",
          "summary": "Confirmed that vulnerability CVE-2024-6789 is exploitable"
        }
      ],
      "status": "draft",
      "version": "2.0"
    }
  },
  "product_tree": {
    "branches": [
      {
        "category": "vendor",
        "name": "APH_Division",
        "branches": [
          {
            "category": "product_name",
            "name": "ACME-Infusion",
            "branches": [
              {
                "category": "product_version",
                "name": "1.0",
                "product": {
                  "name": "APH_Division ACME-Infusion 1.0",
                  "product_id": "CSAFPID_0001",
                  "product_identification_helper": {
                    "sbom_urls": "file:///root/Documents/git_repo/lib4vex/samples/example.json"
                  }
                }
              }
            ]
          }
        ]
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2024-6789",
      "notes": [
        {
          "category": "description",
          "title": "CVE description",
          "text": "https://nvd.nist.gov/vuln/detail/CVE-2024-6789"
        }
      ],
      "product_status": {
        "known_affected": [
          "CSAFPID_0001"
        ]
      },
      "flags": [
        {
          "date": "2024-03-20T21-05-52Z",
          "product_ids": [
            "CSAFPID_0001"
          ]
        }
      ],
      "threats": [
        {
          "category": "impact",
          "details": "The payload could be manipulated leading to a DDOS attack on the product.",
          "date": "2024-03-20T21-05-52Z",
          "product_ids": [
            "CSAFPID_0001"
          ]
        }
      ]
    },
    {
      "cve": "CVE-2023-12345",
      "notes": [
        {
          "category": "description",
          "title": "CVE description",
          "text": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
        }
      ],
      "product_status": {
        "known_not_affected": [
          "CSAFPID_0001"
        ]
      },
      "flags": [
        {
          "date": "2024-03-20T21-05-45Z",
          "label": "component_not_present",
          "product_ids": [
            "CSAFPID_0001"
          ]
        }
      ]
    },
    {
      "cve": "CVE-2024-1234",
      "notes": [
        {
          "category": "description",
          "title": "CVE description",
          "text": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
        }
      ],
      "product_status": {
        "under_investigation": [
          "CSAFPID_0001"
        ]
      },
      "flags": [
        {
          "date": "2024-03-20T21-05-40Z",
          "product_ids": [
            "CSAFPID_0001"
          ]
        }
      ]
    }
  ]
}
```

A summary of the VEX document can be obtained by running the following command:

```bash
$ python 
>>> from lib4vex.parser import VEXParser
>>> vexparser = VEXParser(vex_type="csaf")
>>> vexparser.parse("samples/csaf/acme_1.0_vex.json")
>>> vexparser.get_metadata()
{'version': '2.0', 'title': 'ACME-INFUSION-1.0-VEX Use Case complete', 'category': 'csaf_vex', 'date': '2024-03-20T21-05-52Z', 'notes': [{'title': 'Author Comment', 'text': 'ACME INFUSION PoC II VEX document. Unofficial content for demonstration purposes only.', 'category': 'other'}], 'publisher': 'APH_Division http://www.hospitalproducts.acme', 'author': 'APH_Division', 'author_url': 'http://www.hospitalproducts.acme', 'contact_details': 'Fred Flintstone, fredflintstone@acme.com', 'generator': 'csaf-tool version 0.2.1', 'id': 'ACME-INFUSION-1.0-VEX', 'initial_release_date': '2024-03-20T21-05-40Z', 'revision': [{'date': '2024-03-20T21-05-40Z', 'number': '1', 'summary': 'Initial version'}, {'date': '2024-03-20T21-05-45Z', 'number': '2', 'summary': 'Product Review initiated.'}, {'date': '2024-03-20T21-05-48Z', 'number': '3', 'summary': 'New vulnerability CVE-2024-6789 detected.'}, {'date': '2024-03-20T21-05-52Z', 'number': '4', 'summary': 'Confirmed that vulnerability CVE-2024-6789 is exploitable'}], 'tracking_status': 'draft', 'tracking_version': '2.0'}
>>> vexparser.get_vulnerabilities()
[{'id': 'CVE-2024-6789', 'description': 'https://nvd.nist.gov/vuln/detail/CVE-2024-6789', 'created': '2024-03-20T21-05-52Z', 'Product': 'CSAFPID_0001', 'impact': 'The payload could be manipulated leading to a DDOS attack on the product.', 'status': 'known_affected'}, 
 {'id': 'CVE-2023-12345', 'description': 'https://nvd.nist.gov/vuln/detail/CVE-2023-12345', 'justification': 'component_not_present', 'created': '2024-03-20T21-05-45Z', 'Product': 'CSAFPID_0001', 'status': 'known_not_affected'}, 
 {'id': 'CVE-2024-1234', 'description': 'https://nvd.nist.gov/vuln/detail/CVE-2024-1234', 'created': '2024-03-20T21-05-40Z', 'Product': 'CSAFPID_0001', 'status': 'under_investigation'}]
>>> 
```

This shows that there are 3 vulnerabilities associated with the product, one has been identified as affecting the product, one has no affect and one is under investigation.

## Summary

This tutorial has shown how to use the lib4vex Python library in order to generate and parse VEX documents in the CSAF format.
