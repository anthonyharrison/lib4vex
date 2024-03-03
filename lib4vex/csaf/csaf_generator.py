# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from csaf.generator import CSAFGenerator
from lib4sbom.data.vulnerability import Vulnerability

class CSAFVEXGenerator:

    def __init__(self, author ="Unknown author", creator = "Document Creator"):
        self.doc = {}
        self.author = author
        self.creator = creator
        self.csaf_gen = CSAFGenerator()

    def generate_csaf(self, vulnerabilities, metadata, product, components):
        csaf_vuln = Vulnerability()
        self.csaf_gen.set_title("Technical Summary")
        self.csaf_gen.set_value("author", self.author)
        # Product
        self.csaf_gen.add_product(product_name=product['name'], vendor=self.author, release=product['version'])
        if len(metadata) > 0:
            # Extract attributes
            for attribute in metadata.keys():
                if attribute == "id":
                    self.csaf_gen.set_id(metadata["id"])
                elif attribute == "title":
                    self.csaf_gen.set_header_title(metadata["title"])
                else:
                    self.csaf_gen.set_value(attribute, metadata[attribute])
        for vulnerability in vulnerabilities:
            csaf_vuln.initialise()
            csaf_vuln.copy_vulnerability(vulnerability)
            # Validate component against SBOM if available
            product_name = csaf_vuln.get_value("product")
            release = csaf_vuln.get_value("release")
            if len(components) > 0:
                # Validation against SBOM
                valid_component = False
                for component in components:
                    name=component['name']
                    version=component['version']
                    if name==product_name and version==release:
                        # Component found in SBOM
                        valid_component=True
                        break
            else:
                # No component validation against SBOM
                valid_component=True
            if valid_component:
                # Add product
                self.csaf_gen.add_product(
                    product_name=csaf_vuln.get_value("product"),
                    vendor=csaf_vuln.get_value("vendor"),
                    release=csaf_vuln.get_value("release")
                )
                # Add vulnerability
                self.csaf_gen.add_vulnerability(
                    product_name=product_name,
                    release=release,
                    id=csaf_vuln.get_value("id"),
                    description=csaf_vuln.get_value("description"),
                    status=csaf_vuln.get_value("status"),
                    comment=csaf_vuln.get_value("comment"),
                    justification=csaf_vuln.get_value("justification")
                )
            else:
                print (f"[ERROR] Vulnerability {csaf_vuln.get_value('id')} not processed. {product_name} - {release} not found in SBOM")
        self.csaf_gen.generate_csaf()
    def get_document(self):
        return self.csaf_gen.csaf_document