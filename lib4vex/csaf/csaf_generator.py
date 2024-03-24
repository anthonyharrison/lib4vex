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

    def generate_csaf(self, vulnerabilities, metadata, product):
        csaf_vuln = Vulnerability()
        self.csaf_gen.set_title("Technical Summary")
        self.csaf_gen.set_value("author", self.author)
        # Product
        self.csaf_gen.add_product(product_name=product['name'], vendor=self.author, release=product['version'], sbom=product['sbom'])
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
            product_name = csaf_vuln.get_value("product")
            release = csaf_vuln.get_value("release")
            # Add product
            self.csaf_gen.add_product(
                product_name=product_name,
                vendor=csaf_vuln.get_value("vendor"),
                release=release,
            )
            # Add vulnerability
            self.csaf_gen.add_vulnerability(
                product_name=product_name,
                release=release,
                id=csaf_vuln.get_value("id"),
                description=csaf_vuln.get_value("description"),
                status=csaf_vuln.get_value("status"),
                comment=csaf_vuln.get_value("comment"),
                justification=csaf_vuln.get_value("justification"),
                created=csaf_vuln.get_value("created")
            )
        self.csaf_gen.generate_csaf()
    def get_document(self):
        return self.csaf_gen.csaf_document

    def get_revision(self):
        return self.csaf_gen.get_revision()