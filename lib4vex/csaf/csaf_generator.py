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

    def generate_csaf(self, vulnerabilities):
        csaf_vuln = Vulnerability()

        self.csaf_gen.set_title("Technical Summary")
        for vulnerability in vulnerabilities:
            csaf_vuln.copy_vulnerability(vulnerability)
            # Add product
            self.csaf_gen.add_product(
                product_name=csaf_vuln.get_value("product"),
                vendor=csaf_vuln.get_value("vendor"),
                release=csaf_vuln.get_value("release")
            )
            # Add vulnerability
            self.csaf_gen.add_vulnerability(
                product_name=csaf_vuln.get_value("product"),
                release=csaf_vuln.get_value("release"),
                id=csaf_vuln.get_value("id"),
                description="Not known",
                status=csaf_vuln.get_value("status"),
                comment=csaf_vuln.get_value("comment")
            )
        self.csaf_gen.generate_csaf()
    def get_document(self):
        return self.csaf_gen.csaf_document