# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime
from lib4sbom.data.vulnerability import Vulnerability

class OpenVEXGenerator:
    """
    Generate OpenVEX documents.
    """

    def __init__(self, author ="Unknown author", creator = "Document Creator"):
        self.doc = {}
        self.author = author
        self.creator = creator

    def _generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    def generate_header(self, version="1"):
        id = 9876
        self.doc["@context"] = "https://openvex.dev/ns"
        self.doc["@id"] = f"https://openvex.dev/docs/public/vex-{id}"
        self.doc["author"] = self.author
        self.doc["role"] = self.creator
        self.doc["timestamp"] = self._generateTime()
        self.doc["version"] = version

    def generate_openvex(self, vulnerabilities, doc_version="1"):
        self.generate_header(doc_version)
        statements = []
        for vuln in vulnerabilities:
            vuln_info = Vulnerability(validation="openvex")
            vuln_info.copy_vulnerability(vuln)
            vulnerability = {}
            vulnerability["vulnerability"] = vuln_info.get_value("id")
            vulnerability["timestamp"] = self.doc["timestamp"]
            products = []
            # Only one product
            products.append(f'pkg:{vuln_info.get_value("product")}@{vuln_info.get_value("release")}')
            vulnerability["products"] = products
            vulnerability["status"] = vuln_info.get_value("status")
            if vulnerability["status"] is None or not vuln_info.validate_status(vulnerability["status"]):
                vulnerability["status"] = "under_investigation"
            if "comment" in vuln:
                vulnerability["justification"] = vuln_info.get_value("comment")
            statements.append(vulnerability)
        self.doc["statements"] = statements

    def get_document(self):
        return self.doc

    def get_revision(self):
        return self.doc.get("version","0")
