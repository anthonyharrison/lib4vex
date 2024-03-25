# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime
import uuid
from lib4sbom.data.vulnerability import Vulnerability

class OpenVEXGenerator:
    """
    Generate OpenVEX documents.
    """

    def __init__(self, author ="Unknown author", creator = "Document Creator"):
        self.doc = {}
        self.author = author
        self.creator = creator
        self.revision = 1

    def _generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    def generate_header(self, version="1"):
        id = str(uuid.uuid4()).replace("-","")
        self.doc["@context"] = "https://openvex.dev/ns/v0.2.0"
        self.doc["@id"] = f"https://openvex.dev/docs/public/vex-{id}"
        self.doc["author"] = self.author
        self.doc["role"] = self.creator
        self.doc["timestamp"] = self._generateTime()
        self.doc["version"] = str(version)

    def generate_openvex(self, vulnerabilities, metadata):
        self.revision = metadata.get("version", "0")
        self.author=metadata.get("supplier", self.author)
        self.generate_header(int(self.revision)+1)
        statements = []
        for vuln in vulnerabilities:
            vuln_info = Vulnerability(validation="openvex")
            vuln_info.copy_vulnerability(vuln)
            vulnerability = {}
            id_record={}
            id = vuln_info.get_value("id")
            if id.startswith("CVE-"):
                id_record["@id"]=f"https://nvd.nist.gov/vuln/detail/{id}"
            id_record["name"]=id
            vulnerability["vulnerability"] = id_record
            if "created" in vuln:
                vulnerability["timestamp"] = vuln_info.get_value("created")
            else:
                vulnerability["timestamp"] = self.doc["timestamp"]
            products = []
            # Only one product
            # Could be a PURL
            purl = vuln_info.get_value("purl")
            if purl is not None:
                products.append({"@id": purl})
            else:
                products.append({"@id": f'pkg:generic/{vuln_info.get_value("product")}@{vuln_info.get_value("release")}'})
            vulnerability["products"] = products
            vulnerability["status"] = vuln_info.get_value("status")
            if vulnerability["status"] is None or not vuln_info.validate_status(vulnerability["status"]):
                vulnerability["status"] = "under_investigation"
            if "justification" in vuln:
                vulnerability["justification"] = vuln_info.get_value("justification")
            if "comment" in vuln:
                vulnerability["action_statement"] = vuln_info.get_value("comment")
                if "action_timestamp" in vuln:
                    vulnerability["action_statement_timestamp"] = vuln_info.get_value("action_timestamp")
                else:
                    vulnerability["action_statement_timestamp"] = self.doc["timestamp"]
            statements.append(vulnerability)
        self.doc["statements"] = statements

    def get_document(self):
        return self.doc

    def get_revision(self):
        return self.revision
