# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime
import uuid
from lib4sbom.data.vulnerability import Vulnerability

class SPDXVEXGenerator:
    """
    Generate SPDX VEX documents.
    """

    def __init__(self, author ="Unknown author", creator = "Document Creator"):
        self.doc = {}
        self.author = author
        self.creator = creator
        self.revision = 1
        self.document_generation_time = self._generateTime()

    def _generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def generate_header(self, version="1"):
        id = str(uuid.uuid4()).replace("-","")
        spdx_version = "3.0.0"
        self.doc["@context"] = f"https://spdx.org/rdf/{spdx_version}/spdx-context.jsonld"
        self.doc["@graph"] = []
        # Creation info
        creation = {}
        creation["type"] = "CreationInfo"
        creation["@id"] = "_:creationinfo"
        creation["createdBy"] = ["urn:spdx.dev:lib4vex"]
        creation["specVersion"] = spdx_version
        creation["created"] = self.document_generation_time
        creation["comment"] = "This document has been automatically generated."
        self.doc["@graph"].append(creation)
        # Creator info
        creator = {}
        creator["type"] = "Person"
        creator["@id"] = "_:creationinfo"
        creator["spdxId"] = f'{self.domain}/Person/{self.author.replace(" ","")}'
        creator["name"] = self.author
        creator["creationInfo"] = "_:creationinfo"
        # if email
        creator["externalIdentifier"] = []
        extinfo = {}
        extinfo["type"] = "ExternalIdentifier"
        extinfo["externalIdentifierType"] = "email"
        extinfo["identifier"] = self.author_email
        creator["externalIdentifier"].append(extinfo)
        self.doc["@graph"].append(creator)
        # Document info
        document = {}
        document["type"] = "SpdxDocument"
        document["spdxId"] = f"{self.domain}/{id}"
        document["creationInfo"] = "_:creationinfo"
        #document"dataLicense"] = "CCC"
        document["name"] = "VEX Document"
        document["profileConformance"] = []
        document["profileConformance"].append("core")
        document["profileConformance"].append("software")
        document["profileConformance"].append("security")#
        document["rootElement"] = [f"{self.domain}/VEX1"]
        self.doc["@graph"].append(document)

    def generate_spdx(self, vulnerabilities, metadata, product):
        self.revision = metadata.get("version", "0")
        self.author=metadata.get("supplier", self.author)
        self.domain=metadata.get("author_url","http://spdx.example.com")
        self.author_email=metadata.get("supplier_url","unknown@example.com")
        self.generate_header(int(self.revision)+1)

        # Properties are dependent on status
        vuln_properties = {
            "under_investigation":
                {"type": "VexUnderInvestigationVulnAssessmentRelationship",
                 "id": "urn:spdx.dev:vex-underInvestigation-1",
                 "relationship": "underInvestigationFor",
                },
            "not_affected":
                {"type": "VexNotAffectedVulnAssessmentRelationship",
                 "id": "urn:spdx.dev:vex-not-affected-1",
                 "relationship": "doesNotAffect",
                 },
            "affected":
                {"type": "VexAffectedVulnAssessmentRelationship",
                 "id": "urn:spdx.dev:vex-affected-1",
                 "relationship": "affects",
                 },
            "fixed":
                {"type": "VexFixedVulnAssessmentRelationship",
                 "id": "urn:spdx.dev:vex-fixed-in-1",
                 "relationship": "fixedIn",
                 },
        }

        for vuln in vulnerabilities:
            vuln_info = Vulnerability(validation="spdx")
            vuln_info.copy_vulnerability(vuln)
            vulnerability = {}
            vuln_attributes= vuln_properties[vuln_info.get_value("status")]
            vulnerability["@type"] = vuln_attributes["type"]
            vulnerability["@id"] = vuln_attributes["id"]
            vulnerability["relationshipType"] = vuln_attributes["relationship"]
            id = vuln_info.get_value("id")
            vulnerability["from"] = f"urn:spdx.dev:vuln-{id}"
            vulnerability["to"] = [f"urn:product-{product['name'].replace('-','_')}-{product['version']}"]
            # Only one product
            # Could be a PURL
            purl = vuln_info.get_value("purl")
            if purl is not None:
                vulnerability["assessedElement"] = f'urn:{purl.replace("pkg:","").replace("/","-").replace("@","-")}'
            else:
                vulnerability["assessedElement"] = f'urn:generic-{vuln_info.get_value("product")}-{vuln_info.get_value("release")}'
            supplied_by = f"urn:spdx.dev:agent-{self.author.lower().replace(' ', '-')}"
            vulnerability["suppliedBy"] = [supplied_by]
            if vuln_info.get_value("status") == "affected":
                if "comment" in vuln:
                    vulnerability["actionStatement"] = vuln_info.get_value("comment")
                if "action_timestamp" in vuln:
                    vulnerability["actionStatementTime"] = vuln_info.get_value("action_timestamp")
                else:
                    vulnerability["actionStatementTime"] = self.document_generation_time
            elif vuln_info.get_value("status") == "not_affected":
                if "justification" in vuln:
                    vulnerability["justificationType"] = vuln_info.get_value("justification")
                if "comment" in vuln:
                    vulnerability["impactStatement"] = vuln_info.get_value("comment")
                if "action_timestamp" in vuln:
                    vulnerability["impactStatementTime"] = vuln_info.get_value("action_timestamp")
                else:
                    vulnerability["impactStatementTime"] = self.document_generation_time
            if "created" in vuln:
                vulnerability["publishedTime"] = vuln_info.get_value("created")
            else:
                vulnerability["publishedTime"] = self.document_generation_time
            self.doc["@graph"].append(vulnerability)
        # Now add software SBOM type?

    def get_document(self):
        return self.doc

    def get_revision(self):
        return self.revision
