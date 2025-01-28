# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime
import uuid
from lib4sbom.data.vulnerability import Vulnerability
from packageurl import PackageURL

class SPDXVEXGenerator:
    """
    Generate SPDX VEX documents.
    """
    SPDX_VERSION = "3.0.1"

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
        spdx_version = self.SPDX_VERSION
        self.doc["@context"] = f"https://spdx.org/rdf/{spdx_version}/spdx-context.jsonld"
        self.doc["@graph"] = []
        # Creation info
        creation = {}
        creation["type"] = "CreationInfo"
        creation["@id"] = "_:creationinfo_0"
        creation["createdBy"] = ["urn:spdx.dev:lib4vex"]
        creation["specVersion"] = spdx_version
        creation["created"] = self.document_generation_time
        creation["comment"] = "This document has been automatically generated."
        self.doc["@graph"].append(creation)
        # Tool
        creator = {}
        creator["type"] = "Tool"
        creator["spdxId"] = "https://spdx.org/lib4vex"
        creator["name"] = "lib4vex"
        creator["creationInfo"] = "_:creationinfo_0"
        self.doc["@graph"].append(creator)
        # Creator info
        creator = {}
        creator["type"] = "Person"
        creator["spdxId"] = f'{self.domain}/Person/{self.author.replace(" ","")}'
        self.supplied_by = creator["spdxId"]
        creator["name"] = self.author
        creator["creationInfo"] = "_:creationinfo_0"
        # if email
        creator["externalIdentifier"] = []
        extinfo = {}
        extinfo["type"] = "ExternalIdentifier"
        extinfo["externalIdentifierType"] = "email"
        extinfo["identifier"] = self.author_email
        creator["externalIdentifier"].append(extinfo)
        creator["creationInfo"] = "_:creationinfo_0"
        self.doc["@graph"].append(creator)
        # Document info
        document = {}
        document["type"] = "SpdxDocument"
        document["spdxId"] = f"{self.domain}/{id}"
        document["creationInfo"] = "_:creationinfo_0"
        document["name"] = "VEX Document"
        document["profileConformance"] = []
        document["profileConformance"].append("core")
        document["profileConformance"].append("software")
        document["profileConformance"].append("security")
        self.doc["@graph"].append(document)
        # sbom = {}
        # sbom["type"] = "software_Sbom"
        # sbom["spdxID"] = f"{self.domain}/SBOM_{id}"
        # sbom["creationInfo"] = "_:creationinfo_0"
        # sbom["software_sbomType"] = ["build"]
        # self.doc["@graph"].append(sbom)

    def generate_spdx(self, vulnerabilities, metadata, product):
        self.revision = metadata.get("version", "0")
        self.author=metadata.get("supplier", self.author)
        self.domain=metadata.get("author_url","http://spdx.example.com")
        self.author_email=metadata.get("supplier_url","unknown@example.com")
        self.generate_header(int(self.revision)+1)

        # Properties are dependent on status
        vuln_properties = {
            "under_investigation":
                {"type": "security_VexUnderInvestigationVulnAssessmentRelationship",
                 "id": "urn:spdx.dev:vex-underInvestigation",
                 "relationship": "underInvestigationFor",
                },
            "not_affected":
                {"type": "security_VexNotAffectedVulnAssessmentRelationship",
                 "id": "urn:spdx.dev:vex-not-affected",
                 "relationship": "doesNotAffect",
                 },
            "affected":
                {"type": "security_VexAffectedVulnAssessmentRelationship",
                 "id": "urn:spdx.dev:vex-affected",
                 "relationship": "affects",
                 },
            "fixed":
                {"type": "security_VexFixedVulnAssessmentRelationship",
                 "id": "urn:spdx.dev:vex-fixed-in",
                 "relationship": "fixedIn",
                 },
        }

        # Now add software packages
        software_package = []
        for vuln in vulnerabilities:
            vuln_info = Vulnerability(validation="spdx")
            vuln_info.copy_vulnerability(vuln)
            purl = vuln_info.get_value("purl")
            if purl is not None:
                purl_id = PackageURL.from_string(purl).to_dict()
                name=purl_id['name']
                version=purl_id['version']
            else:
                name = vuln_info.get_value("product")
                version = vuln_info.get_value("release")
            if (name,version) not in software_package:
                software_package.append((name,version))
                software_package_info = {}
                software_package_info["type"] = "software_Package"
                software_package_info["spdxId"] = f'{self.domain}/Package/{name}-{version}'
                software_package_info["creationInfo"] = "_:creationinfo_0"
                software_package_info["name"] = name
                software_package_info["software_packageVersion"] = version
                #software_package_info["orignatedBy"] = [self.supplied_by]
                self.doc["@graph"].append(software_package_info)

        vuln_id=0
        for vuln in vulnerabilities:
            vuln_info = Vulnerability(validation="spdx")
            vuln_info.copy_vulnerability(vuln)
            vulnerability = {}
            vuln_attributes= vuln_properties[vuln_info.get_value("status")]
            vulnerability["type"] = vuln_attributes["type"]
            vulnerability["spdxId"] = f'{vuln_attributes["id"]}-{vuln_id}'
            vulnerability["creationInfo"] = "_:creationinfo_0"
            vulnerability["relationshipType"] = vuln_attributes["relationship"]
            id = vuln_info.get_value("id")
            vulnerability["from"] = f"urn:spdx.dev:vuln-{id}"
            vulnerability["to"] = [f"urn:product-{product['name'].replace('-','_')}-{product['version']}"]
            # Only one product
            # Could be a PURL
            purl = vuln_info.get_value("purl")
            # if purl is not None:
            #     vulnerability["security_assessedElement"] = f'urn:{purl.replace("pkg:","").replace("/","-").replace("@","-")}'
            # else:
            #     vulnerability["security_assessedElement"] = f'urn:generic-{vuln_info.get_value("product")}-{vuln_info.get_value("release")}'
            if purl is not None:
                purl_id = PackageURL.from_string(purl).to_dict()
                name=purl_id['name']
                version=purl_id['version']
            else:
                name = vuln_info.get_value("product")
                version = vuln_info.get_value("release")
            vulnerability["security_assessedElement"] = f'{self.domain}/Package/{name}-{version}'
            vulnerability["suppliedBy"] = self.supplied_by
            if vuln_info.get_value("status") == "affected":
                if "comment" in vuln:
                    vulnerability["actionStatement"] = vuln_info.get_value("comment")
                if "action_timestamp" in vuln:
                    vulnerability["actionStatementTime"] = vuln_info.get_value("action_timestamp")
                else:
                    vulnerability["actionStatementTime"] = self.document_generation_time
                # TODO Remediation
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
                vulnerability["security_publishedTime"] = vuln_info.get_value("created")
            else:
                vulnerability["security_publishedTime"] = self.document_generation_time
            vulnerability["completeness"] = "complete"
            self.doc["@graph"].append(vulnerability)
            vuln_id += 1

    def get_document(self):
        return self.doc

    def get_revision(self):
        return self.revision
