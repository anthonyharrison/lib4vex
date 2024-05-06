# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import json
from urllib.parse import urlparse

from lib4sbom.data.vulnerability import Vulnerability

class SPDXVEXParser:
    def __init__(self):
        self.debug = os.getenv("LIB4VEX_DEBUG") is not None

    def parse(self, vex_file):
        """parses SPDXVEX file extracting vulnerability information"""
        if vex_file.endswith("json"):
            return self.parse_spdxvex_json(vex_file)
        else:
            return None

    def parse_spdxvex_json(self, filename):
        vuln_status = {
            "underInvestigationFor": "under_investigation",
            "doesNotAffect": "not_affected",
            "affects": "affected",
            "fixedIn": "fixed"
        }

        data = json.load(open(filename))
        product_info = {}
        header = {}
        vulnerabilities = []
        vuln_info = Vulnerability(validation="spdx")

        if data.get("@graph") is None:
            # Doesn't look like an SPDX document
            return header, product_info, vulnerabilities

        for element in data["@graph"]:
            element_type  = element.get("type")
            if element_type is None:
                element_type = element.get("@type")
            element_id = element.get("@id")
            if element_id is None:
                element_id = element.get("spdxId")
            if element_type == "CreationInfo":
                header["timestamp"]=element["created"]
                header["specVersion"]=element["specVersion"]
            elif element_type == "Person":
                header["supplier"] = element["name"]
                if "externalIdentifier" in element:
                    for id in element["externalIdentifier"]:
                        if id["externalIdentifierType"] == "email":
                            header["supplier_url"] = id["identifier"]
            elif element_type == "SpdxDocument":
                url = urlparse(element_id)
                header["author_url"] = f"{url.scheme}://{url.netloc}"
            elif element_type in ["VexUnderInvestigationVulnAssessmentRelationship",
                                  "VexNotAffectedVulnAssessmentRelationship",
                                  "VexAffectedVulnAssessmentRelationship",
                                  "VexFixedVulnAssessmentRelationship"]:

                vuln_info.initialise()
                vuln_info.set_status(vuln_status[element["relationshipType"]])
                vuln_info.set_id(element["from"].replace("urn:spdx.dev:vuln-",""))
                # Get affected item
                assessed_element = element["assessedElement"].replace("urn:","").split("-")
                name=assessed_element[1]
                version=assessed_element[2]
                if assessed_element[0] != "generic":
                    # Purl element
                    vuln_info.set_value("purl",f"pkg:{assessed_element[0]}/{name}@{version}")
                vuln_info.set_name(name)
                vuln_info.set_release(version)
                vuln_info.set_value("created", element["publishedTime"])
                if element.get("justificationType") is not None:
                    vuln_info.set_value("justification", element.get("justificationType"))
                if element.get("impactStatementTime") is not None:
                    vuln_info.set_value("action_timestamp", element.get("impactStatementTime"))
                if element.get("actionStatement") is not None:
                    vuln_info.set_value("comment", element.get("actionStatement"))
                    vuln_info.set_value("action_timestamp", element.get("actionStatementTime"))
                # Product information
                for p in element["to"]:
                    product = p.replace("urn:product-","").split("-")
                    product_info={"name":product[0], "version": product[1]}
                vulnerabilities.append(vuln_info.get_vulnerability())
        return header, product_info, vulnerabilities
