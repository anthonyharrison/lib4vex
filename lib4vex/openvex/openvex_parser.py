# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import json
from packageurl import PackageURL

from lib4sbom.data.vulnerability import Vulnerability

class OpenVEXParser:
    def __init__(self):
        self.debug = os.getenv("LIB4VEX_DEBUG") is not None

    def parse(self, vex_file):
        """parses OpenVEX file extracting vulnerability information"""
        if vex_file.endswith("json"):
            return self.parse_openvex_json(vex_file)
        else:
            return None

    def parse_openvex_json(self, filename):
        data = json.load(open(filename))
        product_info = {}
        # Extract header info
        header={}
        vulnerabilities = []
        if data.get("@id") is None:
            # Doesn't look like a OPENVEX document
            return header, product_info, vulnerabilities

        header["id"]=data["@id"]
        header["author"]=data["author"]
        header["role"]=data["role"]
        header["timestamp"]=data["timestamp"]
        header["version"]=data["version"]
        # Extract vulnerability info
        vuln_info = Vulnerability(validation="openvex")
        for vulnerability in data["statements"]:
            vuln_info.initialise()
            vuln_info.set_id(vulnerability["vulnerability"]["name"])
            # Only expecting one product
            for p in vulnerability["products"]:
                purl = PackageURL.from_string(p["@id"]).to_dict()
                name=purl['name']
                release=purl['version']
                vuln_info.set_value("purl", p["@id"])
                vuln_info.set_name(name)
                vuln_info.set_release(release)
            vuln_info.set_status(vulnerability["status"])
            vuln_info.set_value("created", vulnerability["timestamp"])
            if vulnerability.get("justification") is not None:
                vuln_info.set_value("justification", vulnerability.get("justification"))
            if vulnerability.get("action_statement") is not None:
                vuln_info.set_value("comment", vulnerability.get("action_statement"))
                vuln_info.set_value("action_timestamp", vulnerability.get("action_statement"))
            product_info[name]={"name":name, "version": release}
            vulnerabilities.append(vuln_info.get_vulnerability())
        return header, product_info, vulnerabilities
