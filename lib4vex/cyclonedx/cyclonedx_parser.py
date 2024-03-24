# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os

from lib4sbom.parser import SBOMParser

class CycloneDXVEXParser:
    def __init__(self):
        self.debug = os.getenv("LIB4VEX_DEBUG") is not None

    def parse(self, vex_file):
        """parses CycloneDX file extracting vulnerability information"""
        if vex_file.endswith("json"):
            return self.parse_cyclonedx_json(vex_file)
        else:
            return None

    def parse_cyclonedx_json(self, filename):
        cdx_parser = SBOMParser(sbom_type="cyclonedx")
        # Load SBOM - will autodetect SBOM type
        cdx_parser.parse_file(filename)
        product = cdx_parser.get_packages()
        metadata = cdx_parser.get_document()

        return metadata, product, cdx_parser.get_vulnerabilities()