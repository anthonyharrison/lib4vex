# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
from csaf.parser import CSAFParser

class CSAFVEXParser:
    def __init__(self):
        self.debug = os.getenv("LIB4VEX_DEBUG") is not None
        self.csaf_parse = CSAFParser()

    def parse(self, vex_file):
        """parses CSAF file extracting vulnerability information"""
        if vex_file.endswith("json"):
            return self.parse_csaf_json(vex_file)
        else:
            return None

    def parse_csaf_json(self, filename):
        self.csaf_parse.parse_file(filename)
        metadata = self.csaf_parse.get_metadata()
        product = self.csaf_parse.get_product()
        vulnerabilities = self.csaf_parse.get_vulnerabilities()
        return metadata, product, vulnerabilities