# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os

class CycloneDXVEXParser:
    def __init__(self):
        self.debug = os.getenv("LIB4VEX_DEBUG") is not None

    def parse(self, vex_file):
        """parses CycloneDX file extracting vulnerability information"""
        if vex_file.endswith("json"):
            return self.parse_cyclonedx_json(vex_file)
        else:
            return None

    def parse_cyclonedx_json(self):
        pass