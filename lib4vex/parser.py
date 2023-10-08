# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os

from lib4vex.cyclonedx.cyclonedx_parser import CycloneDXVEXParser
from lib4vex.openvex.openvex_parser import OpenVEXParser
from lib4vex.csaf.csaf_parser import CSAFVEXParser

class VEXParser:

    def __init__(self, vex_type = "openvex"):
        self.vex_type = vex_type.lower()
        if self.vex_type not in ["openvex", "cyclonedx", "csaf"]:
            # Set a default SBOM type
            self.vex_type = "openvex"
        if self.vex_type == "openvex":
            self.vex = OpenVEXParser()
        elif vex_type == "cyclonedx":
            self.vex = CycloneDXVEXParser()
        else:
            self.vex = CSAFVEXParser()
        self.vex_complete = False
        self.debug = os.getenv("LIB4VEX_DEBUG") is not None

    def parse(self, filename):
        return self.vex.parse(filename)


