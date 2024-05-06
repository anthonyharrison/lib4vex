# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os

from lib4vex.cyclonedx.cyclonedx_parser import CycloneDXVEXParser
from lib4vex.openvex.openvex_parser import OpenVEXParser
from lib4vex.csaf.csaf_parser import CSAFVEXParser
from lib4vex.spdx.spdx_parser import SPDXVEXParser

class VEXParser:

    vex_options = {"csaf": CSAFVEXParser(), "cyclonedx": CycloneDXVEXParser(), "openvex": OpenVEXParser(), "spdx": SPDXVEXParser()}

    def __init__(self, vex_type = "auto"):
        self.vex_type = vex_type.lower()
        if self.vex_type not in ["openvex", "cyclonedx", "csaf", "spdx", "auto"]:
            # Set a default SBOM type
            self.vex_type = "auto"
        if self.vex_type != "auto":
            self.vex = self.vex_options[self.vex_type]
        self.vex_complete = False
        self.debug = os.getenv("LIB4VEX_DEBUG") is not None
        self.metadata = {}
        self.product = []
        self.vulnerabilities = []

    def parse(self, filename):
        if self.debug:
            print (f"Parse {filename} of VEX Type {self.vex_type}")
        if self.vex_type == "auto":
            if self.debug:
                print (f"VEX file type detection for {filename}")
            for vex_type in self.vex_options:
                if self.debug:
                    print (f"Checking {filename} type : {vex_type}")
                self.vex = self.vex_options[vex_type]
                self.metadata, self.product, self.vulnerabilities = self.vex.parse(filename)
                if len(self.metadata) > 0:
                    # Assume found type of VEX document
                    self.vex_type = vex_type
                    break
            if len(self.metadata) == 0:
                print ("[ERROR] Unable to determine type of VEX document")
                self.product = []
                self.vulnerabilities = []
        else:
            self.metadata, self.product, self.vulnerabilities = self.vex.parse(filename)

    def get_type(self):
        return self.vex_type

    def get_metadata(self):
        return self.metadata

    def get_product(self):
        return self.product

    def get_vulnerabilities(self):
        return self.vulnerabilities



