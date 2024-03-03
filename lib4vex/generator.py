# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os

from lib4vex.cyclonedx.cyclonedx_generator import CycloneDXVEXGenerator
from lib4vex.openvex.openvex_generator import OpenVEXGenerator
from lib4vex.csaf.csaf_generator import CSAFVEXGenerator

from lib4sbom.output import SBOMOutput
from lib4sbom.parser import SBOMParser

from lib4vex.openvex.openvex_generator import OpenVEXGenerator
from lib4vex.version import VERSION


class VEXGenerator:
    """
    Simple VEX Generator.
    """

    def __init__(
        self,
        vex_type: str = "openvex",
        author: str = "",
        application: str = "lib4vex",
        version: str = VERSION,
    ):

        self.set_type(vex_type, author)
        self.vex_complete = False
        self.vex_data = None
        self.debug = os.getenv("LIB4VEX_DEBUG") is not None
        self.product = None
        self.components=[]

    def set_product(self, name, release, sbom=""):
        self.product = {"name": name, "version": release, "sbom": sbom}
        if len(sbom) > 0:
            sbom_parser=SBOMParser()
            sbom_parser.parse_file(sbom)
            self.components=sbom_parser.get_packages()

    def get_type(self) -> str:
        return self.vex_type

    def set_type(self, vex_type, author=""):
        # Allow overide of vex_type
        self.vex_type = vex_type.lower()
        if self.vex_type not in ["openvex", "cyclonedx", "csaf"]:
            # Set a default SBOM type
            self.vex_type = "openvex"
        if self.vex_type == "openvex":
            self.vex = OpenVEXGenerator()
        elif vex_type == "cyclonedx":
            self.vex = CycloneDXVEXGenerator()
        else:
            self.vex = CSAFVEXGenerator(author=author)

    def get_vex(self):
        return self.vex_data

    def generate(
        self,
        project_name : str = "",
        vex_data = [],
        metadata = {},
        filename: str = "",
        send_to_output: bool = True,
    ) -> None:
        if len(vex_data) > 0:
            self.element_set = {}
            if self.vex_type == "openvex":
                self.vex.generate_openvex(vex_data)
            elif self.vex_type == "cyclonedx":
                self.vex.generate_cyclonedx(vex_data, project_name, self.components)
            else:
                self.vex.generate_csaf(vex_data, metadata, self.product, self.components)
            #self.vex = self.vex.get_document()
            if send_to_output:
                sbom_out = SBOMOutput(filename, output_format="json")
                sbom_out.generate_output(self.vex.get_document())

# End of file
