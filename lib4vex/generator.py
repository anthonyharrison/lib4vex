# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os

from lib4vex.cyclonedx.cyclonedx_generator import CycloneDXVEXGenerator
from lib4vex.openvex.openvex_generator import OpenVEXGenerator
from lib4vex.csaf.csaf_generator import CSAFVEXGenerator

from lib4sbom.output import SBOMOutput
#from lib4vex.data.document import VexDocument

from lib4vex.openvex.openvex_generator import OpenVEXGenerator
from lib4vex.version import VERSION


class VEXGenerator:
    """
    Simple VEX Generator.
    """

    def __init__(
        self,
        vex_type: str = "openvex",
        application: str = "lib4vex",
        version: str = VERSION,
    ):

        self.vex_type = vex_type.lower()
        if self.vex_type not in ["openvex", "cyclonedx", "csaf"]:
            # Set a default SBOM type
            self.vex_type = "openvex"

        if self.vex_type == "openvex":
            self.vex = OpenVEXGenerator()
        elif vex_type == "cyclonedx":
            self.vex = CycloneDXVEXGenerator()
        else:
            self.vex = CSAFVEXGenerator()
        self.vex_complete = False
        self.vex_data = None
        self.debug = os.getenv("LIB4VEX_DEBUG") is not None

    def get_type(self) -> str:
        return self.vex_type

    def get_vex(self):
        return self.vex_data

    def generate(
        self,
        project_name : str = "",
        vex_data = [],
        filename: str = "",
        send_to_output: bool = True,
    ) -> None:
        if len(vex_data) > 0:
            self.element_set = {}
            if self.vex_type == "openvex":
                self.vex.generate_openvex(vex_data)
            elif self.vex_type == "cyclonedx":
                self.vex.generate_cyclonedx(vex_data)
            else:
                self.vex.generate_csaf(vex_data)
            #self.vex = self.vex.get_document()
            if send_to_output:
                sbom_out = SBOMOutput(filename, output_format="json")
                sbom_out.generate_output(self.vex.get_document())

# End of file
