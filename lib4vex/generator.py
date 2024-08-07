# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import shutil
from pathlib import Path

from lib4vex.cyclonedx.cyclonedx_generator import CycloneDXVEXGenerator
from lib4vex.openvex.openvex_generator import OpenVEXGenerator
from lib4vex.spdx.spdx_generator import SPDXVEXGenerator
from lib4vex.csaf.csaf_generator import CSAFVEXGenerator
from lib4vex.parser import VEXParser

from lib4sbom.data.vulnerability import Vulnerability
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.document import SBOMDocument

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
        self.uuid = None

    def set_product(self, name, release, sbom=""):
        self.product = {"name": name, "version": release, "sbom": Path(sbom).resolve()}
        if len(sbom) > 0:
            sbom_parser=SBOMParser()
            sbom_parser.parse_file(sbom)
            self.components=sbom_parser.get_packages()
            if self.debug:
                print(self.components)
            document = SBOMDocument()
            document.copy_document(sbom_parser.get_document())
            self.uuid = document.get_value("uuid").replace("uuid","cdx")
            self.bom_version = document.get_value("bom_version","1")

    def get_type(self) -> str:
        return self.vex_type

    def set_type(self, vex_type, author=""):
        # Allow overide of vex_type
        self.vex_type = vex_type.lower()
        if self.vex_type not in ["openvex", "cyclonedx", "csaf", "spdx"]:
            # Set a default SBOM type
            self.vex_type = "openvex"
        if self.vex_type == "openvex":
            self.vex = OpenVEXGenerator(author=author)
        elif vex_type == "cyclonedx":
            self.vex = CycloneDXVEXGenerator()
        elif vex_type == "spdx":
            self.vex = SPDXVEXGenerator()
        else:
            self.vex = CSAFVEXGenerator(author=author)

    def get_vex(self):
        return self.vex_data

    def _validate_vulnerabilities(self, vulnerabilities, components):
        vex_vulnerabilities = []
        the_vuln = Vulnerability()
        for vulnerability in vulnerabilities:
            the_vuln.initialise()
            the_vuln.copy_vulnerability(vulnerability)
            # Validate component against SBOM if available
            product_name = the_vuln.get_value("product")
            release = the_vuln.get_value("release")
            # Could be a PURL
            purl = the_vuln.get_value("purl")
            update = the_vuln.get_value("update")
            if update is None and len(components) > 0:
                # Validation against SBOM. Either purl or name/version
                valid_component = False
                sbom_component = SBOMPackage()
                for component in components:
                    sbom_component.initialise()
                    sbom_component.copy_package(component)
                    name = sbom_component.get_name()
                    version = sbom_component.get_value("version")
                    purl_id = sbom_component.get_purl()
                    if purl_id is not None and purl is not None:
                        if purl == purl_id:
                            valid_component = True
                            break
                    elif name == product_name and version == release:
                        # Component found in SBOM
                        valid_component = True
                        break
            else:
                # No component validation against SBOM
                valid_component = True
            if valid_component:
                if self.uuid is not None and update is None:
                    if purl is not None:
                        element = purl
                    else:
                        element = f"{product_name}-{release}"
                    the_vuln.set_value("bom_link", f"{self.uuid}/{self.bom_version}#{element}")
                vex_vulnerabilities.append(the_vuln.get_vulnerability())
            elif self.debug:
                if purl is not None:
                    print(
                        f"[ERROR] Vulnerability {the_vuln.get_value('id')} not processed. {purl} not found in SBOM")
                else:
                    print(
                        f"[ERROR] Vulnerability {the_vuln.get_value('id')} not processed. {product_name} - {release} not found in SBOM")
        return vex_vulnerabilities

    def generate(
        self,
        project_name : str = "",
        vex_data = [],
        metadata = {},
        filename: str = "",
        send_to_output: bool = True,
    ) -> None:
        vex_update = False
        # Does file already exist? If so, update
        if len(filename) > 0:
            # Check path
            filePath = Path(filename)
            # Check if path exists and valid file
            if filePath.exists() and filePath.is_file():
                # Assume that processing can proceed
                vex_update = True
        if self.debug:
            print (f"[STATUS] VEX update {vex_update}")
        if vex_update:
            vexparser = VEXParser(vex_type=self.vex_type)
            # Read VEX file
            if self.debug:
                print (f"[PARSE] Parse vex file {filename}")
            vexparser.parse(filename)
            orig_metadata = vexparser.get_metadata()
            for attribute in orig_metadata.keys():
                # Copy metadata if not already specified
                if metadata.get(attribute) is None:
                    metadata[attribute]=orig_metadata[attribute]
            if self.debug:
                print (metadata)
            orig_vulnerabilities = vexparser.get_vulnerabilities()
            if self.debug:
                print(orig_vulnerabilities)
            # Add vulnerabilities which aren't being updated
            for orig_vuln in orig_vulnerabilities:
                include_vulnerability = True
                for vuln in vex_data:
                    if orig_vuln['id'] == vuln['id']:
                        # Previous vulnerability being updated, so don't include
                        include_vulnerability = False
                        break
                if include_vulnerability:
                    if self.debug:
                        print (f"Add {orig_vuln['id']}")
                    orig_vuln['update']=False
                    vex_data.append(orig_vuln)
        if len(vex_data) > 0:
            if self.debug:
                print(vex_data)
            # Validate vulnerabilities against SBOM
            vex_vulnerabilities = self._validate_vulnerabilities(vex_data, self.components)
            if self.debug:
                print(vex_vulnerabilities)
            self.element_set = {}
            if self.vex_type == "openvex":
                self.vex.generate_openvex(vex_vulnerabilities, metadata)
            elif self.vex_type == "cyclonedx":
                self.vex.generate_cyclonedx(vex_vulnerabilities, self.product, metadata)
            elif self.vex_type == "spdx":
                self.vex.generate_spdx(vex_vulnerabilities, metadata, self.product)
            else:
                self.vex.generate_csaf(vex_vulnerabilities, metadata, self.product)
            if send_to_output:
                if vex_update:
                    # Preserve file
                    revision = self.vex.get_revision()
                    # Separate filename into directory and filename
                    base=str(filePath.parent)
                    name=str(filePath.name)
                    shutil.copy(filename,f"{base}/{revision}_{name}")
                sbom_out = SBOMOutput(filename, output_format="json")
                sbom_out.generate_output(self.vex.get_document())

# End of file
