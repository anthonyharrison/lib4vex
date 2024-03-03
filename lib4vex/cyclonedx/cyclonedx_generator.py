# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from lib4sbom.generator import SBOMGenerator
from lib4sbom.sbom import SBOM
from lib4vex.version import VERSION

class CycloneDXVEXGenerator:
    """
    Generate CycloneDX document.
    """

    def __init__(self, author ="Unknown author", creator = "Document Creator"):
        self.doc = {}
        self.author = author
        self.creator = creator
        self.sbom = SBOM()
        self.sbom_document = SBOMGenerator(format='json', sbom_type='cyclonedx', application="lib4vex", version=VERSION)

    def generate_cyclonedx(self, vulnerabilities, project_name, components):
        self.sbom.add_vulnerabilities(vulnerabilities)
        self.sbom_document.generate(project_name=project_name, sbom_data = self.sbom.get_sbom(), send_to_output=False)

    def get_document(self):
        return self.sbom_document.get_sbom()



