# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from lib4sbom.generator import SBOMGenerator
from lib4sbom.sbom import SBOM
from lib4sbom.data.vulnerability import Vulnerability
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.document import SBOMDocument
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
        self.document = SBOMDocument()
        self.sbom_document = SBOMGenerator(format='json', sbom_type='cyclonedx', application="lib4vex", version=VERSION)
        self.revision = 1

    def generate_cyclonedx(self, vulnerabilities, product, metadata):
        self.revision = metadata.get("bom_version", "0")
        self.sbom.set_bom_version(int(self.revision)+1)
        if metadata.get("property") is not None:
            for p in metadata.get("property"):
                self.sbom.set_property(p['name'], p['value'])
        self.sbom.set_property(f"Revision_{int(self.revision)+1}",metadata.get("revision_reason","Initial version"))
        #self.document.set_metadata_supplier(metadata.get("author_url"))
        name = f'{metadata.get("supplier","")}#{metadata.get("supplier_url","")}'
        if name != "#":
            self.document.set_creator("person",name)
        self.document.set_metadata_version(product["version"])
        self.document.set_metadata_supplier(self.author)
        self.sbom.add_vulnerabilities(vulnerabilities)
        self.sbom.add_document(self.document.get_document())
        self.sbom_document.generate(project_name=product["name"], sbom_data = self.sbom.get_sbom(), send_to_output=False)

    def get_document(self):
        return self.sbom_document.get_sbom()

    def get_revision(self):
        return self.revision



