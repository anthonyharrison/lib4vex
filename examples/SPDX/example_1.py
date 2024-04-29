from lib4vex.generator import VEXGenerator
from lib4sbom.data.vulnerability import Vulnerability

vextype="spdx"

vexgen = VEXGenerator(vex_type=vextype, author="APH_Division")
vexgen.set_product(name="ACME-Infusion", release="1.0", sbom="samples/example.json")

metadata={}
metadata["id"]="ACME-INFUSION-1.0-VEX"
metadata["title"]="ACME-INFUSION-1.0-VEX Use Case complete"
metadata["comment"]="ACME INFUSION PoC II VEX document. Unofficial content for demonstration purposes only."
metadata["supplier"]="Fred Flintstone"
metadata["supplier_url"]="fredflintstone@acme.com"
metadata["author_url"]="http://www.hospitalproducts.acme"
metadata["status"]="draft"

# Create initial VEX
vulnerability = Vulnerability(validation=vextype)
vulnerabilities = []
# Specifiy vulnerability by product name/version
vulnerability.initialise()
vulnerability.set_id("CVE-2023-12345")
vulnerability.set_name("pyyaml")
vulnerability.set_release("6.0.1")
vulnerability.set_status("under_investigation")
vulnerabilities.append(vulnerability.get_vulnerability())
# Specifiy vulnerability by PURL
vulnerability.initialise()
vulnerability.set_id("CVE-2024-1234")
vulnerability.set_value("purl", "pkg:pypi/defusedxml@0.7.1")
vulnerability.set_status("under_investigation")
vulnerabilities.append(vulnerability.get_vulnerability())
# This vulnerability doesn't apply to the product as component not included in this version of the SBOM
vulnerability.initialise()
vulnerability.set_id("CVE-2024-0987")
vulnerability.set_name("Spring")
vulnerability.set_release("3.2.1")
vulnerability.set_status("under_investigation")
vulnerabilities.append(vulnerability.get_vulnerability())

# Generate VEX document
vexgen.generate(project_name="ACME_Infusion", vex_data = vulnerabilities, metadata = metadata, filename=f"samples/{vextype}/acme_1.0_vex.json")


