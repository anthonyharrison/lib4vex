from lib4vex.generator import VEXGenerator
from lib4sbom.data.vulnerability import Vulnerability

vextype="cyclonedx"

vexgen = VEXGenerator(vex_type=vextype, author="APH_Division")
vexgen.set_product(name="ACME-Infusion", release="1.0", sbom="samples/example.json")

metadata={}
# Only updated metadata
metadata["revision_reason"] = "Product Review initiated."

# Update VEX Statement
vulnerability = Vulnerability(validation=vextype)
vulnerabilities = []
# Specify vulnerability by product name/version
vulnerability.initialise()
vulnerability.set_id("CVE-2023-12345")
vulnerability.set_name("pyyaml")
vulnerability.set_release("6.0.1")
vulnerability.set_status("not_affected")
# Justify decision
vulnerability.set_justification("code_not_reachable")
vulnerabilities.append(vulnerability.get_vulnerability())

# Generate VEX document. As VEX already exists, file will be updated
vexgen.generate(project_name="ACME_Infusion", vex_data = vulnerabilities, metadata = metadata, filename=f"samples/{vextype}/acme_1.0_vex.json")
