from lib4vex.generator import VEXGenerator
from lib4sbom.data.vulnerability import Vulnerability

vextype="csaf"

vexgen = VEXGenerator(vex_type=vextype, author="APH_Division")
vexgen.set_product(name="ACME-Infusion", release="1.0", sbom="samples/example.json")

metadata={}
metadata["revision_reason"] = "New vulnerability CVE-2024-6789 detected."

# Update VEX Statement
vulnerability = Vulnerability(validation=vextype)
vulnerabilities = []
# Specifiy vulnerability by product name/version
vulnerability.initialise()
vulnerability.set_id("CVE-2024-6789")
vulnerability.set_name("pyyaml")
vulnerability.set_release("6.0.1")
vulnerability.set_status("under_investigation")
vulnerabilities.append(vulnerability.get_vulnerability())

# Generate VEX document. As VEX already exists, file will be updated
vexgen.generate(project_name="ACME_Infusion", vex_data = vulnerabilities, metadata = metadata, filename=f"samples/{vextype}/acme_1.0_vex.json")
