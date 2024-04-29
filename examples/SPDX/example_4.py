from lib4vex.generator import VEXGenerator
from lib4sbom.data.vulnerability import Vulnerability

vextype="spdx"

vexgen = VEXGenerator(vex_type=vextype, author="APH_Division")
vexgen.set_product(name="ACME-Infusion", release="1.0", sbom="samples/example.json")

metadata={}
metadata["revision_reason"] = "Confirmed that vulnerability CVE-2024-6789 is exploitable"

# Update VEX Statement
vulnerability = Vulnerability(validation=vextype)
vulnerabilities = []
# Specify vulnerability by product name/version
vulnerability.initialise()
vulnerability.set_id("CVE-2024-6789")
vulnerability.set_name("pyyaml")
vulnerability.set_release("6.0.1")
vulnerability.set_status("affected")
vulnerability.set_comment("The payload could be manipulated leading to a DDOS attack on the product.")
vulnerability.set_remediation("vendor_fix")
vulnerability.set_action("Upgrade to version 6.0.2.")
vulnerabilities.append(vulnerability.get_vulnerability())

# Generate VEX document. As VEX already exists, file will be updated
vexgen.generate(project_name="ACME_Infusion", vex_data = vulnerabilities, metadata = metadata, filename=f"samples/{vextype}/acme_1.0_vex.json")
