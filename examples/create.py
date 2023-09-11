from lib4vex.generator import VEXGenerator
from lib4sbom.data.vulnerability import Vulnerability

vexgen = VEXGenerator(vex_type="cyclonedx")

vulnerabilities = []

vulnerability = Vulnerability(validation="cyclonedx")
vulnerability.set_id("CVE-2020-2345")
vulnerability.set_name("Spring")
vulnerability.set_release("3.2.1")
vulnerability.set_value("bom-ref", "spring@3.2.1")
vulnerability.set_status("fixed")
vulnerability.set_comment("Rebuild with latest compiler")
vulnerabilities.append(vulnerability.get_vulnerability())

vulnerability = Vulnerability(validation="cyclonedx")
vulnerability.set_id("CVE-2023-1235")
vulnerability.set_name("Windows")
vulnerability.set_release("2022H2")
vulnerability.set_value("bom-ref", "windows@2022H2")
vulnerability.set_status("under_investigation")
vulnerabilities.append(vulnerability.get_vulnerability())

# Generate document
vexgen.generate(project_name="Demo", vex_data = vulnerabilities)



