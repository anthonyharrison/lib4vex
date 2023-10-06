from lib4vex.generator import VEXGenerator
from lib4sbom.data.vulnerability import Vulnerability

vextype="csaf"

vexgen = VEXGenerator(vex_type=vextype)

vulnerabilities = []

vulnerability = Vulnerability(validation=vextype)
vulnerability.set_id("CVE-2020-2345")
vulnerability.set_name("Spring")
vulnerability.set_release("3.2.1")
vulnerability.set_value("vendor", "Spring Inc.")
vulnerability.set_value("bom-ref", "spring@3.2.1")
vulnerability.set_status("fixed")
vulnerability.set_comment("Rebuild with latest compiler")
vulnerabilities.append(vulnerability.get_vulnerability())

vulnerability.initialise()
vulnerability.set_id("CVE-2023-1235")
vulnerability.set_name("Windows")
vulnerability.set_release("2022H2")
vulnerability.set_value("vendor", "Microsoft")
vulnerability.set_value("bom-ref", "windows@2022H2")
vulnerability.set_status("under_investigation")
vulnerabilities.append(vulnerability.get_vulnerability())

# Generate document
vexgen.generate(project_name="Demo", vex_data = vulnerabilities, filename=f"/tmp/vex_{vextype}.json")



