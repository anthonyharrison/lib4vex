from lib4vex.generator import VEXGenerator
from lib4sbom.data.vulnerability import Vulnerability

vextype="csaf"

##   Document metadata
#doc_id: ACME-INFUSION-1.0-VEX-DRAFT                DONE
#doc_version: v1.0                                  Not aligned with generated Document
#author: ACME-Hospital-Division                     Not aligned with generated document (no URL)
#doc_time_first_issued: 2021-04-27T18:00:00Z
#doc_time_last_updated: 2023-06-07T18:00:00Z
## Additional metadata
#AuthorComment:  Draft ACME INFUSION PoC II VEX document. Unofficial content for demonstration purposes only.
#SupplierContact: Fred Flinstone, fredflinstone@acme.com
### EXTRA
# Title                                              Not in TXT file

vexgen = VEXGenerator(vex_type=vextype, author="ACME-Hospital-Division")

vexgen.set_product(name="ACME Infusion", release="1.0", sbom="samples/ACME-INFUSION-1-0.cdx.json")
#vexgen.set_product(name="ACME Infusion", release="1.0", sbom="")
#vexgen.set_product(name="ACME Infusion", release="1.0", sbom="samples/example.json")

metadata={}
metadata["id"]="ACME-INFUSION-1.0-VEX-DRAFT"
metadata["title"]="ACME-INFUSION-1.0-VEX-DRAFT Use Case complete"
metadata["comment"]="Draft ACME INFUSION PoC II VEX document. Unofficial content for demonstration purposes only."
metadata["supplier"]="Fred Flintstone"
metadata["supplier_url"]="fredflintstone@acme.com"
metadata["author_url"]="http://www.hospitalproducts.acme"
metadata["status"]="draft"
#metadata["revision_reason"]="Update following software assessment"

vulnerabilities = []

# supplier: Microsoft
# ComponentName: Windows Embedded Standard 7 with SP1 patches
# VersionString: 3.0
# UniqueIdentifier: CPE cpe:2.3:o:microsoft:windows_7:sp1:*:*:*:*:*:*:*
# ##    Vulnerabilility details
# vul_id: CVE-2017-0144
# vul_description: https://nvd.nist.gov/vuln/detail/cve-2017-0144
# ##    Status
# status: not_affected   **** NOT VALID STATUS ****
# impact_statement: "The SMB service is turned off.
#                    The medical device restricts acess to the O/S to field service personnel.
# 				   The medical devices is segmented from the hospital network through the use of an instrument firewall.
# 				   The medical device only allows the installation/execution of known/trusted components."
# justification: Vulnerable_code_cannot_be_controlled_by_adversary

vulnerability = Vulnerability(validation=vextype)
vulnerability.set_id("CVE-2017-0144")
vulnerability.set_value("description","https://nvd.nist.gov/vuln/detail/cve-2017-0144")
#vulnerability.set_name("Windows Embedded Standard 7 with SP1 patches")
#vulnerability.set_release("3.0")
vulnerability.set_value("purl","pkg:pypi/lib4vex@0.1.0")
#vulnerability.set_value("vendor", "Microsoft")
#vulnerability.set_value("bom-ref", "cpe:2.3:o:microsoft:windows_7:sp1:*:*:*:*:*:*:*")
vulnerability.set_status("known_not_affected")
vulnerability.set_value("justification","Vulnerable_code_cannot_be_controlled_by_adversary")
vulnerability.set_comment("The SMB service is turned off. The medical device restricts acesss to the O/S to field service personnel. The medical devices is segmented from the hospital network through the use of an instrument firewall. The medical device only allows the installation/execution of known/trusted components.")
vulnerabilities.append(vulnerability.get_vulnerability())

##    Product details [subcomponent_id]
# supplier: Bob
# ComponentName: Bobs Browser
# VersionString: v12.1
# UniqueIdentifier: purl pkg:generic/Bob/Bobs-Browser@12.1
# ##     Vulnerability details
# vul_id: CVE-2023-1000
# vul_description: Artificial CVE for Bobs Browser
# ##    Status
# status: under_investigation

vulnerability.initialise()
vulnerability.set_id("CVE-2023-1000")
vulnerability.set_value("description","Artificial CVE for Bobs Browser")
vulnerability.set_name("Bobs Browser")
vulnerability.set_release("v12.1")
#vulnerability.set_value("vendor", "Bob")
#vulnerability.set_value("bom-ref", "pkg:generic/Bob/Bobs-Browser@12.1")
vulnerability.set_status("under_investigation")
vulnerabilities.append(vulnerability.get_vulnerability())


# Generate document
vexgen.generate(project_name="Demo", vex_data = vulnerabilities, metadata=metadata, filename=f"/tmp/vex_{vextype}.json")

#vexgen.set_type("cyclonedx")
#vexgen.generate(project_name="Demo", vex_data = vulnerabilities, metadata=metadata, filename=f"/tmp/vex_cdx.json")

#vexgen.set_type("openvex")
#vexgen.generate(project_name="Demo", vex_data = vulnerabilities, metadata=metadata, filename=f"/tmp/vex_ovx.json")


