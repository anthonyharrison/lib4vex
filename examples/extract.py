from lib4vex.parser import VEXParser
import sys
vextype=sys.argv[1]
filename=sys.argv[2]

vexparser = VEXParser(vex_type=vextype)
vexparser.parse(filename)
print("METADATA",vexparser.get_metadata())
# {'version': '2.0', 'title': 'ACME-INFUSION-1.0-VEX Use Case complete', 'category': 'csaf_vex', 'date': '2024-03-20T21-05-40Z', 'notes': [{'title': 'Author Comment', 'text': 'ACME INFUSION PoC II VEX document. Unofficial content for demonstration purposes only.', 'category': 'other'}], 'publisher': 'APH_Division http://www.hospitalproducts.acme', 'author': 'APH_Division', 'author_url': 'http://www.hospitalproducts.acme', 'contact_details': 'Fred Flintstone, fredflintstone@acme.com', 'generator': 'csaf-tool version 0.2.1', 'id': 'ACME-INFUSION-1.0-VEX', 'initial_release_date': '2024-03-20T21-05-40Z', 'revision': [{'date': '2024-03-20T21-05-40Z', 'number': '1', 'summary': 'Initial version'}], 'tracking_status': 'draft', 'tracking_version': '1'}
print("PRODUCT",vexparser.get_product())
# {'CSAFPID_0001': {'vendor': 'APH_Division', 'product': 'ACME-Infusion', 'version': '1.0', 'family': ''}}
print("VULNS",vexparser.get_vulnerabilities())
# [{'id': 'CVE-2023-12345', 'description': 'https://nvd.nist.gov/vuln/detail/CVE-2023-12345', 'created': '2024-03-20T21-05-40Z', 'Product': 'CSAFPID_0001', 'status': 'under_investigation'}, {'id': 'CVE-2024-1234', 'description': 'https://nvd.nist.gov/vuln/detail/CVE-2024-1234', 'created': '2024-03-20T21-05-40Z', 'Product': 'CSAFPID_0001', 'status': 'under_investigation'}]
