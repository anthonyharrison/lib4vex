from lib4vex.parser import VEXParser
from lib4sbom.data.vulnerability import Vulnerability
from lib4vex.data.product import VEXProduct
from lib4vex.data.metadata import VEXMetadata
import sys

vextype=sys.argv[2]

print (f"Vextype {vextype}")
vexparser = VEXParser(vex_type=vextype)
# Read VEX file
vexparser.parse(sys.argv[1])

# Extract key elements of VEX document
vexmetadata=VEXMetadata()
vexmetadata.set_metadata(vexparser.get_metadata())
print ("METADATA===========")
print(vexmetadata.show_metadata())
# Product information
product=vexparser.get_product()
print ("PRODUCT=============")
print(product)

for key in product:
    vexproduct = VEXProduct()
    vexproduct.set_product(key,product[key])
    print (f"VEX document for {vexproduct.get_name()} release {vexproduct.get_release()} produced on {vexmetadata.get_date()}")

# Reported vulnerabilities
vulnerabilities=vexparser.get_vulnerabilities()
print ("VULNERABILITY STATUS")
print ("====================")
print(vulnerabilities)
print ("\n")
for v in vulnerabilities:
    print(v)
    print ("ID", v.get("id"))
    print ("Last update", v.get('created'))
    print ("Description", v.get("description"))
    print ("Status", v.get("status"))
    if v.get("justification") is not None:
        print ("Justification", v.get("justification"))