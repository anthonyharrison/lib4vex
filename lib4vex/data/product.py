class VEXProduct:

    def __init__(self):
        self.product = {}

    def set_product(self, id, product):
        self.product = product
        self.product['id'] = id
        #for key in product:
        #    self.product[key] = product[key]

    def show_product(self):
        for key in self.product:
            print (f"{key} : {self.product[key]}")

    def get_product(self):
        return self.product

    def get_attribute(self, attribute):
        return self.product.get(attribute)

    def get_id(self):
        return self.get_attribute("id")

    def get_vendor(self):
        return self.get_attribute("vendor")

    def get_name(self):
        return self.get_attribute("product")

    def get_release(self):
        return self.get_attribute("version")