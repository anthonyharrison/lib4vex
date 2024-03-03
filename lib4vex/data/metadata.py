class VEXMetadata:

    def __init__(self):
        self.metadata = {}

    def set_metadata(self, metadata):
        self.metadata = metadata

    def show_metadata(self):
        for key in self.metadata:
            print (f"{key} : {self.metadata[key]}")

    def get_metadata(self):
        return self.metadata

    def get_attribute(self, attribute):
        return self.metadata.get(attribute)

    def get_title(self):
        return self.get_attribute("titled")

    def get_date(self):
        return self.get_attribute("date")

    def get_revision(self):
        return self.get_attribute("revision")

    def get_status(self):
        return self.get_attribute("tracking_status")

    def get_version(self):
        return self.get_attribute("tracking_version")