from .models.pkg import Pkg

class Config:

    def __init__(self, data):
        if isinstance(data, dict):
            self.pkg = Pkg(**data)
        else:
            raise TypeError("Data must be a dict. Passed: %s" % type(data))