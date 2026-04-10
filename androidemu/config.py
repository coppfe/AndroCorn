import json

from .data.models.pkg import Pkg

class Config:

    def __init__(self, cfg_path):
        with open(cfg_path) as f:
            data = json.load(f)
        self.pkg = Pkg(**data)