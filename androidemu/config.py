import json

class Config:

    def __init__(self, cfg_path):
        with open(cfg_path) as f: data = json.load(f)
        self.__configs = data

    def get(self, key, def_val=None):
        if (key in self.__configs):
            return self.__configs[key]
        return def_val