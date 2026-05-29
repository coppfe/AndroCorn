import logging

def success(name):
    def f(*args, **kwargs):
        logging.warning(f"Called mocked func `{f.__name__}`")
        return 0
    f.__name__ = name
    return f