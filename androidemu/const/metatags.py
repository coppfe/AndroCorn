# For code beauty
# Contains void decorators

from __future__ import annotations

def PROXY(func):
    """
    Function with this tag calling another function
    """
    func.__PROXY__ = True
    return func

def STUB(func):
    """
    Function with this tag does not have a real implementation of method
    """
    func.__STUB__ = True
    return func