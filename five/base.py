#coding: utf-8
from functools import wraps
from contextlib import contextmanager

from five import log
from five.exceptions import BigipNotSet

class Base():
    def __init__(self):
        self.log = log
        self._current_bigip = None

    def check_current_bigip(func):
        """
        Decorator to check if bigip is set.
        Used to all function which talk to a F5
        """
        @wraps(func)
        def inner(self, *args, **kwargs):
            if not hasattr(self, '_current_bigip') or getattr(self, '_current_bigip') == None:
                raise BigipNotSet('You have to use with current_bigip context manager')
            return func(self, *args, **kwargs)
        return inner

    @contextmanager
    def current_bigip(self, bigip):
        """
        :param bigip: Real bigip object from f5-sdk
        """
        self._current_bigip = bigip
        #self.load()
        yield
        self._current_bigip = None

    check_current_bigip = staticmethod(check_current_bigip)

