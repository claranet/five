""" Five global exceptions """

from icontrol.exceptions import iControlUnexpectedHTTPError

class BigipNotSet(AttributeError):
    """ Raised when bigip is not set and try to use an object's method that need it """
    pass

class ContextNotFound(EnvironmentError):
    """ Raised when bigip or Infra does not find a context for a given Object """
    pass

class NotImplementedMonitor(NotImplementedError):
    """ Raised when try to init a Monitor that is not supported """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.message = getattr(self, 'message', 'only http, https, ftp, icp, tcp, tcp_half_open, udp are supported')

class NotImplementedPersistence(NotImplementedError):
    """ Raised when try to init a Monitor that is not supported """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.message = getattr(self, 'message', 'only cookie, dest-addr, source-addr, hash, ssl, universal are supported')

class NotImplementedProfile(NotImplementedError):
    """ Raised when try to init a Profile that is not supported """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.message = getattr(self, 'message', 'only tcp, udp, fastl4, one_connect, ftp, http, http2, client_ssl, server_ssl are supported')

class AlreadyExist(iControlUnexpectedHTTPError):
    """
    Raised when a resource already exist
    it is the iControlUnexpectedHTTPError 409 - Conflict
    """
    pass

class NotFound(iControlUnexpectedHTTPError):
    """
    Raised when a resource does not Exist
    it is the iControlUnexpectedHTTPError 404 - Not Found
    """
