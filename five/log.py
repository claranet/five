"""
Logging and debug
"""

import logging
from logging.handlers import RotatingFileHandler
logging.VERBOSE = 9

class Log(object):
    def __init__(self, logfile=None, console=False, level='WARNING'):
        map_level = {'VERBOSE':logging.VERBOSE,
                     'DEBUG':logging.DEBUG,
                     'INFO':logging.INFO,
                     'WARNING':logging.WARNING,
                     'ERROR':logging.ERROR,
                     'CRITICAL':logging.CRITICAL}
        self.logfile = logfile
        self.console = console
        #-- logger
        self.logger = logging.Logger(__name__)
        self.logger.handlers = list()
        self.logger.setLevel(map_level.get(level))
        #-- log format for file
        formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
        if self.logfile:
            #one file in mode : 'append' + max size : 10Mo
            file_handler = RotatingFileHandler(self.logfile, 'a', 10000000, 1)
            file_handler.setLevel(map_level.get(level))
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        if self.console:
            stream_handler = logging.StreamHandler()
            stream_handler.setLevel(map_level.get(level))
            stream_handler.setFormatter(formatter)
            self.logger.addHandler(stream_handler)

    def verbose(self, msg):
        self.logger.log(logging.VERBOSE, msg)

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)

    def critical(self, msg):
        self.logger.critical(msg)
