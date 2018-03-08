#coding: utf-8
import logging
from time import sleep

#import threading
#from multiprocessing.dummy import Pool as ThreadPool
from apscheduler.schedulers.background import BackgroundScheduler

from f5.bigip import BigIP
from icontrol.exceptions import iControlUnexpectedHTTPError

from five import log
from five.utils import import_conf
from five.bigip import Bigip

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Infra(object):
    def __init__(self, conf, interval=30):
        """
        :param conf: conf file (yaml or json) load as dictionnary
        :key equipments: list of equipments
        :key user: username for all bigip
        :key passwd: password for all bigip
        :key debug: if True, debug on console
        :key debug_file: absolute to log file
        """
        self.log = log
        self.equipments = list()
        self.load_equipments(conf)
        if interval:
            self.thread = self.reload_bigips(interval=interval)
        else:
            self.thread = None

    def load_equipments(self, conf):
        for host in conf.get('equipments', list()):
            try:
                self.equipments.append(Bigip(host, user=conf.get('user'), passwd=conf.get('passwd')))
                self.log.info('load : {}'.format(host))
            except iControlUnexpectedHTTPError:
                self.log.warning('unable to load : {}'.format(host))

    @property
    def contexts(self):
        return [context for bigip in self.equipments for context in bigip.contexts]

    @staticmethod
    def _reload_bigip(bigip):
        bigip.log.info('{} : scheduled reload configuration'.format(bigip))
        bigip.load()

    def reload_bigips(self, interval=30):
        sched = BackgroundScheduler()
        for host in self.equipments:
            sched.add_job(self._reload_bigip, 'interval', [host], minutes=interval, id=host.hostname)
        sched.start()
        return sched

    def search_context(self, searched):
        """
        return list of tuple as (Context, Bigip)
        """
        finds = list()
        for bigip in self.equipments:
            find = bigip.search_context(searched)
            if find:
                for f in find:
                    finds.append((f,bigip))
        return finds

    def retreive_uniq_context(self, searched):
        """
        :return True, Context: Bigip: if only one context is find
        :return False, results: None: if no context or more than one is return with results as list of tuple [(Context,
        Bigip), .. ]
        """
        results = self.search_context(searched)
        if len(results) == 1:
            return True, results[0][0], results[0][1]
        else:
            return False, results, None
