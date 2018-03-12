#coding: utf-8
from functools import wraps
from copy import copy
from random import random
from five import log

from five.base import Base
from five.net import NetResource
from five.ltm import Node, Member, Pool, Virtual
from five.ltm import Monitor, Profile, Persistence, Rule, Policy
from five.ltm import Snat, Translation
from five.utils import save_file_from_base64
from five.exceptions import BigipNotSet, ContextNotFound, AlreadyExist

## see to replace with Five Exception
from icontrol.exceptions import iControlUnexpectedHTTPError

class Archi(Base):
    """
    Object used to create a full virtual IP architecture
    create nodes if there not exist
    create pools if there not exist
    create virtuals using define pools
    add snat / translation if can find listen vlan
    """

    ## see to implement this with a possible overwritte ..
    node_format = 'nd_{name}'           #
    pool_format = 'pl_{basename}_port-{port}{suffix}'
    virtual_format = 'vs_{basename}_{proto}-{port}{suffix}'
    snat_format = 'snat-out_{name}'

    def __init__(self, infra, **kwargs):
        """
        :param infra: Five Infra
        :param basename:
        :param address:
        :param nodes:
        :param services:
        [OPT]
        :param suffix:
        :param no_snat:
        ...
        """
        self.log = log
        ##### RETREIVE ARGS ######################################
        self.infra = infra
        self.basename = kwargs.pop('basename', None)
        self.address = kwargs.pop('address', None)
        self.raw_nodes = kwargs.pop('nodes', None)
        self.raw_services = kwargs.pop('services', None)
        ###
        self.raw_rules = kwargs.pop('rules', None)
        self.raw_profiles = kwargs.pop('profiles', None)
        self.raw_policies = kwargs.pop('policies', None)
        self.raw_persistences = kwargs.pop('persistences', None)
        self.raw_monitors = kwargs.pop('monitors', None)
        ###

        if not self.basename or not self.address or not self.raw_nodes or not self.raw_services:
            raise ValueError('You have to define at least : basename, address, nodes and services')
        self.suffix = kwargs.pop('suffix', '')
        self.no_snat = kwargs.pop('no_snat', None)
        ##### Try to parse raw archi
        self._set_archi()

    @property
    @Base.check_current_bigip
    def current_user(self):
        return self._current_bigip._meta_data.get('username')

    def _retreive_context(self):
        """
        retreive context on infra with node IP
        :return: context and Bigip object
        """
        success, context, bigip = self.infra.retreive_uniq_context(self.nodes[0])
        if success:
            self.context = context
            self.bigip = bigip
            self.route_domain = context.route_domain
            self.ref_bigip = bigip.ref_bigip
            ## usefull ? .. to see .. 
            self.partition = context.partition
            return self.ref_bigip
        else:
            self.log.warning('ContextNotFound: Archi with nodes : {}'.format(self.raw_nodes))
            raise ContextNotFound

    @staticmethod
    def _clean_dict_none_values(data):
        ## clean all keys with None value
        for k, v in copy(data).items():
            if v == None:
                del data[k]
        return data

    def _set_pool_name(self, port, d_data):
        ## set generic name
        port = d_data.get('pool_port', port)
        # suffix overwritte
        suffix = d_data.get('suffix', self.suffix)  # suffix in service overwritte global suffix
        suffix = d_data.get('pool_suffix', suffix)  # pool_suffix overwritte the service suffix
        # basename overwritte
        basename = d_data.get('basename', self.basename) # basename in service overwritte global suffix
        basename = d_data.get('pool_basename', basename) # pool_basename in service overwritte service basename
        _format = {'basename':basename, 'suffix':suffix, 'port':port}
        return self.pool_format.format(**_format)

    def _set_virtual_name(self, port, d_data):
        suffix = d_data.get('suffix', self.suffix)
        if d_data.get('internal'):
            suffix += '_int'
        basename = d_data.get('basename', self.basename)
        proto = d_data.get('ipProtocol', 'tcp')
        _format = {'basename':basename, 'proto':proto, 'suffix':suffix, 'port':port}
        return self.virtual_format.format(**_format)

    def _parse_pool_params(self, port, d_data):
        """
        retreive pool params and overwritte pool param.
        return a dummy Pool object
        """
        ## see to implement all possible pool params
        params = ['allowNat',
                  'allowSnat',
                  'ignorePersistedWeight',
                  'ipTosToClient',
                  'ipTosToServer',
                  'linkQosToClient',
                  'linkQosToServer',
                  'loadBalancingMode',
                  'members',
                  'minActiveMembers',
                  'minUpMembers',
                  'minUpMembersAction',
                  'minUpMembersChecking',
                  'monitor',
                  'queueDepthLimit',
                  'queueOnConnectionLimit',
                  'queueTimeLimit',
                  'reselectTries',
                  'serviceDownAction',
                  'slowRampTime']
        self.log.debug(f'{self.basename} : _parse_pool_params - {port} raw_data : {d_data}')
        ## set port to pool_port, else use the virtual port
        ## all members will be configured to used this port
        port = d_data.get('pool_port', port)
        ## retreive pool params
        d_pool = {param:d_data.get(param) for param in params if param in d_data}
        ## check monitor : if not set --> tcp (if set to None, it will be not pushed)
        if 'monitor' not in d_data.keys():
            d_pool['monitor'] = 'tcp'
        ## set generic name
        name = self._set_pool_name(port, d_data)
        ## set pool dict 
        d_pool.update({'name': name,
                       'members': d_data.get('members', ['{}:{}'.format(node.name, port) for node in self.nodes]),
                       'description':d_data.get('pool_description', d_data.get('description'))})
        #d_pool = self._clean_dict_none_values(d_pool)
        self.log.debug('archi {} - parse_pool_params {}'.format(self.basename, d_pool))
        return Pool(**d_pool)

    def _parse_virtual_param(self, port, d_data):
        params = ['addressStatus',  # readonly attr ? 
                  'autoLasthop',
                  'cmpEnabled',
                  'connectionLimit',
                  'destination',
                  'enabled',        # pair enable/disable --> to see
                  'gtmScore',
                  'ipProtocol',
                  'mask',
                  'mirror',
                  'mobileAppTunnel',
                  'nat64',
                  'pool',
                  'rateLimit',
                  'rateLimitDstMask',
                  'rateLimitMode',
                  'rateLimitSrcMask',
                  'rules',
                  'profiles',
                  'policies',
                  'serviceDownImmediateAction',
                  'source',
                  'sourceAddressTranslation',
                  'sourcePort',
                  'synCookieStatus',
                  'translateAddress',
                  'translatePort',
                  'vlansDisabled',   # pair vlansEnabled / vlansDisabled --> to see
                  'vlans',
                  'stateless',
                  'persist'
                 ]
        self.log.debug(f'{self.basename} : _parse_virtual_params - {port} raw_data : {d_data}')
        ## pool and virtual anme
        pool_name = self._set_pool_name(port, d_data)
        virtual_name = self._set_virtual_name(port, d_data)
        ## virtuals params
        d_virtual = {param:d_data.get(param) for param in params if param in d_data}
        self.log.debug('archi {} - parse_virtual_param {}'.format(self.basename, d_virtual))
        ## checks vlans
        vlans_ena = d_data.get('vlansEnabled')
        vlans_dis = d_data.get('vlansDisabled')
        if not vlans_ena and not vlans_dis:
            d_virtual.update({'vlansEnabled': True})
        ## listen vlans
        ## add provided list of vlans and try to guess if there is not
        vlans = d_data.get('vlans', [])
        ## if 'internal' listen vlan of the member node
        if not vlans and d_data.get('internal'):
            internal_vlan = self.context.int_vlan(self.nodes[0])
            if internal_vlan:
                vlans.append(internal_vlan)
        elif not vlans and self.context.ext_vlan:
                vlans.append(self.context.ext_vlan)
        d_virtual.update({'vlans':vlans})
        ## snat
        if d_data.get('internal'):
            d_virtual.update({'sourceAddressTranslation':{'type':'automap'}})
        ## last update
        d_virtual.update({'name': virtual_name,
                          'address': self.address,
                          'port': port,
                          'pool': d_data.get('pool', pool_name),
                          'route_domain': self.route_domain})
        #d_virtual = self._clean_dict_none_values(d_virtual)
        return Virtual(**d_virtual)

    def _parse_raw_monitors(self):
        """
        Parse raw monitor and return list of dummy monitor object
        """
        monitors = list()
        try:
            for name, data in self.raw_monitors.items():
                monitors.append(Monitor(name=name, **data))
        except AttributeError:
            pass
        return monitors

    def _parse_raw_nodes(self):
        """
        Parse raw nodes and return list of dummy node object
        """
        ## implement format name here ? conf file ? 
        nodes = list()
        for name, data in self.raw_nodes.items():
            if isinstance(data, (str, bytes)):
                nodes.append(Node(name=name, address=data))
            else:
                nodes.append(Node(name=name, **data))
        return nodes

    def _parse_raw_snats(self):
        """
        create snat object from dummy node object
        """
        snats = list()
        origins = list()
        for snat in self.bigip.snats:
            origins.extend([ori['name'] for ori in snat.origins])
        for node in self.nodes:
            if node.address+'/32' not in origins:
                d_snat = {'name': self.snat_format.format(name=node.name),
                          'origins': ['%s/32' % node.address],
                          'translation': '{}%{}'.format(self.address, self.route_domain)}
                snats.append(Snat(**d_snat))
        return snats

    def _parse_raw_pools(self):
        pools = list()
        for service, data in self.raw_services.items():
            pool = self._parse_pool_params(service, data)
            if pool.name not in [pl.name for pl in pools]:
                pools.append(pool)
        return pools

    def _parse_raw_persistences(self):
        """
        Parse raw monitor and return list of dummy monitor object
        """
        persistences = list()
        try:
            for name, data in self.raw_persistences.items():
                persistences.append(Persistence(name=name, **data))
        except AttributeError:
            pass
        return persistences

    def _parse_raw_rules(self):
        """
        Parse raw monitor and return list of dummy monitor object
        """
        rules = list()
        try:
            for name, data in self.raw_rules.items():
                rules.append(Rule(name=name, **data))
        except AttributeError:
            pass
        return rules

    def _parse_raw_profiles(self):
        """
        Parse raw profiles and return list of dummy profiles object
        """
        profiles = list()
        try:
            for name, data in self.raw_profiles.items():
                profiles.append(Profile(name=name, **data))
        except AttributeError:
            pass
        return profiles

    def _parse_raw_virtuals(self):
        virtuals = list()
        for service, data in self.raw_services.items():
            ## internal
            if 'internal' in data.get('types', []):
                intdata = copy(data)
                intdata.update({'internal':True})
                virtual = self._parse_virtual_param(service, intdata)
                if virtual.name not in [vs.name for vs in virtuals]:
                    virtuals.append(virtual)
            ## external
            if 'external' in data.get('types', []) or not data.get('types'):
                virtual = self._parse_virtual_param(service, data)
                if virtual.name not in [vs.name for vs in virtuals]:
                    virtuals.append(virtual)
        return virtuals

    def _parse_raw_services(self):
        pools = self._parse_raw_pools()
        virtuals = self._parse_raw_virtuals()
        return pools, virtuals

    def _set_archi(self):
        """
        Parse raw_nodes and raw_services in order to provide Node, Pool and Virtual dummy object
        Retreive context in order to retreive bigip and partition
        Set bigip and partition for all dummy resources
        """
        #parse monitors
        self.monitors = self._parse_raw_monitors()
        #parse nodes
        self.nodes = self._parse_raw_nodes()
        # retreive context
        self._retreive_context()
        #parse service for pool and virtuals
        self.pools, self.virtuals = self._parse_raw_services()
        self.rules = self._parse_raw_rules()
        self.persistences = self._parse_raw_persistences()
        self.profiles = self._parse_raw_profiles()
        # set resources
        self.resources = list()
        self.resources.extend(self.monitors)
        self.resources.extend(self.nodes)
        self.resources.extend(self.pools)
        self.resources.extend(self.persistences)
        self.resources.extend(self.rules)
        self.resources.extend(self.profiles)
        self.resources.extend(self.virtuals)
        if not self.no_snat:
            self.snats = self._parse_raw_snats()
            self.resources.extend(self.snats)
        # set context
        for res in self.resources:
            self._set_context(res)

    def _set_context(self, res):
        res.bigip = self.bigip
        res.partition = self.partition
        if isinstance(res, NetResource):
            res.route_domain = self.route_domain

    @Base.check_current_bigip
    def create_monitors(self):
        errors = dict()
        monitors = list()
        for monit in self.monitors:
            with monit.current_bigip(self._current_bigip):
                try:
                    monit.create()
                    monitors.append(monit)
                    self.bigip.monitors.append(monit)
                except AlreadyExist:
                    monitors.append(monit)
                except iControlUnexpectedHTTPError as e:
                    errors.update({monit.name: e.response._content})
                    self.log.warning(f'{self} - {monit} : UnexpectedError : {e.response._content}')
        if len(errors) == len(self.monitors):
            return False, errors
        else:
            return True, errors

    @Base.check_current_bigip
    def create_nodes(self):
        errors = dict()
        nodes = list()
        for nd in self.nodes:
            with nd.current_bigip(self._current_bigip):
                try:
                    nd.create()
                    nodes.append(nd)
                    self.bigip.nodes.append(nd)
                except AlreadyExist:
                    nodes.append(nd)
                except iControlUnexpectedHTTPError as e:
                    errors.update({nd.name: e.response._content})
                    self.log.warning(f'{self} - {nd} : UnexpectedError : {e.response._content}')
        if len(errors) == len(self.nodes):
            return False, errors
        else:
            return True, errors

    @Base.check_current_bigip
    def create_pools(self):
        errors = dict()
        pools = list()
        for pl in self.pools:
            with pl.current_bigip(self._current_bigip):
                try:
                    pl.create()
                    pools.append(pl)
                    self.bigip.pools.append(pl)
                except AlreadyExist:
                    pools.append(pl)
                except iControlUnexpectedHTTPError as e:
                    errors.update({pl.name: e.response._content})
                    self.log.warning(f'{self} - {pl} : UnexpectedError : {e.response._content}')
        if len(errors) == len(self.pools):
            return False, errors
        else:
            return True, errors

    @Base.check_current_bigip
    def create_rules(self):
        errors = dict()
        rules = list()
        for rule in self.rules:
            with rule.current_bigip(self._current_bigip):
                try:
                    rule.create()
                    rules.append(rule)
                    self.bigip.rules.append(rule)
                except AlreadyExist:
                    rules.append(rule)
                except iControlUnexpectedHTTPError as e:
                    errors.update({rule.name: e.response._content})
                    self.log.warning(f'{self} - {rule} : UnexpectedError : {e.response._content}')
        if len(errors) == len(self.rules):
            return False, errors
        else:
            return True, errors

    @Base.check_current_bigip
    def create_persistences(self):
        errors = dict()
        persistences = list()
        for persistence in self.persistences:
            with persistence.current_bigip(self._current_bigip):
                try:
                    persistence.create()
                    persistences.append(persistence)
                    self.bigip.persistences.append(persistence)
                except AlreadyExist:
                    persistences.append(persistence)
                except iControlUnexpectedHTTPError as e:
                    errors.update({persistence.name: e.response._content})
                    self.log.warning(f'{self} - {persistence} : UnexpectedError : {e.response._content}')
        if len(errors) == len(self.persistences):
            return False, errors
        else:
            return True, errors

    def _create_ssl_files(self, profile):
        name = profile.create_files
        del profile.create_files
        alea = int(random()*1000000)
        ## create local files
        key_local_path = '/var/tmp/key'
        cert_local_path = '/var/tmp/crt'
        chain_local_path = '/var/tmp/chain'
        save_file_from_base64(profile.key.encode(), key_local_path)
        save_file_from_base64(profile.cert.encode(), cert_local_path)
        with self.bigip.current_bigip(self._current_bigip):
            ## upload files
            key_path = self.bigip.upload_file(key_local_path)
            cert_path = self.bigip.upload_file(cert_local_path)
            ## create certs
            key, real_key = self.bigip.create('Ssl_key', name=f'{name}.{alea}', sourcePath=key_path, partition=self.partition)
            cert, real_cert = self.bigip.create('Ssl_cert', name=f'{name}.{alea}', sourcePath=cert_path, partition=self.partition)
            ## update profile
            profile.key = real_key.fullPath
            profile.cert = real_cert.fullPath
            ## for chain
            if hasattr(profile, 'chain'):
                save_file_from_base64(profile.chain.encode(), chain_local_path)
                chain_path = self.bigip.upload_file(chain_local_path)
                chain, real_chain = self.bigip.create('Ssl_cert', name=f'{name}.{alea}.chain', sourcePath=chain_path, partition=self.partition)
                profile.chain = real_chain.fullPath

    @Base.check_current_bigip
    def create_profiles(self):
        errors = dict()
        profiles = list()
        ssls = [pr for pr in self.profiles if pr._type in ['client_ssl', 'server_ssl'] if hasattr(pr, 'create_files')]
        for ssl in ssls:
            self._create_ssl_files(ssl)
        for prof in self.profiles:
            with prof.current_bigip(self._current_bigip):
                try:
                    prof.create()
                    profiles.append(prof)
                    self.bigip.profiles.append(prof)
                except AlreadyExist:
                    profiles.append(prof)
                except iControlUnexpectedHTTPError as e:
                    errors.update({prof.name: e.response._content})
                    self.log.warning(f'{self} - {prof} : Unexpected Error : {e.response._content}')
        if len(errors) == len(self.profiles):
            return False, errors
        else:
            return True, errors

    @Base.check_current_bigip
    def create_virtuals(self):
        errors = dict()
        virtuals = list()
        for vs in self.virtuals:
            with vs.current_bigip(self._current_bigip):
                try:
                    vs.create()
                    virtuals.append(vs)
                    self.bigip.virtuals.append(vs)
                except AlreadyExist:
                    virtuals.append(vs)
                except iControlUnexpectedHTTPError as e:
                    errors.update({vs.name: e.response._content})
                    self.log.warning(f'{self} - {vs} : UnexpectedError : {e.response._content}')
        if len(errors) == len(self.virtuals):
            return False, errors
        else:
            return True, errors

    @Base.check_current_bigip
    def create_snats(self):
        errors = dict()
        snats = list()
        for snat in self.snats:
            self.log.debug('{} : snats : {}'.format(self, vars(snat)))
            with snat.current_bigip(self._current_bigip):
                try:
                    snat.create()
                    snats.append(snat)
                    self.bigip.snats.append(snat)
                except AlreadyExist:
                    snats.append(snat)
                except iControlUnexpectedHTTPError as e:
                    errors.update({snat.name: e.response._content})
                    self.log.warning(f'{self} - {snat} : UnexpectedError : {e.response._content}')
        if len(errors) == len(self.snats):
            return False, errors
        else:
            return True, errors

    @Base.check_current_bigip
    def create(self):
        errors = dict()
        #monitors
        success, monitors_errors = self.create_monitors()
        errors.update({'monitors':{'success':success, 'errors':monitors_errors}})
        #nodes
        success, nodes_errors = self.create_nodes()
        errors.update({'nodes':{'success':success, 'errors':nodes_errors}})
        #pools
        success, pools_errors = self.create_pools()
        errors.update({'pools':{'success':success, 'errors':pools_errors}})
        #rules
        success, rules_errors = self.create_rules()
        errors.update({'rules':{'success':success, 'errors':rules_errors}})
        #profiles
        success, profiles_errors = self.create_profiles()
        errors.update({'profiles':{'success':success, 'errors':profiles_errors}})
        #persistences
        success, persistences_errors = self.create_persistences()
        errors.update({'profiles':{'success':success, 'errors':persistences_errors}})
        #virtuals
        success, virtuals_errors = self.create_virtuals()
        errors.update({'virtuals':{'success':success, 'errors':virtuals_errors}})
        #snats
        success, snats_errors = self.create_snats()
        errors.update({'snats':{'success':success, 'errors':snats_errors}})
        return errors

    def __str__(self):
        return f'archi {self.basename} : {self.address} {self.raw_services.keys()}'
