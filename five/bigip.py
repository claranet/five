#coding: utf-8
import os
import re
import logging
import ipaddress
import time
from functools import wraps
from contextlib import contextmanager

from f5.bigip import ManagementRoot
from f5.multi_device.device_group import DeviceGroup
from icontrol.exceptions import iControlUnexpectedHTTPError
from f5.sdk_exception import UnsupportedTmosVersion
from f5.utils.decorators import MaximumAttemptsReached

from five import log
from five.base import Base
from five.exceptions import BigipNotSet, ContextNotFound
from five.resources import Peer, Partition, Ssl_key, Ssl_cert, SecurityPolicy
from five.net import Vlan, Route_Domain, SelfIP
from five.ltm import Node, Member, Pool, Virtual, \
                    Snat, Translation, Persistence, \
                    Rule, Policy, Monitor, Profile

class Bigip(Base):
    def __init__(self, bigip, user=None, passwd=None, load=True, as_peer=False, ref_as_current=False):
        super().__init__()
        self.hostname = bigip
        self.ref_bigip = None       ## Used to retreive configuration of the bigip
        self.ref_as_current = False
        self.connect(user, passwd, as_peer=as_peer)
        if load:
            self.load()
        if ref_as_current:
            self._current_bigip = self.ref_bigip
            self._set_resources_current_bigip()

    #### Connection and close methods
    def _connect(self, user, passwd):
        self.log.debug('{} : connect'.format(self.hostname))
        ## when all in 12.X 
        ## self.real_bigip = ManagementRoot(self.hostname, user, passwd, token=True)
        ## handle exception with invalid credentials + test read-only/read-write call 
        ## + exception for wrong version (<12)
        self.ref_bigip = ManagementRoot(self.hostname, user, passwd)

    def connect(self, user, passwd, as_peer):
        self._connect(user, passwd)
        if not as_peer:
            self.load_peers()
            # devicegroup
            try:
                self.load_devicegroup(user, passwd)
            except MaximumAttemptsReached:
                self.log.warning('{} : not synced -- try to sync before load device group'.format(self))
                dv = [dv for dv in self.ref_bigip.tm.cm.device_groups.get_collection() if dv.type == 'sync-failover'][0]
                dv.sync_to()
                self.load_devicegroup(user, passwd)
        return self.ref_bigip

    ### really used ??
    def connect_to_real(self, user, passwd):
        return ManagementRoot(self.hostname, user, passwd, token=True)

    #### Load configuration methods
    def load(self):
        self.log.info('{} : retreiving configuration'.format(self.hostname))
        self.load_partitions()
        self.load_vlans()
        self.load_route_domains()
        self.load_selfips()
        self.load_nodes()
        self.load_pools()
        self.load_virtuals()
        self.load_snats()
        self.load_translations()
        self.load_rules()
        self.load_policies()
        self.load_monitors()
        self.load_persistences()
        self.load_profiles()
        self.load_ssl_certs()
        self.load_ssl_keys()
        #self.load_security_policies()
        # contexts
        self.retreive_contexts()

    @property
    def resources(self):
        resources = list()
        resources.extend(self.partitions)
        resources.extend(self.vlans)
        resources.extend(self.route_domains)
        resources.extend(self.selfips)
        resources.extend(self.nodes)
        resources.extend(self.pools)
        resources.extend(self.virtuals)
        resources.extend(self.snats)
        resources.extend(self.translations)
        resources.extend(self.rules)
        resources.extend(self.policies)
        resources.extend(self.monitors)
        resources.extend(self.persistences)
        resources.extend(self.profiles)
        resources.extend(self.ssl_certs)
        resources.extend(self.ssl_keys)
        #resources.extend(self.security_policies)
        return resources


    ## for ref_as_current, not correctly implemented yet .. to see 
    @Base.check_current_bigip
    def _set_resources_current_bigip(self):
        for res in self.resources:
            res._current_bigip = self._current_bigip

    def load_peers(self):
        self.log.debug('{} : load peers'.format(self))
        self.peers = [Peer(bigip=self.hostname, **vars(peer)) for peer in
                      self.ref_bigip.tm.cm.devices.get_collection()]
        return self.peers

    def load_partitions(self):
        self.log.debug('{} : load partitions'.format(self))
        self.partitions = [Partition(bigip=self.hostname, **vars(partition)) for partition in
                           self.ref_bigip.tm.sys.folders.get_collection()]
        #[part.set_bigip(self.ref_bigip) for part in self.partitions]
        return self.partitions

    def load_vlans(self):
        self.log.debug('{} : load vlans'.format(self))
        self.vlans = [Vlan(bigip=self.hostname, **vars(vlan)) for vlan in
                      self.ref_bigip.tm.net.vlans.get_collection(requests_params={'params':
                                                                                {'expandSubcollections':'true'}})]
        return self.vlans

    def load_route_domains(self):
        self.log.debug('{} : load routes domains'.format(self))
        self.route_domains = [Route_Domain(bigip=self.hostname, **vars(rd)) for rd in
                              self.ref_bigip.tm.net.route_domains.get_collection()]
        return self.route_domains

    def load_selfips(self):
        self.log.debug('{} : load selfips'.format(self))
        self.selfips = [SelfIP(bigip=self.hostname, **vars(selfip)) for selfip in
                        self.ref_bigip.tm.net.selfips.get_collection()]
        return self.selfips

    def load_nodes(self):
        self.log.debug('{} : load nodes'.format(self))
        self.nodes = [Node(bigip=self.hostname, **vars(node)) for node in self.ref_bigip.tm.ltm.nodes.get_collection()]
        return self.nodes

    def load_pools(self):
        self.log.debug('{} : load pools'.format(self))
        self.pools = [Pool(bigip=self.hostname, **vars(pool)) for pool in
                      self.ref_bigip.tm.ltm.pools.get_collection(requests_params={'params': {'expandSubcollections':'true'}})]
        return self.pools

    def load_virtuals(self):
        self.log.debug('{} : load virtuals'.format(self))
        self.virtuals = [Virtual(bigip=self.hostname, **vars(virtual)) for virtual in
                         self.ref_bigip.tm.ltm.virtuals.get_collection(requests_params={'params': {'expandSubcollections':'true'}})]
        return self.virtuals

    def load_snats(self):
        self.log.debug('{} : load snats'.format(self))
        self.snats = [Snat(bigip=self.hostname, **vars(snat)) for snat in self.ref_bigip.tm.ltm.snats.get_collection()]
        return self.snats

    def load_translations(self):
        self.log.debug('{} : load translations'.format(self))
        self.translations = [Translation(bigip=self.hostname, **vars(trans)) for trans in self.ref_bigip.tm.ltm.snat_translations.get_collection()]
        return self.translations

    def load_rules(self):
        self.log.debug('{} : load irules'.format(self))
        self.rules = [Rule(bigip=self.hostname, **vars(rule)) for rule in self.ref_bigip.tm.ltm.rules.get_collection()]
        return self.rules

    def load_policies(self):
        self.log.debug('{} : load policies'.format(self))
        self.policies = [Policy(bigip=self.hostname, **vars(policy)) for policy in self.ref_bigip.tm.ltm.policys.get_collection()]
        return self.policies

    def load_security_policies(self):
        self.log.debug('{} : load security policies'.format(self))
        self.security_policies = [SecurityPolicy(bigip=self.hostname, **vars(policy)) for policy in
                                  self.ref_bigip.tm.asm.policies_s.get_collection(requests_params={'params':
                                                                                                    {'expandSubcollections':'true'}})]
        return self.security_policies

    def load_monitors(self):
        self.monitors = list()
        #ftp
        self.log.debug('{} : load ftp monitors'.format(self))
        self.monitors.extend([Monitor(bigip=self.hostname, **vars(monitor)) for monitor in
                         self.ref_bigip.tm.ltm.monitor.ftps.get_collection()])
        #http
        self.log.debug('{} : load http monitors'.format(self))
        self.monitors.extend([Monitor(bigip=self.hostname, **vars(monitor)) for monitor in
                         self.ref_bigip.tm.ltm.monitor.https.get_collection()])
        #https
        self.log.debug('{} : load https monitors'.format(self))
        self.monitors.extend([Monitor(bigip=self.hostname, **vars(monitor)) for monitor in
                         self.ref_bigip.tm.ltm.monitor.https_s.get_collection()])
        #tcp
        self.log.debug('{} : load tcp monitors'.format(self))
        self.monitors.extend([Monitor(bigip=self.hostname, **vars(monitor)) for monitor in
                         self.ref_bigip.tm.ltm.monitor.tcps.get_collection()])
        #udp
        self.log.debug('{} : load udp monitors'.format(self))
        self.monitors.extend([Monitor(bigip=self.hostname, **vars(monitor)) for monitor in
                         self.ref_bigip.tm.ltm.monitor.udps.get_collection()])
        #tcp_half_open
        self.log.debug('{} : load tcp_half_open monitors'.format(self))
        self.monitors.extend([Monitor(bigip=self.hostname, **vars(monitor)) for monitor in
                         self.ref_bigip.tm.ltm.monitor.tcp_half_opens.get_collection()])
        #icmp
        self.log.debug('{} : load monitors'.format(self))
        self.monitors.extend([Monitor(bigip=self.hostname, **vars(monitor)) for monitor in
                         self.ref_bigip.tm.ltm.monitor.icmps.get_collection()])
        return self.monitors

    def load_persistences(self):
        self.persistences = list()
        #cookie
        self.log.debug('{} : load cookie persistences'.format(self))
        self.persistences.extend([Persistence(bigip=self.hostname, **vars(persist)) for persist in
                                self.ref_bigip.tm.ltm.persistence.cookies.get_collection()])
        #dest-addr
        self.log.debug('{} : load dest-addr persistences'.format(self))
        self.persistences.extend([Persistence(bigip=self.hostname, **vars(persist)) for persist in
                                self.ref_bigip.tm.ltm.persistence.dest_addrs.get_collection()])
        #source-addr
        self.log.debug('{} : load source-addr persistences'.format(self))
        self.persistences.extend([Persistence(bigip=self.hostname, **vars(persist)) for persist in
                                self.ref_bigip.tm.ltm.persistence.source_addrs.get_collection()])
        #hash
        self.log.debug('{} : load hash persistences'.format(self))
        self.persistences.extend([Persistence(bigip=self.hostname, **vars(persist)) for persist in
                                self.ref_bigip.tm.ltm.persistence.hashs.get_collection()])
        #ssl
        self.log.debug('{} : load ssl persistences'.format(self))
        self.persistences.extend([Persistence(bigip=self.hostname, **vars(persist)) for persist in
                                self.ref_bigip.tm.ltm.persistence.ssls.get_collection()])
        #universal
        self.log.debug('{} : load universal persistences'.format(self))
        self.persistences.extend([Persistence(bigip=self.hostname, **vars(persist)) for persist in
                                self.ref_bigip.tm.ltm.persistence.universals.get_collection()])
        return self.persistences

    def load_profiles(self):
        self.profiles = list()
        #tcp
        self.log.debug('{} : load tcp monitors'.format(self))
        self.profiles.extend([Profile(bigip=self.hostname, **vars(profile)) for profile in
                              self.ref_bigip.tm.ltm.profile.tcps.get_collection()])
        #udp
        self.log.debug('{} : load udp monitors'.format(self))
        self.profiles.extend([Profile(bigip=self.hostname, **vars(profile)) for profile in
                              self.ref_bigip.tm.ltm.profile.udps.get_collection()])
        #fastl4
        self.log.debug('{} : load fastl4 monitors'.format(self))
        self.profiles.extend([Profile(bigip=self.hostname, **vars(profile)) for profile in
                              self.ref_bigip.tm.ltm.profile.fastl4s.get_collection()])
        #one_connect
        self.log.debug('{} : load one_connect monitors'.format(self))
        self.profiles.extend([Profile(bigip=self.hostname, **vars(profile)) for profile in
                              self.ref_bigip.tm.ltm.profile.one_connects.get_collection()])
        #ftp
        self.log.debug('{} : load ftp monitors'.format(self))
        self.profiles.extend([Profile(bigip=self.hostname, **vars(profile)) for profile in
                              self.ref_bigip.tm.ltm.profile.ftps.get_collection()])
        #http
        self.log.debug('{} : load http monitors'.format(self))
        self.profiles.extend([Profile(bigip=self.hostname, **vars(profile)) for profile in
                              self.ref_bigip.tm.ltm.profile.https.get_collection()])
        #client_ssl
        self.log.debug('{} : load client_ssl monitors'.format(self))
        self.profiles.extend([Profile(bigip=self.hostname, **vars(profile)) for profile in
                              self.ref_bigip.tm.ltm.profile.client_ssls.get_collection()])
        #server_ssl
        self.log.debug('{} : load server_ssl monitors'.format(self))
        self.profiles.extend([Profile(bigip=self.hostname, **vars(profile)) for profile in
                              self.ref_bigip.tm.ltm.profile.server_ssls.get_collection()])
        #http2
        self.log.debug('{} : load http2 monitors'.format(self))
        try:
            self.profiles.extend([Profile(bigip=self.hostname, **vars(profile)) for profile in
                              self.ref_bigip.tm.ltm.profile.http2s.get_collection()])
        except UnsupportedTmosVersion:
            self.log.debug('{} : current version does not supported http2 profiles'.format(self))
        return self.profiles

    def load_ssl_certs(self):
        self.ssl_certs = list()
        self.log.debug('{} : load ssl certificates'.format(self))
        self.ssl_certs.extend([Ssl_cert(bigip=self.hostname, **vars(cert)) for cert in
                               self.ref_bigip.tm.sys.file.ssl_certs.get_collection()])
        return self.ssl_certs

    def load_ssl_keys(self):
        self.ssl_keys = list()
        self.log.debug('{} : load ssl keys'.format(self))
        self.ssl_keys.extend([Ssl_key(bigip=self.hostname, **vars(key)) for key in
                              self.ref_bigip.tm.sys.file.ssl_keys.get_collection()])
        return self.ssl_keys

    def load_devicegroup(self, user, passwd):
        """
        Load DeviceGroup
        self.real_peers will be created as list of Bigip for all bigip in the group (without itself)
        """
        self.log.debug('{} : load device group'.format(self))
        self.devicegroup = DeviceGroup(devices=[ManagementRoot(peer.name, user, passwd) for peer in self.peers],
                                       device_group_type='sync-failover',
                                       device_group_name=[group.name for group in
                                                          self.ref_bigip.tm.cm.device_groups.get_collection() if
                                                          group.type == 'sync-failover'][0],
                                       device_group_partition='Common')
        self.real_peers = [Bigip(peer.hostname, user, passwd, load=False, as_peer=True) for peer in self.devicegroup.devices if
                           peer.hostname != self.hostname]
        return self.devicegroup

    @property
    def is_master(self):
        """
        Return True if 'failoverState' is 'active'
        """
        current_device = [peer for peer in self.peers if peer.name == self.hostname][0]
        if current_device.failoverState == 'active':
            return True
        return False

    def sync(self):
        ### implement try / except 
        self.devicegroup.ensure_all_devices_in_sync()

    @Base.check_current_bigip
    def upload_file(self, filepath):
        """
        Upload local file on remote bigip in /var/config/rest/downloads
        """
        try:
            self._current_bigip.shared.file_transfer.uploads.upload_file(filepath)
        except IOError:
            return False
        return os.path.join('/var/config/rest/downloads', os.path.basename(filepath))

    def retreive_contexts(self):
        contexts = list()
        self.log.verbose('{} : retreive context'.format(self))
        for rd in self.route_domains:
            context = Context(self.hostname, rd)
            context.retreive_selfips(self)
            contexts.append(context)
            self.log.verbose('{} : add context {}'.format(self, context))
        self.contexts = contexts

    def _search_pool_context_with_member(self, member):
        if isinstance(member, Member):
                return self.search_context(member)
        elif isinstance(member, (str, bytes)):
            state, nd = self.get(name=member.split(':')[0])
            if state:
                return self.search_context(nd)
            else:
                return list()
        elif isinstance(member, dict):
            if member.get('address'):
                return self.search_context(member.get('address'))
            elif member.get('name'):
                success, nd = self.get(name=member.get('name').split(':')[0])
                if success:
                    return self.search_context(nd)
            return list()
        return list()

    def search_context(self, searched):
        """
        return list of context that match the passed searched object
        str: try to transform as an IP and return context if handles by it
        ipaddress : as str without transformation
        node: return context if it handle node ip address
        """
        self.log.debug('{} : search context for {}'.format(self, searched))
        if isinstance(searched, (str, bytes)):
            self.log.verbose('---- search context -- str/bytes')
            if '%' in searched:
                searched = searched.split('%')[0]
            try:
                ip = ipaddress.ip_address(searched)
            except ValueError:
                self.log.verbose('---- {} is not an ip'.format(searched))
                self.log.verbose('---- {} search as resource name'.format(searched))
                find, res = self.get(name=searched)
                if find:
                    return self.search_context(res)
                else:
                    return list()
            return [context for context in self.contexts if context.handles(ip)]
        elif isinstance(searched, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            self.log.verbose('---- search context -- IP object')
            return [context for context in self.contexts if context.handles(searched)]
        elif isinstance(searched, Node):
            self.log.verbose('---- search context -- Node / Member Object')
            return [context for context in self.contexts if context.handles(searched._address)]
        elif isinstance(searched, Pool):
            self.log.verbose('---- search context -- Pool object')
            if getattr(searched, 'members', None):
                return self._search_pool_context_with_member(searched.members[0])
            else:
                return list()
        elif isinstance(searched, Virtual):
            self.log.verbose('---- search context -- Virtual object')
            if getattr(searched, 'pool', None):
                return self.search_context(searched.pool)
            return list()
        else:
            self.log.verbose('---- search context -- object not handle')
            return list()

    def have_uniq_context(self, searched):
        """
        Used to retreive context if only one
        :return: Tuple as : success, result
        :return: True, Context
        :return: False, None
        """
        contexts = self.search_context(searched)
        if len(contexts) == 1:
            return True, contexts[0]
        else:
            return False, None

    @Base.check_current_bigip
    def create(self, cls, **kwargs):
        """
        helper to create a resource on the real_bigip
        :param cls: string that will be eval to use the corresponding class
        :**kwargs: needed attributes for the resource, bigip and set_bigip is handle by this method
        """
        kwargs.update({'bigip':self.hostname, '_bigip':self._current_bigip})
        res = eval(cls)(**kwargs)
        res.check_attrs()
        with res.current_bigip(self._current_bigip):
            real_res = res.create()
        eval('self.{}s'.format(cls).lower()).append(res)
        return res, real_res

    @Base.check_current_bigip
    def create_with_context(self, cls, res):
        self.log.debug('{} : create {} : {} with context'.format(self, cls, res))
        success, context = self.have_uniq_context(res)
        if not success:
            raise ContextNotFound
        self.log.debug('{} --- context : {}'.format(self, context))
        res.bigip = context.bigip
        res.partition = context.partition
        res.route_domain = context.route_domain
        return self.create(cls, **res)

    @Base.check_current_bigip
    def delete(self, cls, res):
        """
        helper to delete resource on the real bigip
        :param cls: string that will be eval to use the corresponding collection
        :param res: Resource object
        :TO DO: TRY + DELETE ON COLLECTIONS AND RESOURCES IF SUCCESS !!!!
        """
        with res.current_bigip(self._current_bigip):
            success, errors = res.delete()
        if success and cls != 'Member' and cls != 'member':
            eval('self.{}s'.format(cls).lower()).remove(res)
        return success, errors

    @Base.check_current_bigip
    def patch(self, res, **kwargs):
        """
        helper to patch resource on the real bigip
        """
        with res.current_bigip(self._current_bigip):
            res.patch(**kwargs)
        return res

    def get(self, **kwargs):
        """
        helper to retreive resource with some information
        it will compare kwargs with resource attributes and return Resoure object
        advice : use name (and partition if needed)
        """
        match = set()
        for res in self.resources:
            same = True
            for k,v in kwargs.items():
                try:
                    if v != eval('res.{}'.format(k)):
                        same = False
                        break
                except AttributeError:
                    same = False
                    break
            if same:
               match.add(res)
        self.log.verbose('{} : get_resource : {}'.format(self, kwargs))
        self.log.verbose('{} : get_resource - match : {}'.format(self, match))
        if len(match) == 1:
            return True, list(match)[0]
        else:
            return False, match

    def grep(self, searched, cls=None):
        if cls:
            return [res for res in self.resources if re.search(searched, res.name) and isinstance(res, cls)]
        else:
            return [res for res in self.resources if re.search(searched, res.name)]

    def search_ssl(self, dns):
        certs = [cert for cert in self.ssl_certs if cert.handle_dns(dns)]
        profiles = [prof for prof in self.profiles if (prof._type == 'server_ssl' or prof._type == 'client_ssl') and
                    hasattr(prof, 'cert') and prof.cert in [cert.fullPath for cert in certs]]
        virtuals = list()
        for profile in profiles:
            virtuals.extend([virtual for virtual in self.virtuals if profile.fullPath in virtual.profiles])
        return certs, profiles, virtuals

    def __str__(self):
        return self.hostname

class Context(object):
    def __init__(self, bigip, route_domain):
        self.bigip = bigip
        self.partition = route_domain.partition
        self.route_domain = route_domain.id
        self.vlans = getattr(route_domain, 'vlans', None) or list()
        self.networks = set()
        self.vlan_by_network = dict()

    def retreive_selfips(self, bigip):
        for sip in bigip.selfips:
            if int(sip.route_domain) == self.route_domain:
                self.networks.add(sip._address.network)
                self.vlan_by_network.update({sip._address.network:sip.vlan})

    def handles(self, ip):
        """
        :param ip: ipaddress object
        """
        for network in self.networks:
            if ip in network:
                return True
        return False

    @property
    def ext_vlan(self):
        """
        return external vlan name if there is one and only one exist
        """
        vlans = [vlan for vlan in self.vlans if 'external' in vlan]
        if len(vlans) == 1:
            return vlans[0]
        else:
            return None

    def int_vlan(self, node):
        """
        return internal vlan name corresponding to the selfip that handles the node IP
        """
        for lan, vlan in self.vlan_by_network.items():
            if node._address in lan:
                return vlan
        return None

    def __str__(self):
        return '{} : {} / RD {} : {}'.format(self.bigip, self.partition, self.route_domain, self.vlan_by_network)
