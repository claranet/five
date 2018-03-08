#coding: utf-8
import ipaddress
from copy import copy
from contextlib import contextmanager
from five.base import Base
from five.resources import BaseResource, Resource
from five.net import NetResource
from five.exceptions import *

class Snat(NetResource):
    """ source nat object """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.do_not_clean_attrs.update(['_origins'])
        self.attrs_to_clean_before_push.add('_origins')

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.ltm.snats.snat

    def _retreive_origins(self):
        try:
            self._origins = [ipaddress.ip_interface(self.split_domain_addr(origin)[0]) for d in self.origins for origin in d.values()]
        except AttributeError:  #origins as [str, str, .. ] and not [{name: str}, .. ]
            self._origins = [ipaddress.ip_interface(self.split_domain_addr(origin)[0]) for origin in self.origins]

    def set_attrs(self, d_map):
        super().set_attrs(d_map)
        self._retreive_origins()

class Translation(NetResource):
    """ snat-translation object """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.ltm.snat_translations.snat_translation

class Node(NetResource):
    """ node object """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.attrs_required_for_real_res.update(['address'])

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.ltm.nodes.node

    def _create(self, d_create):
        d_create = super()._create(d_create)
        address = d_create.get('address')
        route_domain = d_create.get('route_domain')
        if not '%' in address:
            d_create['address'] = '{}%{}'.format(address, route_domain)
        return d_create

    def disable(self):
        self.patch(session='user-disabled', state='user-up')

    def offline(self):
        self.patch(session='user-disabled', state='user-down')

    def enable(self):
        self.patch(session='user-enabled', state='user-up')

class Member(Node):
    """ pool member object """
    def __init__(self, pool, **kwargs):
        """
        :param pool: Pool object
        """
        super().__init__(**kwargs)
        self.attrs_to_clean_before_push.add('pool')
        self.do_not_clean_attrs.add('pool')
        self.pool = pool
        self.bigip = pool.bigip

    @contextmanager
    def current_bigip(self, bigip):
        with super().current_bigip(bigip):
            self.pool._current_bigip = bigip
            yield
            self.pool._current_bigip = None

    @property
    @Base.check_current_bigip
    def res(self):
        return self.pool.real.members_s.members

    @Base.check_current_bigip
    def load(self, from_pool=False):
        if from_pool:
            self.pool = from_pool
        if self.pool.real:
            super().load()

class Pool(Resource):
    """ pool object """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.do_not_clean_attrs.update(['members'])

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.ltm.pools.pool

    @contextmanager
    def current_bigip(self, bigip):
        with super().current_bigip(bigip):
            for m in self.members:
                if isinstance(m, Member):
                    m._current_bigip = bigip
                    m.load(from_pool=self)
            yield
            for m in self.members:
                if isinstance(m, Member):
                    m._current_bigip = None

    def _retreive_members(self):
        if hasattr(self, 'membersReference'):
            self.members = [Member(self, bigip=self.bigip, **member) for member in self.membersReference.get('items', list())]
            delattr(self, 'membersReference')
        elif hasattr(self, 'members'):
            pass
        else:
            self.members = list()

    def set_attrs(self, d_map):
        super().set_attrs(d_map)
        self._retreive_members()

    def sanitize(self, d_san):
        d_san = super().sanitize(d_san)
        if 'members' in d_san:
            mems = list()
            for m in d_san['members']:
                if isinstance(m, Member):
                    mems.append(m.sanitize(vars(m)))
                elif isinstance(m, dict):
                    mems.append(super().sanitize(m))
                else:
                    mems.append(m)
            d_san['members'] = mems
        return d_san

    def _create(self, d_map):
        d_map = super()._create(d_map)
        if self.members:
            members = list()
            for m in self.members:
                if isinstance(m, Member):
                    members.append(m.sanitize(vars(m)))
                else:
                    members.append(m)
            d_map.update({'members':members})
        return d_map

    @Base.check_current_bigip
    def compare_with_real(self, patch=None):
        diff = super().compare_with_real(patch=patch)
        if 'members' in diff:
            mdiff = dict()
            for m in diff['members'][0]:
                m._current_bigip = self._current_bigip
                d = m.compare_with_real()
                if d:
                    mdiff.update({m.name:d})
            if mdiff:
                diff['members'] == mdiff
            else:
                del(diff['members'])
        return diff

    def get_member(self, name):
        try:
            return [m for m in self.members if name == m.name][0]
        except IndexError:
            return False

    @Base.check_current_bigip
    def add_member(self, member):
        mems = copy(self.members)
        mems.append(member)
        return self.patch(members=mems)

    @Base.check_current_bigip
    def del_member(self, name):
        mem = self.get_member(name)
        if mem:
            mems = copy(self.members)
            mems.remove(mem)
            return self.patch(members=mems)
        return False

    @Base.check_current_bigip
    def disable(self):
        """
        disable all members
        """
        [m.disable() for m in self.members]
        return True

    @Base.check_current_bigip
    def offline(self):
        """
        forced offline all members
        """
        [m.offline() for m in self.members]
        return True

    @Base.check_current_bigip
    def enable(self):
        """
        enable all members
        """
        [m.enable() for m in self.members]
        return True

class Virtual(NetResource):
    """ virtual server object """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.do_not_clean_attrs.update(['profiles', 'policies', 'port', 'address'])
        self.attrs_required_for_real_res.remove('route_domain')     ## needed for LTM 11.5 -- to delete later
        self.attrs_to_clean_before_push.update(['address', 'port'])

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.ltm.virtuals.virtual

    def _set_port(self):
        if getattr(self, 'address', None) and getattr(self, 'port', None):
            self.port = str(self.port)
            return
        elif getattr(self, 'address', None) or getattr(self, 'port', None):
            raise ValueError("""You have to define either destination (as ip:port -- ip.port for v6 ip)
                                or address and  port argument""")
        try:
            self.address, self.port = self.destination.split(':')
        except ValueError:
            ## ipv6 format
            self.address, self.port = self.destination.split('.')
        self.address = self.address.split('/')[-1]
        self.log.debug(f"{self!s} :: set_port :: {self.address} {self.port}")

    def _set_address(self, d_map):
        dest = d_map.get('destination', '')
        address = d_map.get('address', '')
        port = d_map.get('port', '')
        if not dest and not address and not port:
            return d_map
        elif dest and '%' in dest:
            # destination already set with route domain
            return d_map
        elif dest and dest.count(':') > 1:
            address, port = dest.split('.')
            sep = '.'
        elif dest:
            address, port = dest.split(':')
            sep = ':'
        elif ':' in address:
            sep = '.'
        else:
            sep = ':'
        destination = f'{address}{sep}{port}'
        if not '%' in destination and self.route_domain:
            destination = f'{address}%{self.route_domain}{sep}{port}'
        d_map.update({'destination':destination})
        return d_map

    def _retreive_profiles(self):
        if hasattr(self, 'profilesReference'):
            self.profiles = [prof['fullPath'] for prof in self.profilesReference.get('items', list())]
            delattr(self, 'profilesReference')
        else:
            self.policies = list()

    def _retreive_policies(self):
        if hasattr(self, 'policiesReference'):
            self.policies = [pol['fullPath'] for pol in self.policiesReference.get('items', list())]
            delattr(self, 'policiesReference')
        else:
            self.policies = list()

    def set_attrs(self, d_map):
        Resource.set_attrs(self, d_map)
        self._set_port()
        self._set_ipaddress()
        self._retreive_profiles()
        self._retreive_policies()

    def disable(self):
        return self.patch({'disabled':True})

    def enable(self):
        return self.patch({'enabled':True})

class Monitor(Resource):
    """ monitor / health-check object """
    def __init__(self, **kwargs):
        self.types = {'tm:ltm:monitor:ftp:ftpstate': 'ftp',
                       'tm:ltm:monitor:http:httpstate': 'http',
                       'tm:ltm:monitor:https:httpsstate': 'https',
                       'tm:ltm:monitor:icmp:icmpstate': 'icmp',
                       'tm:ltm:monitor:tcp-half-open:tcp-half-openstate': 'tcp_half_open',
                       'tm:ltm:monitor:tcp:tcpstate': 'tcp',
                       'tm:ltm:monitor:udp:udpstate': 'udp'}
        super().__init__(**kwargs)
        self.attrs_to_clean_before_push.add('types')
        self.attrs_to_clean_before_push.add('_type')
        self.do_not_clean_attrs.add('types')
        self.do_not_clean_attrs.add('_type')

    def set_attrs(self, d_map):
        super().set_attrs(d_map)
        self._set_type()

    def _set_type(self):
        if getattr(self, 'kind', None) not in self.types.keys() \
           and getattr(self, '_type', None) not in self.types.values():
            raise NotImplementedMonitor
        elif getattr(self, 'kind', False):
            self._type = self.types[self.kind]
        elif getattr(self, '_type', False):
            pass
        else:
            raise NotImplementedMonitor

    @property
    @Base.check_current_bigip
    def res(self):
        if self._type == 'ftp':
            return self._current_bigip.tm.ltm.monitor.ftps.ftp
        elif self._type == 'http':
            return self._current_bigip.tm.ltm.monitor.https.http
        elif self._type == 'https':
            return self._current_bigip.tm.ltm.monitor.https_s.https
        elif self._type == 'icmp':
            return self._current_bigip.tm.ltm.monitor.icmps.icmp
        elif self._type == 'tcp':
            return self._current_bigip.tm.ltm.monitor.tcps.tcp
        elif self._type == 'udp':
            return self._current_bigip.tm.ltm.monitor.udps.udp
        elif self._type == 'tcp_half_open':
            return self._current_bigip.tm.ltm.monitor.tcp_half_opens.tcp_half_open

    def _create(self, d_create):
        d_create = super()._create(d_create)
        d_create['defaultFrom'] = d_create.get('defaultFrom', '/Common/{}'.format(self._type))
        return d_create

class Persistence(Resource):
    """ persistence object """
    def __init__(self, **kwargs):
        self.types = {'tm:ltm:persistence:cookie:cookiestate': 'cookie',
                      'tm:ltm:persistence:dest-addr:dest-addrstate': 'dest_addr',
                      'tm:ltm:persistence:source-addr:source-addrstate': 'source_addr',
                      'tm:ltm:persistence:hash:hashstate': 'hash',
                      'tm:ltm:persistence:ssl:sslstate': 'ssl',
                      'tm:ltm:persistence:sip:sipstate': 'sip',
                      'tm:ltm:persistence:universal:universalstate': 'universal'}
        super().__init__(**kwargs)
        self.attrs_to_clean_before_push.add('types')
        self.attrs_to_clean_before_push.add('_type')
        self.do_not_clean_attrs.add('types')
        self.do_not_clean_attrs.add('_type')

    def set_attrs(self, d_map):
        super().set_attrs(d_map)
        self._set_type()

    def _set_type(self):
        if getattr(self, 'kind', None) not in self.types.keys() \
           and getattr(self, '_type', None) not in self.types.values():
            raise NotImplementedPersistence
        elif getattr(self, 'kind', False):
            self._type = self.types[self.kind]
        elif getattr(self, '_type', False):
            pass
        else:
            raise NotImplementedPersistence

    def _create(self, d_create):
        d_create = super()._create(d_create)
        d_create['defaultFrom'] = d_create.get('defaultFrom', '/Common/{}'.format(self._type))
        return d_create

    @property
    @Base.check_current_bigip
    def res(self):
        if self._type == 'cookie':
            return self._current_bigip.tm.ltm.persistence.cookies.cookie
        elif self._type == 'dest_addr':
            return self._current_bigip.tm.ltm.persistence.dest_addrs.dest_addr
        elif self._type == 'source_addr':
            return self._current_bigip.tm.ltm.persistence.source_addrs.source_addr
        elif self._type == 'hash':
            return self._current_bigip.tm.ltm.persistence.hashs.hash
        elif self._type == 'ssl':
            return  self._current_bigip.tm.ltm.persistence.ssls.ssl
        elif self._type == 'universal':
            return self._current_bigip.tm.ltm.persistence.universals.universal
        else:
            raise NotImplementedPersistence

class Profile(Resource):
    """ profile object """
    def __init__(self, **kwargs):
        self.types = {'tm:ltm:profile:tcp:tcpstate': 'tcp',
                      'tm:ltm:profile:udp:udpstate': 'udp',
                      'tm:ltm:profile:fastl4:fastl4state': 'fastl4',
                      'tm:ltm:profile:one-connect:one-connectstate': 'one_connect',
                      'tm:ltm:profile:ftp:ftpstate': 'ftp',
                      'tm:ltm:profile:http:httpstate': 'http',
                      'tm:ltm:profile:http2:http2state': 'http2',
                      'tm:ltm:profile:client-ssl:client-sslstate': 'client_ssl',
                      'tm:ltm:profile:server-ssl:server-sslstate': 'server_ssl'}
        super().__init__(**kwargs)
        self.attrs_to_clean_before_push.add('types')
        self.attrs_to_clean_before_push.add('_type')
        self.do_not_clean_attrs.add('types')
        self.do_not_clean_attrs.add('_type')

    def set_attrs(self, d_map):
        super().set_attrs(d_map)
        self._set_type()

    def _set_type(self):
        if getattr(self, 'kind', None) not in self.types.keys() \
           and getattr(self, '_type', None) not in self.types.values():
            raise NotImplementedProfile
        elif getattr(self, 'kind', False):
            self._type = self.types[self.kind]
        elif getattr(self, '_type', False):
            pass
        else:
            raise NotImplementedProfile('You can only {} profile'.format(self.types.values()))

    @property
    @Base.check_current_bigip
    def res(self):
        if self._type == 'tcp':
            return self._current_bigip.tm.ltm.profile.tcps.tcp
        elif self._type == 'udp':
            return self._current_bigip.tm.ltm.profile.udps.udp
        elif self._type == 'fastl4':
            return self._current_bigip.tm.ltm.profile.fastl4s.fastl4
        elif self._type == 'one_connect':
            return self._current_bigip.tm.ltm.profile.one_connects.one_connect
        elif self._type == 'ftp':
            return self._current_bigip.tm.ltm.profile.ftps.ftp
        elif self._type == 'http':
            return self._current_bigip.tm.ltm.profile.https.http
        elif self._type == 'http2':
            return self._current_bigip.tm.ltm.profile.http2s.http2
        elif self._type == 'client_ssl':
            return self._current_bigip.tm.ltm.profile.client_ssls.client_ssl
        elif self._type == 'server_ssl':
            return self._current_bigip.tm.ltm.profile.server_ssls.server_ssl

    @staticmethod
    def ssl_sanitize(d_map):
        if d_map.get('key', None) and d_map.get('key', '')[-4:] != '.key':
            d_map['key'] = d_map['key']+'.key'
        if d_map.get('cert', None) and d_map.get('cert', '')[-4:] == '.cer':
            d_map['cert'] = d_map['cert'].replace('.cer', '.crt')
        elif d_map.get('cert', None) and d_map.get('cert', '')[-4:] != '.crt':
            d_map['cert'] = d_map['cert']+'.crt'
        if d_map.get('chain', None) and d_map.get('chain', '')[-4:] == '.cer':
            d_map['chain'] = d_map['chain'].replace('.cer', '.crt')
        elif d_map.get('chain', None) and d_map.get('chain', '')[-4:] != '.crt':
            d_map['chain'] = d_map['chain']+'.crt'
        return d_map

    def sanitize(self, d_map):
        d_map = super().sanitize(d_map)
        if self._type in ['client_ssl', 'server_ssl']:
            self.ssl_sanitize(d_map)
        return d_map

    def _create(self, d_create):
        d_create = super()._create(d_create)
        d_create['defaultFrom'] = d_create.get('defaultFrom', '/Common/{}'.format(self._type))
        return d_create

    def update(self):
        raise NotImplementedError('Using update will break inheritance since all attributes will be pushed. Please use patch method instead')

class Rule(Resource):
    """ irule object """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.ltm.rules.rule

class Policy(Resource):
    """ LTM Policy object """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.ltm.policys.policy


