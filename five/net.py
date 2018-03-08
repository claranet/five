#coding: utf-8
import ipaddress

from five.base import Base
from five.resources import Resource

class NetResource(Resource):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.attrs_required_for_real_res.add('route_domain')
        self.read_only_attrs.add('address')
        try:
            self.attrs_to_clean_before_push.remove('address')
        except KeyError:
            ## if create from Dummy Resource, this stage is already done
            pass
        self.do_not_clean_attrs.update(['_address', 'route_domain'])

    def _set_ipaddress(self):
        """
        split route domain from the address and create _address attribute as ipaddress address or interface
        """
        if hasattr(self, 'address') and (not hasattr(self, 'route_domain') or '%' in getattr(self, 'address')):
            addr, self.route_domain = self.split_domain_addr(self.address)
            self.log.verbose('{} : split rd on {}'.format(self, self.address))
            self.log.verbose('{} : split rd find : {} {}'.format(self, addr, self.route_domain))
            if addr == 'any':
                addr = '0.0.0.0'.format(self.route_domain)
            try:
                self._address = ipaddress.ip_address(addr)
            except ValueError:
                self._address = ipaddress.ip_interface(addr)
            self.log.verbose('{} : set ipaddress {}'.format(self, self._address))
        elif hasattr(self, 'address') and not '%' in self.address and '/' in self.address:
            addr, mask = self.address.split('/', 1)
            self.address = f'{addr}%{self.route_domain}/{mask}'
        elif hasattr(self, 'address') and not '%' in self.address:
            self.address = f'{self.address}%{self.route_domain}'

    def _set_address(self, d_map):
        """
        return d_map with address as A.B.C.D%RD if ip_address or A.B.C.D%RD/CIDR if ip_interface
        """
        if '%' in d_map.get('address', ''):
            """ route domain already set .. don't touch anything """
            return d_map
        elif '/' in d_map.get('address', ''):
            addr, mask = d_map.get('address', '').split('/')
            d_map['address'] = '{}%{}/{}'.format(addr, d_map.get('route_domain', ''), mask)
        else:
            d_map['address'] = '{}%{}'.format(d_map.get('address'), d_map.get('route_domain', ''))
        return d_map

    def set_attrs(self, d_map):
        super().set_attrs(d_map)
        self._set_ipaddress()

    def sanitize(self, d_map):
        d_map = self._set_address(d_map)
        return super().sanitize(d_map)

    @staticmethod
    def split_domain_addr(addr):
        """ return address and route domain """
        address, _, raw = addr.partition('%')
        if raw:
            rd, _, mask = raw.partition('/')
        else:
            rd = '0'
            mask = ''
        if mask:
            mask = _ + mask
        else:
            mask = ''
        return u'{}{}'.format(address, mask), rd

class Vlan(Resource):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.net.vlans.vlan

class Route_Domain(Resource):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.net.route_domains.route_domain

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

class SelfIP(NetResource):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.net.selfips.selfip


