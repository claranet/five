#coding: utf-8
import os
import logging
import json
from functools import wraps
from contextlib import contextmanager
from copy import copy

from icontrol.exceptions import iControlUnexpectedHTTPError

from five.base import Base
from five.exceptions import BigipNotSet, AlreadyExist, NotFound

class BaseResource(Base):
    """
    Meta class for BaseResource
    """

    def __init__(self, **kwargs):
        super().__init__()
        ## required for dummy object
        self.attrs_required = set(['name'])
        ## required to create real resource on BigIP
        self.attrs_required_for_real_res = set(['partition', 'name'])
        ## attrs to clean before push real resource on BigIP
        self.attrs_to_clean_before_push = set(['attrs_to_clean_after_pull', 'attrs_required', 'read_only_attrs',
                                               'attrs_required_for_real_res', 'do_not_clean_attrs',
                                               'attrs_to_clean_before_push', 'bigip', '_bigip', '_current_bigip', 'real', 'log',
                                               '_address', 'address'])
        ## attrs to clean after pulling real resource from BigIP
        self.attrs_to_clean_after_pull = ['_meta_data', 'generation', 'selfLink', 'ephemeral',
                                          'fqdn', 'trafficGroupReference', 'vlanReference', 'vlansReference',
                                          'rulesReference', 'nameReference', 'poolReference', 'vlansDisabled']
        ## on real resource, attr are not set if empty, we have to clean all attributes which are not present in real
        ## resource. Some of the attrs are never on the real bigip but we have to keep it.
        self.do_not_clean_attrs = set(['attrs_to_clean_after_pull', 'attrs_required', 'attrs_required_for_real_res',
                                       'read_only_attrs', 'do_not_clean_attrs', 'attrs_to_clean_before_push',
                                       'bigip', '_bigip', '_current_bigip', 'real', 'log'])
        ## read-only attrs : these attrs can not be modify on real resource once the resource is created
        self.read_only_attrs = set(['name'])
        self.bigip = None
        self.real = None

    def check_attrs(self):
        """ use to check if there is at least required attributes at init of the object """
        if self.attrs_required - set(vars(self).keys()):
            raise ValueError('you have to define at least : {}'.format(', '.join(self.attrs_required)))

    def set_attrs(self, d_map):
        """
        set attributes from d_map if key is not in attrs_to_clean_after_pull
        """
        #self.check_attrs_for_real_res(d_map)
        for attr, value in d_map.items():
            if attr not in self.attrs_to_clean_after_pull:
                if isinstance(value, (str, bytes)):
                    value = value.strip()
                setattr(self, attr, value)
        self.log.debug('{} : load attributes'.format(self))

    def clean_attrs(self, d_map):
        """
        clean all attributes that are not in d_map and not in do_not_clean_attrs
        """
        for attr in copy(vars(self)):
            if attr not in d_map and attr not in self.do_not_clean_attrs:
                self.log.verbose('del attr : {} {}'.format(attr, getattr(self, attr)))
                delattr(self, attr)

    @property
    @Base.check_current_bigip
    def res(self):
        """
        Return the right method in the f5-sdk
        eg:
            Node.res will return bigip.ltm.nodes.node
            Pool.res will resturn bigip.ltm.pools.pool
            ..
        """
        raise NotImplementedError

    @contextmanager
    def current_bigip(self, bigip):
        """
        context manager
        use to modify a resource with a user account rather than the admin account use to retreive all configuration
        """
        with super().current_bigip(bigip):
            try:
                self.load()
            except NotFound:
                pass
            yield
            self.real = None

    @property
    @Base.check_current_bigip
    def current_user(self):
        """ return the current user -- ie connected to the real equipment """
        return self._current_bigip._meta_data.get('username')

    @Base.check_current_bigip
    def refresh_from_real(self):
        """
        set all attributes to the new value from the real object
        clean all attributes that no longer exist on the real object
        """
        self.log.debug('{} : refresh from real object'.format(self))
        self.bigip = self.real._meta_data['bigip'].hostname
        self.set_attrs(vars(self.real))
        self.clean_attrs(vars(self.real))
        return self

    @Base.check_current_bigip
    def load(self):
        """ retreive existing resource from bigip and update attributes """
        ## bigip interpret the % so we have to encode it before
        try:
            self._load()
        except iControlUnexpectedHTTPError as e:
            if e.response.status_code == 404 and e.response.reason == 'Not Found':
                self.log.debug('{} : does not exist yet'.format(self))
                raise NotFound
            else:
                raise e
        return self.real

    def _load(self):
        self.real = self.res.load(name=self.name.replace('%', '%25'))
        self.refresh_from_real()

    @staticmethod
    def compare_dict(one, two):
        """
        iter on one
        """
        diff = dict()
        for k, v in one.items():
            if k in ['_current_bigip', 'real']:
                continue
            try:
                if v != two[k]:
                    diff.update({k: (v, two[k])})
            except KeyError:
                diff.update({k: (v, None)})
        return diff

    @Base.check_current_bigip
    def compare_with_real(self, patch=None):
        """
        Made a copy of self as reference (this reference is overwritte with patch if passed)
        Made a copy of self to retreive real information from BigIP
        compare all attributes in both way
        :return: dict as {attribute: (ref value, real value)}
        """
        ##copy from self
        ref_cop = copy(self)
        real_cop = copy(self)
        ## load real values from bigip
        real_cop.load()
        ## overwritte ref_cop with patch to compare with dict values
        if patch:
            for k, v in patch.items():
                setattr(ref_cop, k, v)
        ## compare in one way
        a = self.compare_dict(vars(ref_cop), vars(real_cop))
        ## other way
        b = self.compare_dict(vars(real_cop), vars(ref_cop))
        ## result
        if not a and not b: ## no diff
            return dict()
        else:   ## add existant argument on b that not in a
            for k, v in b.items():
                if k not in a:
                    a.update({k:(v[1], v[0])})
        return a

    def clean_read_only_attrs(self, d_patch):
        for attr in [attr for attr in self.read_only_attrs if attr in d_patch]:
            self.log.debug('{} : del read only attr {}'.format(self, attr))
            del(d_patch[attr])
        return d_patch

    @Base.check_current_bigip
    def update(self):
        """
        Update resource on bigip using attribute of the object.
        At the difference of the patch method, all attribute will be update !
        *read-only attributes are removed
        """
        d_patch = self.sanitize(copy(vars(self)))
        d_patch = self.clean_read_only_attrs(d_patch)
        self.real.modify(**d_patch)
        self.log.info('{} update by {}'.format(self, self.current_user))
        self.log.verbose('----- details : {}'.format(d_patch))
        self.load()

    @Base.check_current_bigip
    def patch(self, d_patch=None, **kwargs):
        """
        Update resource on bigip with dictionnary
        At the difference of the update method, only the defines attributes in dict are update
        *read-only attributes are removed
        """
        if d_patch:
            kwargs = d_patch
        kwargs = self.sanitize(kwargs)
        kwargs = self.clean_read_only_attrs(kwargs)
        self.real.modify(**kwargs)
        self.log.info('{} patch by {} with {}'.format(self, self.current_user, kwargs))
        self.load()

    def _create(self, d_create=dict()):
        """
        return sanitize dict from the object ready to be push with create().
        if d_create, update copy of object attributes
        the copy is sanitize and compare to attrs_required_for_real_res in order to ensure that enough data is send
        return the a sanitize dict ready to push
        """
        d_copy = copy(vars(self))
        if d_create:
            d_copy.update(d_create)
        sanitize_dict = self.sanitize(d_copy)
        if self.attrs_required_for_real_res - set(sanitize_dict):
            raise ValueError('You have to define at least : {} in the object or in the passed dictionnary'.format(', '.join(self.attrs_required_for_real_res)))
        self.log.verbose(f'{self.name} :: pushed dict :: {sanitize_dict}')
        return sanitize_dict

    @Base.check_current_bigip
    def create(self, d_create=dict()):
        """
        create resource on bigip, sanitize and check data with _create()
        """
        try:
            self.real = self.res.create(**self._create(d_create))
            self.log.info('{} : created by {}'.format(self, self.current_user))
            self.load()
        except iControlUnexpectedHTTPError as e:
            if e.response.status_code == 409:
                self.log.info('{} : already exist : {}'.format(self, json.loads(e.response.text)["message"]))
                raise AlreadyExist
            else:
                raise e
        return self.real

    @Base.check_current_bigip
    def delete(self):
        """
        delete resource on bigip
        """
        try:
            self.real.delete()
            self.log.info('{} : deleted by {}'.format(self, self.current_user))
        except iControlUnexpectedHTTPError as e:
            self.log.error('{} : fail to be deleted by {}'.format(self, self.current_user))
            self.log.error('{} : fail : {}'.format(self, e.response._content))
            return False, e.response._content
        return True, None

    def sanitize(self, d_data):
        d_san = dict()
        for k, v in d_data.items():
            if (k == 'session' and v not in ['user-enabled', 'user-disabled']) or \
                (k == 'state' and v not in ['user-up', 'user-down']):
                    self.log.verbose('{}: session/state not update with : {}'.format(self, v))
                    continue
            elif k not in self.attrs_to_clean_before_push:
                d_san.update({k:v})
            else:
                self.log.verbose('{} : delete before push to real: {} - {}'.format(self, k, v))
        return d_san

    def __str__(self):
        return "{} - {}".format(self.bigip, self.name)

    ## needed method to implement unpacking like a mapping
    ## call(**Resource())
    def __getitem__(self, item):
        return getattr(self, str(item))

    def keys(self):
        return vars(self).keys()

class Resource(BaseResource):
    """ Meta class Resource, specificatino of BaseResource """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_attrs(kwargs)
        self.check_attrs()

    def _load(self):
        self.real = self.res.load(name=self.name.replace('%', '%25'), partition=self.partition,
                                    requests_params={'params': {'expandSubcollections':'true'}})
        self.refresh_from_real()

class Peer(Resource):
    """ equipment configured as peer """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.cm.devices.device

class Partition(BaseResource):
    """ Folder object """
    def __init__(self, **kwargs):
        self.subPath = kwargs.get('subPath', '/')
        super().__init__(**kwargs)
        self.attrs_to_clean_before_push.add('default_rd')
        self.attrs_required_for_real_res.remove('partition')
        self.set_attrs(kwargs)
        self.check_attrs()

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.sys.folders.folder

    def _load(self):
        super()._load()
        if '/' not in self.name:
            auth_part = self._current_bigip.tm.auth.partitions.partition.load(name=self.name)
            self.default_rd = getattr(auth_part, 'defaultRouteDomain', None)
        return self.real

    @Base.check_current_bigip
    def set_default_route_domain(self, rd):
        """
        Set default route domain to a partition
        :param rd: route domain id (int)
        """
        auth_part = self._current_bigip.tm.auth.partitions.partition.load(name=self.name)
        auth_part.modify(defaultRouteDomain=rd)
        self.log.debug('{} set default route domain to {}'.format(self, auth_part.defaultRouteDomain))
        self.default_rd = rd

    def __str__(self):
        return self.name

class File(Resource):
    """ Meta file object """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.attrs_required_for_real_res.add('sourcePath')

    def sanitize(self, d_map):
        d_map = super().sanitize(d_map)
        if d_map.get('sourcePath', None) and d_map.get('sourcePath')[:5] != 'file:':
            d_map['sourcePath'] = 'file:' + d_map['sourcePath']
        return d_map

    def update(self):
        raise NotImplementedError('you cannot update a File')

    def patch(self):
        raise NotImplementedError('you cannot patch a File')

class Ssl_cert(File):
    """ ssl cert file object """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def sanitize(self, d_map):
        d_map = super().sanitize(d_map)
        if d_map.get('name', '')[-4:] == '.cer':
            d_map['name'] = d_map['name'].replace('.cer', '.crt')
        elif d_map.get('name', '')[-4:] != '.crt':
            d_map['name'] = d_map['name'] + '.crt'
        return d_map

    def set_attrs(self, d_map):
        super().set_attrs(d_map)
        if self.name[-4:] == '.cer':
            self.name = self.name.replace('.cer', '.crt')
        elif self.name[-4:] != '.crt':
            self.name = self.name+'.crt'

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.sys.file.ssl_certs.ssl_cert

    def handle_dns(self, dns):
        sub = getattr(self, 'subjectAlternativeName', None)
        if not sub:
            return False
        names = [s.replace('DNS:', '') for s in sub.split()]
        if dns in names:
            return True
        else:
            return False

class Ssl_key(File):
    """ ssl key file object """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def sanitize(self, d_map):
        d_map = super().sanitize(d_map)
        if d_map.get('name', '')[-4:] != '.key':
            d_map['name'] = d_map['name'] + '.key'
        return d_map

    def set_attrs(self, d_map):
        super().set_attrs(d_map)
        if self.name[-4:] != '.key':
            self.name = self.name+'.key'

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.sys.file.ssl_keys.ssl_key

class SecurityPolicy(Resource):
    """ ASM Policy object """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    @Base.check_current_bigip
    def res(self):
        return self._current_bigip.tm.asm.policies_s.policy

    def _load(self):
        """ retreive existing resource from bigip and update attributes """
        ## bigip interpret the % so we have to encode it before
        self.real = self.res.load(name=self.name.replace('%', '%25'), id=self.id)
        self.refresh_from_real()
        return self.real

