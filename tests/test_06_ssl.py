import pytest

from tests.test_00_create_env import PREFIX
from five.resources import Ssl_key, Ssl_cert
from five.ltm import Profile

def test_create_key(bigip):
    with bigip.current_bigip(bigip.ref_bigip):
        keypath = bigip.upload_file('./tests/ssl/five.key')
        key, real_key = bigip.create('Ssl_key', name=PREFIX+'five', sourcePath=keypath, partition='Common')
        assert bigip.ref_bigip.tm.sys.file.ssl_keys.ssl_key.load(name=key.name, partition='Common')
        assert bigip.grep(key.name, cls=Ssl_key)
        ## new
        keypath = bigip.upload_file('./tests/ssl/five-new.key')
        key, real_key = bigip.create('Ssl_key', name=PREFIX+'five-new', sourcePath=keypath, partition='Common')
        assert bigip.ref_bigip.tm.sys.file.ssl_keys.ssl_key.load(name=key.name, partition='Common')
        assert bigip.grep(key.name, cls=Ssl_key)

def test_create_cert(bigip):
    with bigip.current_bigip(bigip.ref_bigip):
        certpath = bigip.upload_file('./tests/ssl/five.crt')
        cert, real_cert = bigip.create('Ssl_cert', name=PREFIX+'five', sourcePath=certpath, partition='Common')
        assert bigip.ref_bigip.tm.sys.file.ssl_certs.ssl_cert.load(name=cert.name, partition='Common')
        assert bigip.grep(cert.name, cls=Ssl_cert)
        ## new
        certpath = bigip.upload_file('./tests/ssl/five-new.cer')
        cert, real_cert = bigip.create('Ssl_cert', name=PREFIX+'five-new', sourcePath=certpath, partition='Common')
        assert bigip.ref_bigip.tm.sys.file.ssl_certs.ssl_cert.load(name=cert.name, partition='Common')
        assert bigip.grep(cert.name, cls=Ssl_cert)

def test_create_ssl_prof(bigip):
    with bigip.current_bigip(bigip.ref_bigip):
        res, real = bigip.create('Profile', name=PREFIX+'ssl_five', key=PREFIX+'five.key', cert=PREFIX+'five.crt',
                                 partition='Common', _type='client_ssl')
        assert bigip.ref_bigip.tm.ltm.profile.client_ssls.client_ssl.load(name=res.name, partition=res.partition)
        assert bigip.grep(res.name, cls=Profile)

def test_many_options_prof(bigip):
    with bigip.current_bigip(bigip.ref_bigip):
        res, real = bigip.create('Profile', _type='client_ssl', name=PREFIX+'ssl_02_five', partition='Common', defaultsFrom=PREFIX+'ssl_five',
                                 serverName='toto.fr', sniDefault=True)
        assert bigip.ref_bigip.tm.ltm.profile.client_ssls.client_ssl.load(name=res.name, partition=res.partition)
        assert real.defaultsFrom == '/Common/'+PREFIX+'ssl_five'
        assert real.sniDefault == 'true'
        assert real.serverName == 'toto.fr'

def test_update_ssl_prof(bigip):
    prof = bigip.grep(PREFIX+'ssl', cls=Profile)[0]
    with bigip.current_bigip(bigip.ref_bigip):
        bigip.patch(prof, key=PREFIX+'five-new.key', cert=PREFIX+'five-new.crt')
    with prof.current_bigip(bigip.ref_bigip):
        real = prof.load()
        assert real.key == '/Common/'+PREFIX+'five-new.key' and real.cert == '/Common/'+PREFIX+'five-new.crt'

