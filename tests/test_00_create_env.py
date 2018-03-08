import pytest

from icontrol.exceptions import iControlUnexpectedHTTPError
from f5.bigip import BigIP

from five.bigip import Bigip
from five.utils import import_conf
from five.resources import *
from five.exceptions import NotFound
from tests.create_env import *

@pytest.fixture(scope='class')
def env():
    yield import_conf('./tests/test_env.yaml')

def del_and_assert_collection(bigip, cls, collection):
    for res in collection:
        with bigip.current_bigip(bigip.ref_bigip):
            assert bigip.delete(cls, res) == (True, None)
            assert bigip.get(**vars(res)) == (False, set())
        with pytest.raises(NotFound):
            with res.current_bigip(bigip.ref_bigip):
                res.load()

def test_delete_environments(bigip):
    """
    delete all object with name that matched match
    In order:
        destroy all #virtuals
                    #monitors
                    #rules
                    #policies
                    #profiles
                    pools
                    nodes
                    selfips
                    route_domains
                    vlans
                    partitions
    """
    bigip.log.info('{}: Start delete environment {}'.format(bigip, PREFIX))
    ## LTM Obj
    ltm_class = ['Virtual', 'Persistence', 'Rule', 'Pool', 'Node', 'Monitor', 'Snat']
    for cls in ltm_class:
        del_and_assert_collection(bigip, cls, [res for res in bigip.grep(PREFIX) if isinstance(res, eval(cls))])
    # profile to handle inheritance
    ## del daugther first
    del_and_assert_collection(bigip, 'Profile', [p for p in bigip.grep(PREFIX) if isinstance(p, Profile) and
                                                 p.defaultsFrom != '/Common/{}'.format(p._type)])
    ## then other
    del_and_assert_collection(bigip, 'Profile', [p for p in bigip.grep(PREFIX) if isinstance(p, Profile)])
    ## Key and Cert
    for cls in ['Ssl_key', 'Ssl_cert']:
        del_and_assert_collection(bigip, cls, [res for res in bigip.grep(PREFIX, cls=eval(cls))])
    ## VIP SelfIP
    for res in [res for res in bigip.grep(PREFIX)
                if isinstance(res, SelfIP) and res.trafficGroup != '/Common/traffic-group-local-only']:
        with bigip.current_bigip(bigip.ref_bigip):
            assert bigip.delete('SelfIP', res) == (True, None)
            assert bigip.get(**vars(res)) == (False, set())
            with pytest.raises(iControlUnexpectedHTTPError):
                with res.current_bigip(bigip.ref_bigip):
                   res.load()
    bigip.sync()
    cluster_devices = bigip.real_peers[:]
    cluster_devices.append(bigip)
    for dev in cluster_devices:
        with dev.current_bigip(dev.ref_bigip):
            dev.load()
    ## Now on each device
    class_list = ['SelfIP', 'Route_Domain', 'Vlan', 'Partition']
    for device in cluster_devices:
        ### Unset possible default RD before start to clean all resource
        for partition in device.partitions:
            if PREFIX in partition.name:
                with partition.current_bigip(device.ref_bigip):
                    partition.set_default_route_domain(0)
        for cls in class_list:
            del_and_assert_collection(device, cls, [res for res in device.grep(PREFIX) if isinstance(res, eval(cls))])
        time.sleep(5)
    bigip.sync()
    bigip.retreive_contexts()

def test_create_partition(bigip, env):
    partitions = ['{}{}'.format(PREFIX, partition) for partition in env.get('partitions')]
    for partition in partitions:
        create_partition(bigip, partition)
    for partition in partitions:
        ## tests creation on Real BigIP Master
        assert bigip.ref_bigip.tm.sys.folders.folder.load(name=partition)
        ## tests creation on Five Bigip
        assert [part for part in bigip.partitions if part.name == partition]
    for device in bigip.real_peers:
        for partition in partitions:
            ## tests creation on Real BigIP Master
            assert device.ref_bigip.tm.sys.folders.folder.load(name=partition)
            ## tests creation on Five Bigip
            assert [part for part in bigip.partitions if part.name == partition]

def test_create_vlans(bigip, env):
    for partition, d_map in env.get('partitions').items():
        partition = PREFIX+partition
        create_vlans(bigip, partition, d_map)
        create_vlans(bigip.real_peers[0], partition, d_map)
    bigip.sync()
    ## retreive info from ENV to check
    vlans =  [{'name':'{}{}'.format(PREFIX, vlan),
              'tag':data.get('id'),
              'partition':'{}{}'.format(PREFIX, partition)}
              for partition, d_part in env.get('partitions').items()
              for rd, d_rd in d_part.get('route_domains').items() for vlan, data in d_rd.get('vlans').items()]
    for vlan in vlans:
        ## create on Real Bigip Master
        assert bigip.ref_bigip.tm.net.vlans.vlan.load(name=vlan['name'], partition=vlan['partition'])
        ## create on Real Bigip Slave
        assert bigip.real_peers[0].ref_bigip.tm.net.vlans.vlan.load(name=vlan['name'], partition=vlan['partition'])
        ## creation on Five Bigip
        assert [vl for vl in bigip.vlans if vl.name == vlan.get('name') and vl.tag == vlan.get('tag')
                and vl.partition == vlan.get('partition')]
        ## creation on Five Bigip
        assert [vl for vl in bigip.real_peers[0].vlans if vl.name == vlan.get('name') and vl.tag == vlan.get('tag')
                and vl.partition == vlan.get('partition')]

def test_create_route_domains(bigip, env):
    for partition, d_map in env.get('partitions').items():
        partition = PREFIX+partition
        create_route_domains(bigip, partition, d_map)
        create_route_domains(bigip.real_peers[0], partition, d_map)
    bigip.sync()
    rds = [{'name':PREFIX+rd,
            'partition':PREFIX+partition,
            'id':d_rd.get('id'),
            'default_rd': d_rd.get('default_rd'),
            'vlans':d_rd.get('vlans').keys()}
                for partition, d_part in env.get('partitions').items()
                for rd, d_rd in d_part.get('route_domains').items()]
    for rd in rds:
        ## create on Real Bigip Master
        assert bigip.ref_bigip.tm.net.route_domains.route_domain.load(name=rd.get('name'), partition=rd.get('partition'))
        ## create on Real Bigip Slave
        assert bigip.real_peers[0].ref_bigip.tm.net.route_domains.route_domain.load(name=rd.get('name'),
                                                                                partition=rd.get('partition'))
        ## creation on Five Bigip
        assert [_rd for _rd in bigip.route_domains if _rd.name == rd.get('name') and _rd.id == rd.get('id')
                and set(_rd.vlans) == set(['/{}/{}'.format(rd.get('partition'), PREFIX+vlan) for vlan in rd.get('vlans')])]
        ## creation on Five Bigip
        assert [_rd for _rd in bigip.real_peers[0].route_domains if _rd.name == rd.get('name')
                and _rd.id == rd.get('id')
                and set(['/{}/{}'.format(rd.get('partition'), PREFIX+vlan) for vlan in rd.get('vlans')])]
        part = bigip.ref_bigip.tm.auth.partitions.partition.load(name=rd.get('partition'))
        ## check default route domain
        if rd.get('default_rd'):
            assert getattr(part, 'defaultRouteDomain', None) == int(rd.get('id'))
        else:
            assert getattr(part, 'defaultRouteDomain', None) == int('0')
    bigip.sync()

def test_create_selfips(bigip, env):
    for partition, d_part in env.get('partitions').items():
        selfips = format_selfips(PREFIX+partition, d_part)
        create_selfips(bigip, selfips[0])
        for selfip in selfips[0]:
            real = bigip.ref_bigip.tm.net.selfips.selfip.load(name=selfip.get('name'), partition=PREFIX+partition)
            assert real
            assert '%' in real.address
            assert not '%0' in real.address
        create_selfips(bigip.real_peers[0], selfips[1])
        for selfip in selfips[1]:
            real = bigip.real_peers[0].ref_bigip.tm.net.selfips.selfip.load(name=selfip.get('name'), partition=PREFIX+partition)
            assert real
            assert '%' in real.address
            assert not '%0' in real.address
        create_selfips(bigip, selfips['vip'])
        for selfip in selfips['vip']:
            real = bigip.ref_bigip.tm.net.selfips.selfip.load(name=selfip.get('name'), partition=PREFIX+partition)
            assert real
            assert '%' in real.address
            assert not '%0' in real.address
    bigip.sync()

def test_retreive_contexts(bigip):
    ## no test yet beut had to be run in order to retreive new contexts
    bigip.retreive_contexts()
