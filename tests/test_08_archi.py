import pytest

from five import import_conf, Archi, Node
from five.exceptions import ContextNotFound

@pytest.fixture(scope='class')
def archi(infra):
    raw_archi = import_conf('./tests/test_archi.yaml')
    archi = Archi(infra, **raw_archi)
    yield archi

def test_wrong_archi_init(infra):
    with pytest.raises(ValueError):
        ## not basename, address nodes or services
        Archi(infra, **{})

def test_parse_raw_nodes_and_context(archi):
    ## note that _parse_raw_nodes already been execute at init of Archi
    nodes = archi._parse_raw_nodes()
    nodes = sorted(nodes, key=lambda x: x.name)
    assert len(nodes) == 2
    nd1 = nodes[0]
    assert nd1.name == '__Test_Five_archi_node01'
    assert nd1.address == '10.1.41.100'
    nd2 = nodes[1]
    assert nd2.name == '__Test_Five_archi_node02'
    assert nd2.address == '10.1.41.191'
    assert nd2.description == 'complex node'

def test_retreive_context(infra, archi):
    ## _retreive_context already been execute at init of Archi
    ## just checked values
    assert archi.context
    assert archi.route_domain == 4000
    assert archi.partition == '__Test_Five_part_01'
    ##no context
    with pytest.raises(ContextNotFound):
        Archi(infra, basename='wrong', address='192.168.1.1',
                nodes={'wrong01':'192.168.44.2'},
                services = {'80':{}})

def test_clean_dict_none_values(archi):
    data = {'a':1, 'b':2, 'c':None}
    data = archi._clean_dict_none_values(data)
    assert len(data) == 2
    assert data.get('a') == 1
    assert data.get('b') == 2
    with pytest.raises(KeyError):
        data['c']

def test_set_naming(archi):
    # Test _set_pool_name and _set_virtual_name together since it is set with same data
    port = '443'
    ## with no overwritte
    d_data = {}
    assert archi._set_pool_name(port, d_data) == 'pl___Test_Five_archi_port-443'
    assert archi._set_virtual_name(port, d_data) == 'vs___Test_Five_archi_tcp-443'
    ## service overwritte
    d_data = {'suffix': '_sv_suff',
              'basename': '__Test_Five_sv_base',
              'ipProtocol': 'udp'}
    assert archi._set_pool_name(port, d_data) == 'pl___Test_Five_sv_base_port-443_sv_suff'
    assert archi._set_virtual_name(port, d_data) == 'vs___Test_Five_sv_base_udp-443_sv_suff'
    ## service pool overwritte
    d_data.update({'pool_port': '80',
                   'pool_basename': '__Test_Five_pl_base',
                   'pool_suffix': '_pl_suff',
                   'ipProtocol': 'tcp',
                   'internal': True})
    assert archi._set_pool_name(port, d_data) == 'pl___Test_Five_pl_base_port-80_pl_suff'
    assert archi._set_virtual_name(port, d_data) == 'vs___Test_Five_sv_base_tcp-443_sv_suff_int'

def test_parse_pool_params(archi):
    port = '443'
    ## no overwritte
    d_data = {}
    pool = archi._parse_pool_params(port, d_data)
    assert pool.name == archi._set_pool_name(port, d_data)
    assert pool.monitor == 'tcp'
    assert set(pool.members) == set(['__Test_Five_archi_node01:443','__Test_Five_archi_node02:443'])
    assert pool.description == None
    with pytest.raises(AttributeError):
        pool.loadBalancingMode

#def test_create(archi):
#    with archi.current_bigip(archi.bigip.ref_bigip):
#        res = archi.create()
#        ## here current_user has to be 'admin'
#        assert archi.current_user == 'admin'
#    assert not res['monitors']['errors']
#    assert not res['nodes']['errors']
#    assert not res['pools']['errors']
#    assert not res['rules']['errors']
#    assert not res['virtuals']['errors']

def test_create_monitors(archi):
    bigip = archi.bigip
    real_bigip = bigip.ref_bigip
    with archi.current_bigip(real_bigip):
        archi.create_monitors()
    ## check monitors
    assert real_bigip.tm.ltm.monitor.https.http.load(name='__Test_Five_spec_monitor', partition='__Test_Five_part_01')
    success, monit = bigip.get(name='__Test_Five_spec_monitor')
    assert success
    assert monit.send == 'GET /monitor/check\\r\\n'
    assert monit.recv == 'IT WORKS'

def test_create_nodes(archi):
    bigip = archi.bigip
    real_bigip = bigip.ref_bigip
    with archi.current_bigip(real_bigip):
        archi.create_nodes()
    ## check nodes
    assert real_bigip.tm.ltm.nodes.node.load(name='__Test_Five_archi_node01', partition='__Test_Five_part_01')
    success, nd = bigip.get(name='__Test_Five_archi_node01')
    assert success
    assert nd.address == '10.1.41.100%4000'
    assert nd.route_domain == '4000'
    assert real_bigip.tm.ltm.nodes.node.load(name='__Test_Five_archi_node02', partition='__Test_Five_part_01')
    success, nd = bigip.get(name='__Test_Five_archi_node02')
    assert success
    assert nd.address == '10.1.41.191%4000'
    assert nd.description == 'complex node'

def test_create_pools(archi):
    bigip = archi.bigip
    real_bigip = bigip.ref_bigip
    with archi.current_bigip(real_bigip):
        archi.create_pools()
    ## check pools
    assert real_bigip.tm.ltm.pools.pool.load(name='pl___Test_Five_archi_port-80', partition='__Test_Five_part_01')
    success, pl = bigip.get(name='pl___Test_Five_archi_port-80')
    assert success
    assert set([m.name for m in pl.members]) == set(['__Test_Five_archi_node01:80', '__Test_Five_archi_node02:80'])
    assert pl.monitor.split('/')[-1] == '__Test_Five_spec_monitor'
    assert real_bigip.tm.ltm.pools.pool.load(name='pl___Test_Five_archi_port-444', partition='__Test_Five_part_01')
    success, pl = bigip.get(name='pl___Test_Five_archi_port-444')
    assert success
    assert set([m.name for m in pl.members]) == set(['__Test_Five_archi_node01:444', '__Test_Five_archi_node02:444'])
    assert pl.monitor.split('/')[-1] == 'tcp'
    assert real_bigip.tm.ltm.pools.pool.load(name='pl___Test_Five_archi_node01_port-22', partition='__Test_Five_part_01')
    success, pl = bigip.get(name='pl___Test_Five_archi_node01_port-22')
    assert success
    assert set([m.name for m in pl.members]) == set(['__Test_Five_archi_node01:22'])
    assert pl.monitor.split('/')[-1] == 'tcp'
    assert pl.description == 'pool desc'

def test_create_profiles(archi):
    bigip = archi.bigip
    real_bigip = bigip.ref_bigip
    with archi.current_bigip(real_bigip):
        archi.create_profiles()
    ##check profiles
    assert real_bigip.tm.ltm.profile.https.http.load(name='__Test_Five_spec_http_profiles', partition='__Test_Five_part_01')
    assert real_bigip.tm.ltm.profile.client_ssls.client_ssl.load(name='__Test_Five_ssl_root_01', partition='__Test_Five_part_01')
    assert real_bigip.tm.ltm.profile.client_ssls.client_ssl.load(name='__Test_Five_ssl_default_sni', partition='__Test_Five_part_01')
    assert real_bigip.tm.ltm.profile.client_ssls.client_ssl.load(name='__Test_Five_ssl_01', partition='__Test_Five_part_01')
    assert real_bigip.tm.ltm.profile.client_ssls.client_ssl.load(name='__Test_Five_ssl_02', partition='__Test_Five_part_01')
    success, ssl_01 = bigip.get(name='__Test_Five_ssl_01')
    assert success
    assert ssl_01.defaultsFrom.split('/')[-1] == '__Test_Five_ssl_root_01'
    assert ssl_01.serverName == '01.toto.fr'
    success, ssl_02 = bigip.get(name='__Test_Five_ssl_02')
    assert success
    assert ssl_02.defaultsFrom.split('/')[-1] == '__Test_Five_ssl_root_01'
    assert ssl_02.serverName == '02.toto.fr'

def test_create_rules(archi):
    bigip = archi.bigip
    real_bigip = bigip.ref_bigip
    with archi.current_bigip(real_bigip):
        archi.create_rules()
    assert real_bigip.tm.ltm.rules.rule.load(name='__Test_Five_rule_archi', partition='__Test_Five_part_01')
    success, rule = bigip.get(name='__Test_Five_rule_archi')
    assert success
    assert rule.apiAnonymous

def test_create_persistences(archi):
    bigip = archi.bigip
    real_bigip = bigip.ref_bigip
    with archi.current_bigip(real_bigip):
        archi.create_persistences()
    assert real_bigip.tm.ltm.persistence.cookies.cookie.load(name='__Test_Five_archi_cookie', partition='__Test_Five_part_01')
    success, cookie = bigip.get(name='__Test_Five_archi_cookie')
    assert success
    assert cookie.matchAcrossVirtuals == 'enabled'
    assert cookie.cookieName == 'VOLT_SESSION'
    assert real_bigip.tm.ltm.persistence.source_addrs.source_addr.load(name='__Test_Five_archi_source_addr',
                                                                       partition='__Test_Five_part_01')
    success, source = bigip.get(name='__Test_Five_archi_source_addr', partition='__Test_Five_part_01')
    assert success
    assert source.matchAcrossServices == 'enabled'

def test_create_virtuals(archi):
    bigip = archi.bigip
    real_bigip = bigip.ref_bigip
    with archi.current_bigip(real_bigip):
        archi.create_virtuals()
    ## check virtuals exist on real equipment
    assert real_bigip.tm.ltm.virtuals.virtual.load(name='vs___Test_Five_archi_tcp-80', partition='__Test_Five_part_01')
    assert real_bigip.tm.ltm.virtuals.virtual.load(name='vs___Test_Five_archi_tcp-80_int', partition='__Test_Five_part_01')
    assert real_bigip.tm.ltm.virtuals.virtual.load(name='vs___Test_Five_archi_tcp-443', partition='__Test_Five_part_01')
    ## external virtual HTTP
    success, extvs = bigip.get(name='vs___Test_Five_archi_tcp-80')
    assert success
    assert [r.split('/')[-1] for r in extvs.rules] == ['__Test_Five_rule_archi']
    assert extvs.pool == '/__Test_Five_part_01/pl___Test_Five_archi_port-80'
    assert extvs.destination.split('/')[-1] == '10.1.40.100%4000:80'
    assert extvs.address == '10.1.40.100%4000'
    assert extvs.port == '80'
    assert extvs.route_domain == '4000'
    assert extvs.vlansEnabled
    assert extvs.vlans == ['/__Test_Five_part_01/__Test_Five_rd4000_vlan_external_4040']
    assert extvs.persist[0]['name'] == '__Test_Five_archi_cookie'
    ## internal virtual HTTP
    success, intvs = bigip.get(name='vs___Test_Five_archi_tcp-80_int')
    assert success
    assert intvs.pool == '/__Test_Five_part_01/pl___Test_Five_archi_port-80'
    assert intvs.destination.split('/')[-1] == '10.1.40.100%4000:80'
    assert intvs.address == '10.1.40.100%4000'
    assert intvs.port == '80'
    assert intvs.vlans == ['/__Test_Five_part_01/__Test_Five_rd4000_vlan_internal_4041']
    assert intvs.route_domain == '4000'
    assert intvs.vlansEnabled
    assert intvs.sourceAddressTranslation == {'type':'automap'}
    ## external virtual HTTPS
    success, extvs = bigip.get(name='vs___Test_Five_archi_tcp-443')
    assert success
    assert extvs.pool == '/__Test_Five_part_01/pl___Test_Five_archi_port-80'
    assert extvs.destination.split('/')[-1] == '10.1.40.100%4000:443'
    assert extvs.address == '10.1.40.100%4000'
    assert extvs.port == '443'
    assert extvs.route_domain == '4000'
    assert extvs.vlansEnabled
    assert extvs.vlans == ['/__Test_Five_part_01/__Test_Five_rd4000_vlan_external_4040']
    assert set(extvs.profiles) == set(['/__Test_Five_part_01/__Test_Five_spec_http_profiles',
                                       '/__Test_Five_part_01/__Test_Five_ssl_default_sni',
                                       '/__Test_Five_part_01/__Test_Five_ssl_01',
                                       '/__Test_Five_part_01/__Test_Five_ssl_02',
                                       '/Common/tcp'])
    assert extvs.persist[0]['name'] == '__Test_Five_archi_cookie'

