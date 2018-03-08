import pytest

from tests.test_00_create_env import PREFIX
from five.utils import import_conf
from five.ltm import Node

from five.exceptions import BigipNotSet

@pytest.fixture(scope='class')
def dummy_nodes():
    raw_nodes = import_conf('tests/test_nodes.yaml')
    dummy_nodes = [Node(name='{}{}'.format(PREFIX, name), address=address) for name, address in raw_nodes.items()]
    assert dummy_nodes
    yield dummy_nodes

@pytest.fixture
def infra_nodes(bigip):
    infra_nodes = [res for res in bigip.grep(PREFIX) if isinstance(res, Node)]
    assert infra_nodes
    yield infra_nodes

def test_create_nodes(bigip, dummy_nodes):
    """
    Test nodes creation from test_nodes.yaml
    Test environment have to be set first
    TO DO: tests create with option (desc, monitor, etc .. )
    """
    for nd in dummy_nodes:
        with bigip.current_bigip(bigip.ref_bigip):
            bigip.create_with_context('Node', nd)
    ### ON REAL BIGIP
    nodes = bigip.ref_bigip.tm.ltm.nodes.get_collection()
    ## valid BigipNotSet
    with pytest.raises(BigipNotSet):
        dummy_nodes[0].load()
    for nd in dummy_nodes:
        with nd.current_bigip(bigip.ref_bigip):
            assert nd.load()
            assert not nd.route_domain == 0
            assert '%' in nd.real.address
            assert not '%0' in nd.real.address

def test_compare_with_real(bigip, dummy_nodes):
    """
    compare dummy node object with real object
    """
    for nd in dummy_nodes:
        _, context = bigip.have_uniq_context(nd)
        nd.partition = context.partition
        nd.route_domain = context.route_domain
        with nd.current_bigip(bigip.ref_bigip):
            assert not nd.compare_with_real()
            nd.description = 'toto test'
            assert nd.compare_with_real() == {'description': ('toto test', getattr(nd.real, 'description', None))}
            nd.real.description = 'from web'
            nd.real.update()
            assert nd.compare_with_real() == {'description' : (getattr(nd, 'description', None), 'from web')}

def test_patch(bigip, infra_nodes):
    """
    test to patch nodes
    """
    for nd in infra_nodes:
        with nd.current_bigip(bigip.ref_bigip):
            nd.patch(description='test patch', monitor='icmp')
            real = nd.load()
            assert real.description == 'test patch'
            assert real.monitor == '/Common/icmp '
            assert nd.description == 'test patch'
            assert nd.monitor == '/Common/icmp'

def test_update(bigip, infra_nodes):
    """
    test to update nodes
    """
    for nd in infra_nodes:
        with nd.current_bigip(bigip.ref_bigip):
            nd.description = None
            nd.update()
            real = nd.load()
            with pytest.raises(AttributeError):
                real.description
            with pytest.raises(AttributeError):
                nd.description

def test_disable(bigip, infra_nodes):
    """
    """
    for nd in infra_nodes:
        with nd.current_bigip(bigip.ref_bigip):
            nd.disable()
            real = nd.load()
            assert real.session == 'user-disabled' and real.state != 'user-down'
            assert nd.session == 'user-disabled' and nd.state != 'user-down'

def test_offline(bigip, infra_nodes):
    """
    """
    for nd in infra_nodes:
        with nd.current_bigip(bigip.ref_bigip):
            nd.offline()
            real = nd.load()
            assert real.session == 'user-disabled' and real.state == 'user-down'
            assert nd.session == 'user-disabled' and nd.state == 'user-down'

def test_enable(bigip, infra_nodes):
    """
    """
    for nd in infra_nodes:
        with nd.current_bigip(bigip.ref_bigip):
            nd.enable()
            real = nd.load()
            assert real.session == 'user-enabled' and real.state != 'user-down'
            assert nd.session == 'user-enabled' and nd.state != 'user-down'
