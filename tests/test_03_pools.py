import pytest

from icontrol.exceptions import iControlUnexpectedHTTPError

from tests.test_00_create_env import PREFIX

from five.utils import import_conf
from five.ltm import Pool, Member
from five.exceptions import ContextNotFound

@pytest.fixture(scope='class')
def dummy_pools():
    raw_pools = import_conf('tests/test_pools.yaml')
    dummy_pools = [Pool(name='{}{}'.format(PREFIX, name), **data) for name, data in raw_pools.items()]
    assert dummy_pools
    yield dummy_pools

@pytest.fixture(scope='class')
def valid_dummy_pools(dummy_pools):
    valid_dummy_pools = [pl for pl in dummy_pools if 'no_members' not in pl.name]
    assert valid_dummy_pools
    yield valid_dummy_pools

@pytest.fixture
def infra_pools(bigip):
    infra_pools = [res for res in bigip.grep(PREFIX) if isinstance(res, Pool)]
    assert infra_pools
    yield infra_pools

def test_create_pools(bigip, dummy_pools, valid_dummy_pools):
    """
    Test pools creation from test_pools.yaml
    Test environment have to be set first
    """
    for pl in dummy_pools:
        with bigip.current_bigip(bigip.ref_bigip):
            if 'no_members' in pl.name:
                ## Can't find context without member
                with pytest.raises(ContextNotFound):
                    bigip.create_with_context('Pool', pl)
            else:
                bigip.create_with_context('Pool', pl)
    pools = bigip.ref_bigip.tm.ltm.pools.get_collection()
    for pl in valid_dummy_pools:
        assert pl.name in [pl.name for pl in pools]
        assert bigip.get(**vars(pl)) != set()

def test_compare_with_real(bigip, dummy_pools, valid_dummy_pools):
    for pl in valid_dummy_pools:
        _, context = bigip.have_uniq_context(pl)
        pl.partition = context.partition
        with pl.current_bigip(bigip.ref_bigip):
            assert not pl.compare_with_real()
            pl.description = 'toto test'
            assert pl.compare_with_real() == {'description': ('toto test', getattr(pl.real, 'description', None))}
            pl.load()
            pl.real.modify(description = 'from web')
            assert pl.compare_with_real() == {'description': (getattr(pl, 'description', None), 'from web')}

def test_patch(bigip, infra_pools):
    for pl in infra_pools:
        with pl.current_bigip(bigip.ref_bigip):
            ## change all members before patch
            for m in pl.members:
                m.description = 'test'
            pl.patch(description='test test test',
                    monitor='tcp_half_open', members=pl.members)
            assert pl.real.description == 'test test test'
            assert pl.real.monitor == '/Common/tcp_half_open '
            assert pl.description == 'test test test'
            assert pl.monitor == '/Common/tcp_half_open'
            for m in pl.real.members_s.get_collection():
                assert m.description == 'test'
            for m in pl.members:
                assert m.description == 'test'

def test_update(bigip, infra_pools):
    for pl in infra_pools:
        with pl.current_bigip(bigip.ref_bigip):
            pl.description = None
            ## patch member
            pl.members[0].ratio = 9
            pl.update()
            real = pl.load()
            with pytest.raises(AttributeError):
                real.description
            with pytest.raises(AttributeError):
                pl.description
            assert real.members_s.members.load(name=pl.members[0].name, partition=pl.partition).ratio == 9
            assert pl.members[0].ratio == 9

def test_add_members(bigip, infra_pools):
    for pl in infra_pools:
        with pl.current_bigip(bigip.ref_bigip):
            nd = [n for n in bigip.nodes if n.partition == pl.partition][0]
            pl.add_member('{}:4242'.format(nd.name))
            real = pl.load()
            assert real.members_s.members.load(name='{}:4242'.format(nd.name), partition=nd.partition)
            assert pl.get_member('{}:4242'.format(nd.name))

def test_del_members(bigip, infra_pools):
    for pl in infra_pools:
        with pl.current_bigip(bigip.ref_bigip):
            nd = [n for n in bigip.nodes if n.partition == pl.partition][0]
            pl.del_member('{}:4242'.format(nd.name))
            real = pl.load()
            with pytest.raises(iControlUnexpectedHTTPError):
                real.members_s.members.load(name='{}:4242'.format(nd.name), partition=nd.partition)
            assert not pl.get_member('{}:4242'.format(nd.name))

def test_disable(bigip, infra_pools):
    for pl in infra_pools:
        with pl.current_bigip(bigip.ref_bigip):
            pl.disable()
            pl.load()
            for m in pl.members:
                assert m.session == 'user-disabled'
                assert m.state != 'user-down'

def test_offline(bigip, infra_pools):
    for pl in infra_pools:
        with pl.current_bigip(bigip.ref_bigip):
            pl.offline()
            pl.load()
            for m in pl.members:
                assert m.session == 'user-disabled'
                assert m.state == 'user-down'

def test_enable(bigip, infra_pools):
    for pl in infra_pools:
        with pl.current_bigip(bigip.ref_bigip):
            pl.enable()
            pl.load()
            for m in pl.members:
                # if node has a specific monitor, return monitor-enabled instead of user-enabled
                assert m.session == 'user-enabled' or m.session == 'monitor-enabled'
                assert m.state != 'user-down'
