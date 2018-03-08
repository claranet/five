import pytest

from icontrol.exceptions import iControlUnexpectedHTTPError

from tests.test_00_create_env import PREFIX

from five.utils import import_conf
from five.ltm import Virtual
from five.exceptions import ContextNotFound

@pytest.fixture(scope='class')
def dummy_virtuals():
    raw_virtuals = import_conf('tests/test_virtuals.yaml')
    dummy_virtuals = [Virtual(name='{}{}'.format(PREFIX, name), **data) for name, data in raw_virtuals.items()]
    assert dummy_virtuals
    yield dummy_virtuals

@pytest.fixture(scope='class')
def valid_dummy_virtuals(dummy_virtuals):
    valid_dummy_virtuals = [vs for vs in dummy_virtuals if getattr(vs, 'pool', None)]
    assert valid_dummy_virtuals
    yield valid_dummy_virtuals

@pytest.fixture
def infra_virtuals(bigip):
    infra_virtuals = [res for res in bigip.grep(PREFIX) if isinstance(res, Virtual)]
    assert infra_virtuals
    yield infra_virtuals

def test_create_virtuals(bigip, dummy_virtuals, valid_dummy_virtuals):
    for vs in dummy_virtuals:
        with bigip.current_bigip(bigip.ref_bigip):
            if getattr(vs, 'pool', None):
                bigip.create_with_context('Virtual', vs)
            else:
                with pytest.raises(ContextNotFound):
                    bigip.create_with_context('Virtual', vs)
    virtuals = bigip.ref_bigip.tm.ltm.virtuals.get_collection()
    for vs in valid_dummy_virtuals:
        assert vs.name in [vs.name for vs in virtuals]
        assert bigip.get(**vars(vs)) != set()
    for vs in valid_dummy_virtuals:
        with vs.current_bigip(bigip.ref_bigip):
            assert not vs.route_domain == 0
            assert '%' in vs.real.destination
            assert not '%0' in vs.real.destination

def test_compare_with_real(bigip, dummy_virtuals, valid_dummy_virtuals):
    for vs in valid_dummy_virtuals:
        _, context = bigip.have_uniq_context(vs)
        vs.partition = context.partition        #since its a dummy object we have to set partition before try to load it
        with vs.current_bigip(bigip.ref_bigip):
            assert not vs.compare_with_real()
            vs.description = 'toto test'
            assert vs.compare_with_real() == {'description': ('toto test', getattr(vs.real, 'description', None))}
            vs.load()
            vs.real.description = 'from web'
            vs.real.update()
            assert vs.compare_with_real() == {'description': (getattr(vs, 'description', None), 'from web')}

def test_patch(bigip, infra_virtuals):
    with bigip.current_bigip(bigip.ref_bigip):
        for vs in infra_virtuals:
            bigip.patch(vs, description='test desc')
            with vs.current_bigip(bigip.ref_bigip):
                real = vs.load()
                assert real.description == 'test desc'
                assert vs.description == 'test desc'

def test_update(bigip, infra_virtuals):
    for vs in infra_virtuals:
        with vs.current_bigip(bigip.ref_bigip):
            vs.description = None
            vs.update()
            real = vs.load()
            with pytest.raises(AttributeError):
                real.description
                vs.description

def test_disable(bigip, infra_virtuals):
    for vs in infra_virtuals:
        with vs.current_bigip(bigip.ref_bigip):
            vs.disable()
            real = vs.load()
            assert real.disabled == True
            assert vs.disabled == True
            with pytest.raises(AttributeError):
                real.enabled
                vs.enabled

def test_enable(bigip, infra_virtuals):
    for vs in infra_virtuals:
        with vs.current_bigip(bigip.ref_bigip):
            vs.enable()
            real = vs.load()
            assert real.enabled == True
            assert vs.enabled == True
            with pytest.raises(AttributeError):
                real.disabled
                vs.disabled

## to see later
"""
def add_rule():
    pass
def add_profile():
    pass
def add_policy():
    pass
"""

