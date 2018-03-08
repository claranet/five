import pytest

from tests.test_00_create_env import PREFIX
from five.utils import import_conf
from five.ltm import Profile

@pytest.fixture(scope='class')
def dummy_profiles():
    raw_profiles = import_conf('tests/test_profiles.yaml')
    dummy_profiles = [Profile(name='{}{}'.format(PREFIX, name), partition='Common', **data) for name, data in
                      raw_profiles.items()]
    dummy_profiles.sort(key=lambda x: x.name)
    assert dummy_profiles   ## must not be empty
    yield dummy_profiles

@pytest.fixture
def infra_profiles(bigip):
    return [p for p in bigip.grep(PREFIX) if isinstance(p, Profile)]

def test_create_profiles(bigip, dummy_profiles):
    for p in dummy_profiles:
        with bigip.current_bigip(bigip.ref_bigip):
            bigip.create('Profile', **vars(p))
    for p in dummy_profiles:
        with p.current_bigip(bigip.ref_bigip):
            assert p.load()
            assert bigip.get(**vars(p))

def test_compare_with_real(bigip, infra_profiles):
    for p in infra_profiles:
        with p.current_bigip(bigip.ref_bigip):
            assert not p.compare_with_real()

def test_patch(bigip, infra_profiles):
    ## http
    for p in [p for p in infra_profiles if p._type == 'http']:
        with p.current_bigip(bigip.ref_bigip):
            p.patch(insertXforwardedFor='disabled')
            real = p.load()
            assert real.insertXforwardedFor == 'disabled'
            assert p.insertXforwardedFor == 'disabled'

def test_update(bigip, infra_profiles):
    for p in [p for p in infra_profiles]:
        with p.current_bigip(bigip.ref_bigip):
            with pytest.raises(NotImplementedError):
                p.update()

