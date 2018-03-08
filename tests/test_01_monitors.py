import pytest

from tests.test_00_create_env import PREFIX
from five.utils import import_conf
from five.ltm import Monitor

@pytest.fixture(scope='class')
def dummy_monitors():
    raw_monitors = import_conf('tests/test_monitors.yaml')
    dummy_monitors = [Monitor(name=name, partition='Common', **data) for name, data in raw_monitors.items()]
    assert dummy_monitors #must not be empty
    yield dummy_monitors

@pytest.fixture
def infra_monitors(bigip):
    infra_monitors = [res for res in bigip.grep(PREFIX) if isinstance(res, Monitor)]
    assert infra_monitors
    yield infra_monitors

def test_create_monitors(bigip, dummy_monitors):
    for m in dummy_monitors:
        with bigip.current_bigip(bigip.ref_bigip):
            bigip.create('Monitor', **vars(m))
    real_http_monitors = [m.name for m in bigip.ref_bigip.tm.ltm.monitor.https.get_collection()]
    for m in dummy_monitors:
        if m._type == 'http':
            assert m.name in real_http_monitors
    assert bigip.ref_bigip.tm.ltm.monitor.tcps.tcp.load(name='{}tcp_user'.format(PREFIX), partition='Common')

def test_compare_with_real(bigip, dummy_monitors):
    for m in dummy_monitors:
        with m.current_bigip(bigip.ref_bigip):
            assert not m.compare_with_real()

def test_patch(bigip, infra_monitors):
    for m in infra_monitors:
        with m.current_bigip(bigip.ref_bigip):
            m.patch(description='patched user monitor')
            assert m.real.description == 'patched user monitor'
            assert m.description == 'patched user monitor'

def test_update(bigip, infra_monitors):
    for m in infra_monitors:
        with m.current_bigip(bigip.ref_bigip):
            m.description = None
            m.interval = 2
            m.timeout = 7
            m.update()
            with pytest.raises(AttributeError):
                m.real.description
            with pytest.raises(AttributeError):
                m.description
            assert m.real.interval == 2
            assert m.real.timeout == 7
            assert m.interval == 2
            assert m.timeout == 7
