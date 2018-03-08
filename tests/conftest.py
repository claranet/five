import pytest

from five.utils import import_conf
from five import Infra, Bigip

@pytest.fixture(autouse=True, scope='session')
def infra():
    conf = import_conf('./conf.dev')
    infra = Infra(conf)
    yield infra

@pytest.fixture(autouse=True, scope='session')
def bigip(infra):
    """
    This fixture is run once before all tests
    When used in test you can retreive the bigip object
    """
    ### BEFORE TESTS (setup)
    #retreive test conf
    #conf = import_conf('./conf.dev')
    #load test bigip
    #bigip = Bigip(conf.get('equipments')[0], conf.get('user'), conf.get('passwd'))
    bigip = infra.equipments[0]
    ### TESTS
    yield bigip
    ### AFTER TESTS  (teardown)
    bigip.sync()

