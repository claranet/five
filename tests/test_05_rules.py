import pytest

from tests.test_00_create_env import PREFIX
from five.utils import import_conf
from five.ltm import Rule

@pytest.fixture(scope='class')
def dummy_rules():
    raw_rules = import_conf('tests/test_rules.yaml')
    dummy_rules = [Rule(name='{}{}'.format(PREFIX, name), **data) for name, data in raw_rules.items()]
    assert dummy_rules
    yield dummy_rules

def test_create_rules(bigip, dummy_rules):
    for r in dummy_rules:
        with bigip.current_bigip(bigip.ref_bigip):
            bigip.create('Rule', **vars(r))
        assert bigip.ref_bigip.tm.ltm.rules.rule.load(name=r.name, partition=r.partition)

def test_compare_with_real(bigip, dummy_rules):
    for r in dummy_rules:
        with r.current_bigip(bigip.ref_bigip):
            assert not r.compare_with_real()
            r.wrong_attr = 'toto test'
            assert r.compare_with_real() == {'wrong_attr': ('toto test', None)}

#def test_patch():
#    pass
#
#def test_update():
#    pass
