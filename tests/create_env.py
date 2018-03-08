#coding: utf-8
import time
from five.bigip import Bigip
from five.utils import import_conf
from five.resources import Partition
from five.net import *
from five.ltm import *
from five import log

PREFIX = '__Test_Five_'

def create_partition(device, partition):
    #create partition (synced)
    log.info('{}: CREATE PARTITION {}'.format(device, partition))
    with device.current_bigip(device.ref_bigip):
        device.create('Partition', name=partition)
        device.sync()

def create_vlans(device, partition, d_map):
    """ create vlans (not synced) """
    vlans = {'{}{}'.format(PREFIX, vlan):data.get('id') for _, rd in d_map.get('route_domains').items() for vlan, data in rd.get('vlans').items()}
    for name, tag in vlans.items():
        with device.current_bigip(device.ref_bigip):
            device.create('Vlan', name=name, partition=partition, tag=tag)
            log.info('{}: CREATE VLAN {}'.format(device, name))

def create_route_domains(device, partition, d_map):
    for name, data in d_map.get('route_domains').items():
        log.info('{} CREATE RD : {}'.format(device, name))
        vlans = ['{}{}'.format(PREFIX, name) for name, id in data.get('vlans').items()]
        with device.current_bigip(device.ref_bigip):
            device.create('Route_Domain', name='{}{}'.format(PREFIX, name), id=data.get('id'), partition=partition, vlans=vlans)
        # set default rd if needed
        if data.get('default_rd'):
            log.verbose('{} : default_rd set for {}'.format(device, name))
            success, part = device.get(name=partition)
            log.verbose('{} : get resource : {}, {}'.format(device, success, part))
            if success:
                with part.current_bigip(device.ref_bigip):
                    part.set_default_route_domain(data.get('id'))
                    log.info('{} : partition {} : set default RD {}'.format(device, partition, name))

def format_selfip(partition, rd_id, vlan, address, trafficgroup='traffic-group-local-only'):
    sip = {'name':'{}{}'.format(PREFIX, address.replace('/', '_').replace(':','-')),
            'partition':partition,
            'vlan':'{}{}'.format(PREFIX, vlan),
            'trafficGroup':trafficgroup,
            'route_domain':rd_id,
            'address': '{}%{}/{}'.format(address.split('/')[0], rd_id, address.split('/')[1])}
    return sip

def format_selfips(partition, d_map):
    selfips = dict()
    for rd, data in d_map.get('route_domains').items():
        rd_id = data.get('id')
        for vlan, data in data.get('vlans').items():
            for unit, address in data.get('selfips').items():
                if not unit in selfips:
                    selfips.update({unit: list()})
                sip = format_selfip(partition, rd_id, vlan, address)
                if unit == 'vip':
                    sip.update({'trafficGroup':'traffic-group-1'})
                selfips[unit].append(sip)
    return selfips

def create_selfips(device, selfips):
    for sip in selfips:
        with device.current_bigip(device.ref_bigip):
            log.info('{} CREATE SELFIP {}'.format(device, sip))
            device.create('SelfIP', **sip)

def create_environment(bigip, partition, d_map):
    """
    Create Full environnment on Bigip Cluster from a dictionnary
    TODO : factorize
    """
    ## create cluster list
    cluster_devices = bigip.real_peers[:]
    cluster_devices.append(bigip)       ## we add the device itself at the end of the list
    log.info('CREATE ENVIRONNEMENT : {}'.format(partition))
    log.verbose('{} : {}'.format(partition, d_map))

    partition = PREFIX+partition
    #synced
    create_partition(bigip, partition)

    # not synced
    for device in cluster_devices:
        create_vlans(device, partition, d_map)
        create_route_domains(device, partition, d_map)
    bigip.sync()

    #create SelfIP local-only firts
    ## Master (as 0: in vlans: selfips)
    selfips = format_selfips(partition, d_map)
    create_selfips(bigip, selfips[0])
    ## Slave (as 1)
    create_selfips(cluster_devices[0], selfips[1])
    ## VIP
    create_selfips(bigip, selfips['vip'])
    bigip.sync()

def create_environments(bigip, conf_path):
    test_env = import_conf(conf_path)
    for partition, data in test_env.get('partitions').items():
        create_environment(bigip, partition, data)
    bigip.retreive_contexts()

if __name__ == '__main__':
    conf = import_conf('conf.dev')
    bigip = Bigip(conf.get('equipments')[0], conf.get('user'), conf.get('passwd'))
    create_environments(bigip, './tests/test_env.yaml')
