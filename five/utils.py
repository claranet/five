#coding: utf-8
import yaml
import base64

def import_conf(conf_path):
    try:
        with open(conf_path) as f:
            conf = yaml.load(f)
    except IOError:
        raise IOError('you have to define a configuration file eg: ./conf.yml, please documentation')
    return conf

def save_file_from_base64(data, path):
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'=' * (4 - missing_padding)
    with open(path, 'w') as f:
        f.write(base64.decodebytes(data).decode())
