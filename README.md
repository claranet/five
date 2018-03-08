Five
=====

Simple lib based on f5-sdk used to manipulate one or multiple BigIP.
Use at your own risk. Work in progress.

requirement:

  - >= python3.5
  - pip install requests
  - pip install pyyaml
  - pip install pytest
  - pip install apscheduler
  - pip install f5-sdk

Start
======

with Bigip
-----------

```
from five.bigip import Bigip

bigip = Bigip(hostname, user, passwd)
```

with all Infra
---------------

```
from five.infra import Infra
from five.utils import import_conf

conf = import_conf('./some_path_to_the_conf_file.yml')
infra = Infra(conf)
```

please read conf.sample to see how to fill it.
