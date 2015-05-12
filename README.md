# BitForge
A pure and powerful python bitcoin library


## Development

First, get the code:
```
git clone git@github.com:muun/bitforge.git; cd bitforge;
```

Then, create a new virtualenv for this project:
```
sudo pip install virtualenv
virtualenv env
```

Activate virtualenv:
```
source env/bin/activate
```

Then, install bitforge's dependencies:
```
pip install -r requirements.txt
```

Run the tests to make sure everything is working:
```
py.test tests/*
```

should output something similar to:
```
$ py.test tests/*
================================= test session starts =================================
platform linux2 -- Python 2.7.6 -- py-1.4.27 -- pytest-2.7.0
rootdir: /path/to/bitforge, inifile:
collected 69 items

tests/address.py ............
tests/privkey.py ....................
tests/pubkey.py ..............
tests/script.py .....
tests/unit.py ...
tests/uri.py ...............

============================== 69 passed in 0.47 seconds ==============================
```

