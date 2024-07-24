# nuki-py

![GitHub License](https://img.shields.io/github/license/Kanksu/nuki-py)


## A python library to operate Nuki smart lock

You must have a registered digital key to operate the nuki smart lock.
Before you can operate a Nuki Smart Lock, the key must be generated and
registered in the smart lock (pair).

Press the button on the Nuki smart lock for 5 seconds, the smart lock will
go into pairing mode. Only in pairing mode, the key can be registered.

The pairing prcoess is described in Nuki API document:
https://developer.nuki.io/page/nuki-smart-lock-api-2/2

The generated credentials must be stored in the computer,
so that it can be used in the future to operate the smart lock.

By default, the credentials will be stored with a file name `secrets.json`.
The file name can be changed, see:
```bash
python nuki.py --help
```


### Pair
```bash
python nuki.py auth
```

### Operation
```bash
python nuki.py unlock
python nuki.py unlatch
python nuki.py lock
```

### Get status
```bash
python nuki.py status
```
