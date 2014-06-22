#! /usr/bin/env python

import pyclamd

print('pyclamd version: {}'.format(pyclamd.__version__))

pyclamd.init_unix_socket('/var/run/clamav/clamd.ctl')
if pyclamd.ping():
    print('Connection to Unix socket established.')
    print('ClamAV version: {}'.format(pyclamd.version()))

# test scan
result = pyclamd.scan_stream(pyclamd.EICAR)
print('Scan result: {}'.format(result))
