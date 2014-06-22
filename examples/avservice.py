#! /usr/bin/env python

import amqpav

print('Starting AV service...')
receiver = amqpav.AVReceiver(
    # enter your URL
    amqp_url='amqp://guest:guest@prophet/antivir')

print('Done.')
receiver.run()
