#! /usr/bin/env python

import amqpav

from kombu import Connection
from kombu import Exchange
from kombu import Queue

import uuid
import datetime
import base64
import socket

import time
import random

# AV exchanges
av_exchange = Exchange('check', 'fanout', durable=True)
reply_exchange = Exchange('check-result', 'fanout', durable=True)
# client ID
client_id = 'test-1'

msg_id = ''

# connection to AV service
with Connection('amqp://guest:guest@prophet/antivir') as conn:

    conn.connect()
    producer = conn.Producer()

    # create result queue
    resultq = Queue(
        client_id,
        exchange=reply_exchange,
    )
    resultq(conn.channel()).declare()

    # file for AV check
    # eicar - EICAR test file for example
    bin_data = open('eicar', 'rb').read()

    # create message
    #
    # generate message ID
    msg_id = str(uuid.uuid4())
    # generate correlation ID
    cor_id = str(uuid.uuid4())
    message = amqpav.AVMessageRequest(
        msg_id=msg_id,
        correlation_id=cor_id,
        created=str(datetime.datetime.now()),
        interface='something',
        content_type='application/octet-stream',
        data=bin_data,
    )
    headers = message.headers()

    # send message
    producer.publish(
        message.body(),
        exchange=av_exchange,
        headers=headers,
        **message.properties()
    )

    print(' + Message sent')
    print('Headers: {}'.format(headers))
    print('Properties: {}'.format(message.properties()))

    # sleep random time
    time.sleep(random.randint(1, 8))
 

# stop flag
stop = False


# process reply
def p_reply(body, message):
    
    response = amqpav.AVMessageResponse()
    response.load(message)

    print(' * Message received')
    print('Response headers: {}'.format(response.headers()))
    print('Response properties: {}'.format(response.properties()))

    # get message's parent UUID
    cid = response.correlation_id

    if (msg_id == cid):

        message.ack()
        print('=== Message received.')

        global stop
        stop = True

    else:

        print('=== Message skipped.')

# wait for response
rq = Queue(client_id, exchange=reply_exchange)

# change URL for your server
with Connection('amqp://guest:guest@prophet/antivir') as conn:
    with conn.Consumer(rq, callbacks=[p_reply], no_ack=False) as consumer:
        while not stop:

            try:

                conn.drain_events(timeout=5)

            except socket.timeout:
                
                print('timeout')
                consumer.recover()
