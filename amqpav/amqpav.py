# -*- coding: utf-8 -*-

'''Module for antivirus control over AMQP.'''

from __future__ import unicode_literals
from __future__ import print_function

# ClamAV binding
import pyclamd

# AMQP framework
from kombu import Connection
from kombu import Exchange
from kombu import Queue

import json
import base64
import uuid
import datetime

from multiprocessing import Pool
import time
import socket
import pprint


############################################
stop = False
message_id = ''
result = True


def process_reply(body, message):
    
    response = AVMessageResponse()
    response.load(message)

    correlation_id = response.correlation_id

    if (message_id == correlation_id):
        
        # found our message
        message.ack()
        global stop
        stop = True

        if response.msg_type == 'response-error':

            # prepare error message data
            emsg = response.error_msg
            data = emsg.split(':', 1)

            if len(data) == 2:

                emsg_type = data[0]

            else:

                emsg_type = 'unknown'

            # check error message type
            if emsg_type == 'bad app-id':

                raise BadExchangeException(emsg)

            elif emsg_type == 'unknown protocol':

                raise InvalidMessageException(emsg)

            elif emsg_type == 'unknown':

                raise InvalidMessageException(emsg)

        else:

            global result
            result = response.is_clean
            #print(response.headers())


def get_av_result(
        msg_id,
        avex,
        host):
    '''Return check result for message ID.'''
    
    time.sleep(3)

    global stop
    stop = False
    global message_id
    message_id = msg_id

    rq = Queue('client1', exchange=avex)
    with Connection(host) as conn:
        with conn.Consumer(
                rq, callbacks=[process_reply], no_ack=False) as consumer:

            while not stop:

                try:
                    
                    conn.drain_events(timeout=5)

                except socket.timeout:
                    
                    print('Socket timeout')
                    consumer.recover()

    return result
############################################################


class BadExchangeException(Exception):
    pass


class InvalidMessageException(Exception):
    pass


class AVClient:
    '''AV AMQP client.
    
    Args:
        amqp_host (str): AMQP broker URL
        client_id (str): Client identification
    '''
    
    def __init__(
            self,
            amqp_host='amqp://localhost/antivir',
            client_id=None):
        '''Create client.'''

        self.av_exchange = Exchange(
            'check', 'fanout', durable=True)
        self.reply_exchange = Exchange(
            'check-result', 'fanout', durable=True)
        self.amqp_host = amqp_host
        
        if client_id:

            self.client_id = client_id

        else:

            self.client_id = self.gen_client_id()

        self.login = None
        self.password = None

        self.load_config('avclient.cfg')

    def login(self, username, password):
        '''External settings for credentials.
        
        Args:
            username (str): AMQP user
            password (str): AMQP password
        '''

        self.login = username
        self.password = password

    def client_id(self):
        '''Return client ID.
        
        Return:
            str: Client identification
        '''

        return self.client_id

    def gen_client_id(self):
        '''Generate client ID and return it.
        
        Return:
            str: Generated client identification'''

        # fake gen
        return 'client1'

    def get_result(self, msg_id):
        '''Synchronous method for getting result.

        Args:
            msg_id (str): Message UUID
        
        Return:
            bool: Clean flag - True means file is clean
        '''

        if msg_id is None:

            raise TypeError('msg_id cannot be None')

        time.sleep(3)
        result = get_av_result(
            msg_id,
            self.reply_exchange,
            self.amqp_host)

        return result

    def get_result_async(self, msg_id, callback):
        '''Asynchronous version for getting result.
        
        Args:
            msg_id (str): Message UUID
            callback (func): Callback function
        '''

        pool = Pool()
        pool.apply_async(
            get_av_result,
            args=(
                msg_id,
                self.reply_exchange,
                self.amqp_host,),
            callback=callback
        )
        pool.close()

    def result_func(self, msg_id, function):
        '''Register callback function.'''
        pass

    def submit_request(self, request):
        '''Submit request and return message ID.
        
        Args:
            request (str): Binary data

        Return:
            str: Message UUID'''
        
        with Connection(self.amqp_host) as conn:
            
            conn.connect()
            producer = conn.Producer()

            # create result queue - if not exists
            resultq = Queue(
                self.client_id,
                exchange=self.reply_exchange,
            )
            resultq(conn.channel()).declare()

            message_id = str(uuid.uuid4())

            bin_data = request
            message = AVMessageRequest(
                msg_id=message_id,
                created=str(datetime.datetime.now()),
                content_type='application/octet-stream',
                data=bin_data,
            )

            # generate headers
            headers = message.headers()

            # send message
            producer.publish(
                message.body(),
                exchange=self.av_exchange,
                headers=headers,
                **message.properties()
            )

            print('Message sent.')

        return message_id

    def check_file(self, filename):
        '''Send file for control and return message ID.
        
        Args:
            filename (str): Filename
        
        Return:
            str: Message UUID
        '''

        data = None
        try:

            data = open(filename, 'rb').read()

        except IOError as e:
            
            print('File not found')

        msg_id = None
        if data is not None:

            msg_id = self.submit_request(data)

        return msg_id

    def load_config(self, filename):
        '''Load configuration from file.'''
        pass


class AVServer:
    '''AV AMQP server.'''
    
    def __init__(self, amqp_url='amqp://localhost/antivir'):
        
        self.receiver = AVReceiver(amqp_url)

    def run(self):
        
        try:

            self.receiver.run()

        except pyclamd.ScanError as e:
            
            print('Pyclamd problem: {}'.format(e))
            print('Is ClamAV daemon running?')

        except socket.error as e:
            
            print('Connection problem: {}'.format(e))
            print('Is RabbitMQ running?')

        except Exception as e:
            
            print(type(e))


class AVControl:

    def __init__(
            self,
            socket='/var/run/clamav/clamd.ctl'):

        pyclamd.init_unix_socket(socket)

    def check_stream(self, data):
        
        result = pyclamd.scan_stream(data)

        return result


class Headers(object):
    '''Headers mapper.'''
    
    def __init__(
            self,
            created='created',
            protocol='protocol',
            error_msg='errorMsg',
            is_clean='isClean'):

        # create time
        self.created = created
        # protocol version
        self.protocol = protocol
        # error message
        self.error_msg = error_msg
        # clean status flag
        self.is_clean = is_clean

    def load_from_file(self, filename):
        '''Load mapping from file.'''

        pass


class AVMessage(object):
    '''Base class for antivirus messages.'''

    def __init__(
            self,
            msg_id='',
            msg_type='request',
            created='',
            # default protocol version
            protocol='1',
            reply_to='',
            content_type='',
            content_encoding='',
            correlation_id='',
            delivery_mode='',
            data=''):
        
        self.app_id = 'antivirus'

        # message UUID
        self.msg_id = msg_id
        # message type
        self.msg_type = msg_type
        # create time
        self.created = created
        # protocol version
        self.protocol = protocol
        # callback queue
        self.reply_to = reply_to
        # body content type
        self.content_type = content_type
        # body content encoding
        self.content_encoding = content_encoding
        # correlation ID
        self.correlation_id = correlation_id
        # delivery mode
        self.delivery_mode = delivery_mode
        # timestamp
        self.timestamp = datetime.datetime.now()
        
        # data from message body
        self.data = data

        # headers mapper
        self.hdrs = Headers()

    def load(self, message):
        '''Load all data.'''

        self.load_headers(message)
        self.load_properties(message)
        self.load_body(message)

    def load_properties(self, message):
        '''Load message properties.'''

        self.app_id = message.properties.get('app_id', '')
        self.content_type = message.properties.get('content_type', '')
        self.content_encoding = message.properties.get(
            'content_encoding', '')
        self.delivery_mode = message.properties.get('delivery_mode', '')
        self.msg_id = message.properties.get('message_id', '')
        self.msg_type = message.properties.get('type', '')
        self.correlation_id = message.properties.get('correlation_id', '')

    def load_headers(self, message):
        '''Load message headers.'''

        self.created = message.headers.get(self.hdrs.created, '')
        self.protocol = message.headers.get(self.hdrs.protocol, '')

    def load_body(self, message):
        '''Load message body.'''

        if self.content_type == 'application/octet-stream':

            self.data = message.body

    def body(self):
        
        if self.content_type == 'application/octet-stream':

            return self.data

    def load_JSON(self, json_str):
        '''Load message data from JSON.'''
        
        self.data = json.loads(json_str)

    def properties(self):
        
        msg_properties = {
            'content_type': self.content_type,
            'content_encoding': self.content_encoding,
            #'delivery_mode': self.delivery_mode,
            'message_id': self.msg_id,
            'type': self.msg_type,
            'correlation_id': self.correlation_id,
            'timestamp': self.timestamp,
            'app_id': self.app_id,
        }

        return msg_properties

    def headers(self):
        '''Return message headers.'''
        
        msg_headers = {
            self.hdrs.created: self.created,
            self.hdrs.protocol: self.protocol,
        }

        return msg_headers

    def __str__(self):
        
        return 'AV Message: {}'.format(self.msg_id)


class AVMessageRequest(AVMessage):
    pass


class AVErrorMessage(AVMessage):
    '''Error message class.'''

    def __init__(
            self,
            msg_id='',
            correlation_id='',
            created='',
            data=''):
        super(AVErrorMessage, self).__init__(
            msg_id=msg_id,
            msg_type='error',
            correlation_id=correlation_id,
            created=created,
            data=data)
 

class AVMessageResponse(AVMessage):
    '''Class for antivirus response messages.'''
    
    def __init__(
            self,
            msg_id='',
            msg_type='response',
            correlation_id='',
            created='',
            data='',
            is_clean=False,
            include_data=False,
            error_msg=''):
        super(AVMessageResponse, self).__init__(
            msg_id=msg_id,
            msg_type=msg_type,
            correlation_id=correlation_id,
            created=created,
            data=data)
        
        # clean status flag
        self.is_clean = is_clean
        # use of message body flag
        self.include_data = include_data
        # error info message
        self.error_msg = error_msg

    def load_headers(self, message):
        '''Load message headers.'''

        super(AVMessageResponse, self).load_headers(message)

        self.is_clean = bool(message.headers.get(self.hdrs.is_clean, ''))
        self.error_msg = message.headers.get(self.hdrs.error_msg, '')

    def properties(self):
        
        data = super(AVMessageResponse, self).properties()

        return data

    def headers(self):
        
        data = super(AVMessageResponse, self).headers()

        data[self.hdrs.is_clean] = self.is_clean
        data[self.hdrs.error_msg] = self.error_msg

        return data


class AVErrorMessageResponse(AVMessageResponse):
    '''Class for antivirus error response messages.'''
    
    def __init__(
            self,
            msg_id='',
            correlation_id='',
            created='',
            data='',
            include_data=False,
            error_msg='Error'):
        super(AVErrorMessageResponse, self).__init__(
            msg_id=msg_id,
            msg_type='response-error',
            correlation_id=correlation_id,
            created=created,
            data=data,
            error_msg=error_msg)


class AVReceiver:
    '''Class for receiving antivirus messages.'''
    
    def __init__(
            self,
            mtype='JSON',
            amqp_url='amqp://guest:guest@localhost/antivir',
            inex_name='check',
            outex_name='check-result'):

        # message type
        self.mtype = mtype

        self.amqp_url = amqp_url

        # input exchange for receiving
        self.inex = Exchange(inex_name, 'fanout', durable=True)
        # output exchange for sending back
        self.outex = Exchange(outex_name, 'fanout', durable=True)
        # queue for incoming messages
        self.avq = Queue(
            'clamav-check',
            exchange=self.inex)

    def process_message(self, body, message):
        '''Process message, send data to antivirus and send response.'''
        
        msg = AVMessage()
        msg.load(message)

        print(' * Message received')
        print('Message: {}'.format(msg))
        print('Headers:')
        pprint.pprint(message.headers, indent=4)
        print('Properties:')
        pprint.pprint(message.properties, indent=4)

        print('Protocol version: {}'.format(msg.protocol))
        try:

            protocol_version = int(msg.protocol)

        except ValueError:
            
            protocol_version = 0

        # check protocol version
        if not (protocol_version >= 1 and protocol_version <= 1):

            self.error_reply(msg, 'unknown protocol: {}'.format(msg.protocol))

        # check application ID
        elif msg.app_id != 'antivirus':

            self.error_reply(msg, 'bad app-id: {}'.format(msg.app_id))

        else:

            ### AV check
            data = msg.data
            result = self.av_check(data)

            print('AV result: {}'.format(result))

            if not result:
                clean = True
            else:
                clean = False

            self.reply(msg, clean)
            
        message.ack()

    def av_check(self, data):
        '''Antivirus control.'''
        
        av = AVControl()
        status = av.check_stream(data)

        return status

    def reply(self, parent_msg, status):
        '''Reply to sender queue.'''

        now = datetime.datetime.now().isoformat()

        msg = AVMessageResponse(
            msg_id=str(uuid.uuid4()),
            correlation_id=parent_msg.msg_id,
            created=now,
            data=parent_msg.data,
            is_clean=status
        )

        with Connection(self.amqp_url) as conn:
            producer = conn.Producer()

            producer.publish(
                msg.body(),
                headers=msg.headers(),
                exchange=self.outex,
                **msg.properties()
            )

    def error_reply(self, parent_msg, error_info):
        '''Send error message to sender queue.'''

        now = datetime.datetime.now().isoformat()

        msg = AVErrorMessageResponse(
            msg_id=str(uuid.uuid4()),
            correlation_id=parent_msg.msg_id,
            created=now,
            data=parent_msg.data,
            error_msg=error_info
        )

        with Connection(self.amqp_url) as conn:
            producer = conn.Producer()

            producer.publish(
                msg.body(),
                headers=msg.headers(),
                exchange=self.outex,
                **msg.properties()
            )

    def run(self):
        
        with Connection(self.amqp_url) as conn:
            
            with conn.Consumer(
                    self.avq,
                    callbacks=[self.process_message]) as consumer:

                while True:

                    conn.drain_events()
