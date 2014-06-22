#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# avlibclient.py
#
# Anti-virus client example
#

import time
import amqpav


def print_result(info):
    
    print('Is clean: {}'.format(info))


def main():
    
    print('AV Client')
    print('-' * 9)

    avc = amqpav.AVClient()
    print('# Normal call')
    msg_id = avc.check_file('eicar')
    print('msg ID: {}'.format(msg_id))
    result = avc.get_result(msg_id)
    print('Is clean: {}'.format(result))
    print('')

    # async client
    print('# Async call')
    msg_id = avc.check_file('avclient.py')
    print('msg ID: {}'.format(msg_id))
    avc.get_result_async(msg_id, print_result)
    # wait max 10 seconds
    time.sleep(10)


if __name__ == '__main__':

    main()
