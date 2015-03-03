## AMQP anti-virus module

Python module which offers an anti-virus client and a server communicating over AMQP. Message broker is RabbitMQ.

## Prerequisities

#### Debian Wheezy
ClamAV server.
```
# apt-get install clamav
```
Start server:
```
# /etc/init.d/clamav-daemon start
```

Python ClamAV library.
```
# apt-get install python-pyclamd
```

RabbitMQ server.
```
# apt-get install rabbitmq-server
```
Start server:
```
# /etc/init.d/rabbitmq-server start
```

## Devel run
You can run server example from repository root with *runserver.sh* script.
```
$ ./runserver.sh
AV Service
----------
Listening...

```
