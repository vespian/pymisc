#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2014 Pawel Rozlach
# Copyright (c) 2013 Spotify AB
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.


# Make it a bit more like python3 (if we are not already working under it):
from __future__ import division
from __future__ import nested_scopes
from __future__ import print_function
from __future__ import with_statement

# Imports:
from collections import namedtuple
from pyother.script import FatalException
from pyother.script import RecoverableException
try:
    import bernhard
    import dns.resolver
except ImportError:
    pass
import logging
import re
import sys
import socket


class ScriptStatus(object):

    _STATES = {'ok': 0,
               'warn': 1,
               'critical': 2,
               'unknown': 3,
               }

    _status = 'ok'
    _message = ''
    _message_aux = ''  # Used to filter out OK messages in case there are
                       # CRIT/WARN ones.
    _nrpe_enabled = False
    _riemann_enabled = False
    _riemann_connections = []
    _riemann_tags = None
    _hostname = ''
    _debug = None

    @classmethod
    def _send_data(cls, event):
        """
        Sends script status to all Riemann servers.

        Args:
            event: event to sent
        """
        for riemann_connection in cls._riemann_connections:
            logging.info('Sending event {0}, '.format(str(event)) +
                         'using Riemann conn {0}:{1}'.format(
                             riemann_connection.host, riemann_connection.port)
                         )
            if not cls._debug:
                try:
                    riemann_connection.send(event)
                except Exception as e:
                    logging.exception("Failed to send event to Rieman host: " +
                                      "{0}".format(str(e))
                                      )
                    continue
                else:
                    logging.info("Event sent succesfully")
            else:
                logging.info('Debug flag set, I am performing no-op instead '
                             'of real sending of call')

    @classmethod
    def _name2ip(cls, name):
        """
        Resolve a dns name.

        Args:
            name: fqdn or IP to resolve to.

        Returns:
            A string representation of the ip address.

        Raises:
            RecoverableException - DNS record was not found

        """
        if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', name):
            # already an IP entry:
            return name
        else:
            # Hostname, we need to resolve it:
            try:
                ipaddr = dns.resolver.query(name, 'A')
            except dns.resolver.NXDOMAIN:
                raise RecoverableException("A DNS record for " +
                                           "{0} was not found".format(name))

            return ipaddr[0].to_text()

    @classmethod
    def _resolve_srv_hosts(cls, name):
        """
        Find Riemann servers by resolving SRV record.

        Method provides some sanity checks as well.

        Args:
            name: domain name which SRV record should be resolved

        Raises:
            FatalException - name argument is not a valid SRV record

        Returns:
            A list of named tuples "RiemannHost", each one  holding information
            about one Rieman instance. Meaning of the tuple fields is as
            follows:
                (<host>, <port>, <protocol>)

            where:
                <protocol> is either tcp or udp,
                <host> is an IP address in format of a string,
                <port> port, as an integer.

        """
        result = []
        logging.debug("Resolving " + name)
        if name.find('._udp') > 0:
            proto = 'udp'
        elif name.find('._tcp') > 0:
            proto = 'tcp'
        else:
            raise FatalException("Entry {0} ".format(name) +
                                 "is not a valid SRV name")

        try:
            resolved = dns.resolver.query(name, 'SRV')
        except dns.resolver.NXDOMAIN:
            logging.error("Entry {0} does not exist, skipping.")
            return []

        for rdata in resolved:
            entry = namedtuple("RiemannHost", ['host', 'port', 'proto'])
            entry.host = cls._name2ip(rdata.target.to_text())
            if entry.host is None:
                continue
            entry.port = rdata.port
            entry.proto = proto
            result.append(entry)
            logging.debug("String {0} resolved as {1}".format(name, str(entry)))

        return result

    @classmethod
    def _resolve_static_entry(cls, name):
        """
        Find Riemann servers by resolving plain A record.

        Method provides some sanity checks as well.

        Args:
            name: domain name which should be resolved

        Returns:
            A list of named tuples "RiemannHost", each one  holding information
            about one Rieman instance. Meaning of the tuple fields is as
            follows:
                (<host>, <port>, <protocol>)

            where:
                <protocol> is either tcp or udp,
                <host> is an IP address in format of a string,
                <port> port, as an integer.

        Raises:
            FatalException - name argument is invalid

        """
        entry = namedtuple("RiemannHost", ['host', 'port', 'proto'])
        try:
            a, b, c = name.split(":")
            entry.host = cls._name2ip(a)
            if entry.host is None:
                raise ValueError()
            entry.port = int(b)  # Raises ValueError by itself
            entry.proto = c
        except ValueError:
            raise FatalException(
                "String {0} is not a valid ip:port:proto entry".format(name))

        logging.debug("String {0} resolved as {1}".format(name, str(entry)))
        return [entry]

    @classmethod
    def initialize(cls,
                   riemann_enabled=False,
                   riemann_hosts_config=None,
                   riemann_tags=None,
                   riemann_service_name=None,
                   riemann_ttl=None,
                   nrpe_enabled=False,
                   debug=False):
        """
        Initialize the Status class.

        Few things are done in this method:
          * decide whether we data has to be sent to Riemann, passed to NRPE,
            or both.
          * if riemann is to be used - establish all the connections needed

        Args:
          riemann_enabled: if set to True, all the Riemann event sending logic is
                   enabled.
          riemann_hosts_config: list of Riemann servers where events should be
                                sent. Its format is:
                                {
                                    "static": ["<IP>:<port>:<proto>", ...],
                                    "by_srv": ["srv_record_1", ...]
                                }
          riemann_tags: list of tags that events should be marked with
          riemann_service_name: service name to pass in event
          riemann_ttl: TTL to ser for events
          nrpe_enabled: if set to True, script will output information in NRPE
                    friendly format as well.

        Raises:
            FatalException - it is impossible to send notifications to monitoring
                             system. Either call syntax is invalid or there is
                             other error that prohibits normal operation. See
                             exception message for details.
            RecoverableException - error is not fata, call may repeated.

        """

        cls._debug = debug
        cls._status = 'ok'
        cls._message = ''
        cls._message_aux = ''
        cls._riemann_enabled = riemann_enabled
        cls._nrpe_enabled = nrpe_enabled

        # FIXME:
        # - move all riemann logic into separate class
        # - Import riemann classes only if necessary, some of the people
        #   will be using nrpe only.

        if not cls._riemann_enabled and not cls._nrpe_enabled:
            raise FatalException("At least one of Riemann or NRPE " +
                                 "functionalitiy should be enabled.")

        if cls._riemann_enabled:

            if riemann_tags is None or len(riemann_tags) < 1:
                raise FatalException('There must be at least one Riemann tag defined.')
            else:
                cls._riemann_tags = riemann_tags

            if not riemann_service_name:
                raise FatalException('Riemann service name must be defined.')
            else:
                cls._riemann_service_name = riemann_service_name

            if not riemann_ttl or riemann_ttl < 1:
                raise FatalException('Riemann event TTL must be defined and >1.')
            else:
                cls._riemann_ttl = riemann_ttl

            if not riemann_hosts_config:
                raise FatalException('There are no Rieman servers configured.')

            cls._hostname = socket.gethostname()

            # FIXME - we should probably do some disconect here if we re-initialize
            # probably using conn.shutdown() call
            cls._riemann_connections = []

            tmp = []
            if "static" in riemann_hosts_config:
                for line in riemann_hosts_config["static"]:
                    tmp.extend(cls._resolve_static_entry(line))

            if "by_srv" in riemann_hosts_config:
                for line in riemann_hosts_config["by_srv"]:
                    tmp.extend(cls._resolve_srv_hosts(line))

            for riemann_host in tmp:
                try:
                    if riemann_host.proto == 'tcp':
                        riemann_connection = bernhard.Client(riemann_host.host,
                                                             riemann_host.port,
                                                             bernhard.TCPTransport)
                    elif riemann_host.proto == 'udp':
                        riemann_connection = bernhard.Client(riemann_host.host,
                                                             riemann_host.port,
                                                             bernhard.UDPTransport)
                    else:
                        raise FatalException("Unsupported transport " +
                                             "{0}".format(riemann_host.proto) +
                                             ", not connected to {0}".format(riemann_host))
                except bernhard.TransportError as e:
                    logging.error("Failed to connect to Rieman host " +
                                  "{0}: {1}, ".format(riemann_host, str(e)) +
                                  "address has been exluded from the list.")
                else:
                    logging.debug("Connected to Riemann instance {0}".format(riemann_host))
                    cls._riemann_connections.append(riemann_connection)

            if not cls._riemann_connections:
                raise FatalException("There are no active connections to Riemann, " +
                                     "metrics will not be send!")

    @classmethod
    def notify_immediate(cls, status, message):
        """
        Immediatelly sent provided data to the monitoring system.

        Data is sent without regard to the information already stored in
        the class.

        Args:
          status: status to sent
          message: justification/description of the status, at least 3 chars
        """
        if status not in cls._STATES:
            raise FatalException("Trying to issue an immediate notification" +
                                 "with malformed status: " + status)

        if not message or len(message) < 3:
            raise FatalException("Trying to issue an immediate" +
                                 "notification without any message")

        logging.warn("notify_immediate, " +
                     "status=<{0}>, ".format(status) +
                     "message=<{0}>".format(message)
                     )
        if cls._riemann_enabled:
            event = {
                'host': cls._hostname,
                'service': cls._riemann_service_name,
                'state': status,
                'description': message,
                'tags': cls._riemann_tags,
                'ttl': cls._riemann_ttl,
            }

            cls._send_data(event)

        if cls._nrpe_enabled:
            print(message)
            sys.exit(cls._STATES[status])

    @classmethod
    def notify_agregated(cls):
        """
        Sent gathered data to the monitoring system.
        """

        if cls._status == 'ok':
            if not cls._message_aux:
                msg = "All OK"
            else:
                msg = cls._message_aux
        else:
            msg = cls._message

        logging.debug("notify_agregated, " +
                      "status=<{0}>, message=<{1}>".format(
                          cls._status, msg))

        if cls._riemann_enabled:
            event = {
                'host': cls._hostname,
                'service': cls._riemann_service_name,
                'state': cls._status,
                'description': msg,
                'tags': cls._riemann_tags,
                'ttl': cls._riemann_ttl,
            }
            cls._send_data(event)

        if cls._nrpe_enabled:
            print(msg)
            sys.exit(cls._STATES[cls._status])

    @classmethod
    def update(cls, status, message):
        """
        Accumullate accumulate partial status/message.

        Args:
          status: status to sent
          message: justification/description of the status
        """
        if status not in cls._STATES:
            raise FatalException("Trying to do the status update" +
                                 "with malformed status: " + status)

        if not message or len(message) < 3:
            raise FatalException("Trying to issue an update" +
                                 "notification without any message")

        logging.info("updating script status, " +
                     "status=<{0}>, message=<{1}>".format(
                         status, message))
        # We only escalate up...
        if cls._STATES[cls._status] < cls._STATES[status]:
            cls._status = status
        if cls._STATES['ok'] < cls._STATES[status]:
            if cls._message:
                cls._message += ' '
            cls._message += message
        else:
            if cls._message_aux:
                cls._message_aux += ' '
            cls._message_aux += message
