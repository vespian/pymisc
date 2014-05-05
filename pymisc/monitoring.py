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
from pymisc.script import RecoverableException
import bernhard
import dns.resolver
import logging
import re
import socket

# Defaults:
DEFAULT_DATA_TTL = 25*60*60  # Data gathered by the script run should be valid
                             # for 25 hours.


class ScriptStatus(object):

    _STATES = {'ok': 0,
               'warn': 1,
               'critical': 2,
               'unknown': 3,
               }

    _status = 'ok'
    _message = ''
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
                             'of real sent call')

    @classmethod
    def _name2ip(cls, name):
        """
        Resolve a dns name.

        Args:
            name: fqdn or IP to resolve to.

        Returns:
            A string representation of the ip address.
        """
        if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', name):
            # already an IP entry:
            return name
        else:
            # Hostname, we need to resolve it:
            try:
                ipaddr = dns.resolver.query(name, 'A')
            except dns.resolver.NXDOMAIN:
                logging.error("A record for {0} was not found".format(name))
                return name  # Let somebody else worry about it ;)

            return ipaddr[0].to_text()

    @classmethod
    def _resolve_srv_hosts(cls, name):
        """
        Find Riemann servers by resolving SRV record.

        Method provides some sanity checks as well.

        Args:
            name: domain name which SRV record should be resolved

        Raises:
            RecoverableException - name argument is not a valid SRV record

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
            raise RecoverableException("Entry {0} ".format(name) +
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
        """
        entry = namedtuple("RiemannHost", ['host', 'port', 'proto'])
        try:
            a, b, c = name.split(":")
            entry.host = cls._name2ip(a)
            if entry.host is None:
                raise ValueError()
            entry.port = int(b)  # Raises ValueError by itself
            if c in ['tcp', 'udp']:
                entry.proto = c
            else:
                raise ValueError()
        except ValueError:
            logging.error("String {0} is not a valid ip:port:proto entry")
            return []

        logging.debug("String {0} resolved as {1}".format(name, str(entry)))
        return [entry]

    @classmethod
    def initialize(cls, use_riemann=False, riemann_hosts_config={},
                   riemann_tags=[], use_nrpe=False, debug=False):
        """
        Initialize the Status class.

        Few things are done in this class:
          * decide whether we data has to be sent to Riemann, passed to NRPE,
            or both.
          * if riemann is to be used - establish all the connections needed

        Args:
          use_riemann: if set to True, all the Riemann event sending logic is
                       enabled.
          use_nrpe: if set to True, script will output information in NRPE
                    friendly format as well.
          riemann_hosts_config: list of Riemann servers where events should be
                                sent. Its format is:
                                {
                                    "static": ["<IP>:<port>:<proto>", ...],
                                    "by_srv": ["srv_record_1", ...]
                                }
          riemann_tags: list of tags that events should be marked with
        """

        # FIXME:
        # - import riemann classes only if necessary
        # - move all riemann logic into separate class

        cls._riemann_tags = riemann_tags
        cls._hostname = socket.gethostname()
        cls._debug = debug
        cls._status = 'ok'
        cls._message = ''
        # FIXME - we should probably do some disconect here if we re-initialize
        # probably using conn.shutdown() call
        cls._riemann_connections = []

        if not riemann_tags:
            logging.error('there should be at least one Riemann tag defined.')
            return  # should it sys.exit or just return ??
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
                    logging.error("Unsupported transport {0}".format(riemann_host.proto) +
                                  ", not connected to {1}".format(riemann_host))
            except Exception as e:
                logging.exception("Failed to connect to Rieman host " +
                                  "{0}: {1}, ".format(riemann_host, str(e)) +
                                  "address has been exluded from the list.")
                continue

            logging.debug("Connected to Riemann instance {0}".format(riemann_host))
            cls._riemann_connections.append(riemann_connection)

        if not cls._riemann_connections:
            logging.error("There are no active connections to Riemann, " +
                          "metrics will not be send!")

    @classmethod
    def notify_immediate(cls, status, message):
        """
        Immediatelly sent provided data to the monitoring system.

        Data is sent without regard to the information already stored in
        the class.

        Args:
          status: status to sent
          message: justification/description of the status
        """
        if status not in cls._STATES:
            logging.error("Trying to issue an immediate notification" +
                          "with malformed status: " + status)
            return

        if not message:
            logging.error("Trying to issue an immediate" +
                          "notification without any message")
            return

        logging.warn("notify_immediate, " +
                     "status=<{0}>, ".format(status) +
                     "message=<{0}>".format(message)
                     )
        event = {
            'host': cls._hostname,
            'service': SERVICE_NAME,
            'state': status,
            'description': message,
            'tags': cls._riemann_tags,
            'ttl': DATA_TTL,
        }

        cls._send_data(event)

    @classmethod
    def notify_agregated(cls):
        """
        Sent gathered data to the monitoring system.
        """

        if cls._status == 'ok' and cls._message == '':
            cls._message = 'All certificates are OK'

        logging.debug("notify_agregated, " +
                      "status=<{0}>, message=<{1}>".format(
                          cls._status, cls._message))

        event = {
            'host': cls._hostname,
            'service': SERVICE_NAME,
            'state': cls._status,
            'description': cls._message,
            'tags': cls._riemann_tags,
            'ttl': DATA_TTL,
        }

        cls._send_data(event)

    @classmethod
    def update(cls, status, message):
        """
        Accumullate accumulate partial status/message.

        Args:
          status: status to sent
          message: justification/description of the status
        """
        if status not in cls._STATES:
            logging.error("Trying to do the status update" +
                          "with malformed status: " + status)
            return

        logging.info("updating script status, " +
                     "status=<{0}>, message=<{1}>".format(
                         status, message))
        if cls._STATES[cls._status] < cls._STATES[status]:
            cls._status = status
        # ^ we only escalate up...
        if message:
            if cls._message:
                cls._message += '\n'
            cls._message += message