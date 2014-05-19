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


# Make it a bit more like python3:
from __future__ import absolute_import
from __future__ import division
from __future__ import nested_scopes
from __future__ import print_function
from __future__ import with_statement

# Global imports:
try:
    import bernhard
except ImportError:
    print("\nbernhard module is not present, some of the tests will be disabled\n")
    skip_Riemann = True
else:
    skip_Riemann = False
import dns.resolver
import mock
import os
import platform
import sys
major, minor, micro, releaselevel, serial = sys.version_info
if major == 2 and minor < 7:
    # Not shure if it will work with <2.7, but still - somebody may find it
    # usefull
    import unittest2 as unittest
else:
    import unittest

if major == 3:
    builtins_path = "builtins.print"
else:
    builtins_path = "__builtin__.print"

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
from pymisc.monitoring import FatalException
from pymisc.monitoring import RecoverableException
import pymisc.monitoring


@mock.patch('logging.warn')
@mock.patch('logging.info')
@mock.patch('logging.error')
class TestPymiscMonitoring(unittest.TestCase):
    @mock.patch('pymisc.monitoring.bernhard')
    @unittest.skipIf(skip_Riemann, "In order to test Riemann functionality " +
                     "bernhard module must be installed")
    def test_riemann_syntax_checking(self, RiemannMock, LoggingErrorMock,
                                     LoggingInfoMock, LoggingWarnMock):

        # There should be at least one tag defined:
        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.initialize(riemann_enabled=True,
                                                      riemann_hosts_config={
                                                          'static': ['192.168.122.16:5555:udp']},
                                                      riemann_tags=[],
                                                      riemann_service_name="Test",
                                                      riemann_ttl=360
                                                      )

        # There should be at least one Riemann host defined:
        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.initialize(riemann_enabled=True,
                                                      riemann_hosts_config={},
                                                      riemann_tags=['tag1', 'tag2'],
                                                      riemann_service_name="Test",
                                                      riemann_ttl=360
                                                      )

        # TTL should be >1
        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.initialize(riemann_enabled=True,
                                                      riemann_hosts_config={
                                                          'static': ['192.168.122.16:5555:udp']},
                                                      riemann_tags=['tag1', 'tag2'],
                                                      riemann_service_name="Test"
                                                      )

        # Service name must be defined:
        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.initialize(riemann_enabled=True,
                                                      riemann_hosts_config={
                                                          'static': ['192.168.122.16:5555:udp']},
                                                      riemann_tags=['tag1', 'tag2'],
                                                      riemann_ttl=360
                                                      )

        # Transport should be tcp or udp:
        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.initialize(riemann_enabled=True,
                                                      riemann_hosts_config={
                                                          'static': ['192.168.122.16:5555:buzz']},
                                                      riemann_tags=['tag1', 'tag2'],
                                                      riemann_service_name="Test",
                                                      riemann_ttl=360
                                                      )

        # Connection string should be sane
        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.initialize(riemann_enabled=True,
                                                      riemann_hosts_config={
                                                          'static': ['This is not correct']},
                                                      riemann_tags=['tag1', 'tag2'],
                                                      riemann_service_name="Test",
                                                      riemann_ttl=360
                                                      )

        # If you are using Riemann, there should be at least one reachable
        # server
        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.initialize(riemann_enabled=True,
                                                      riemann_hosts_config={},
                                                      riemann_tags=['tag1', 'tag2'],
                                                      riemann_service_name="Test",
                                                      riemann_ttl=360
                                                      )

        # SRV records should be sane:
        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={
                'by_srv': ['_riemann._bleeh']
                },
                riemann_tags=['tag1', 'tag2'],
                riemann_service_name="Test",
                riemann_ttl=360,
                riemann_enabled=True
                )

    def test_basic_syntax_checking(self, LoggingErrorMock, LoggingInfoMock,
                                   LoggingWarnMock):

        # Either Riemann or NRPE or both functionalities should be enabled
        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.initialize(riemann_enabled=False,
                                                      nrpe_enabled=False)

        # Initialize the class properly:
        pymisc.monitoring.ScriptStatus.initialize(nrpe_enabled=True)

        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.notify_immediate("not a real status",
                                                            "message")
        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.notify_immediate("ok", "")

        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.update("not a real status", "message")

        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.update("ok", "")

    @mock.patch('pymisc.monitoring.bernhard.Client')
    @unittest.skipIf(skip_Riemann, "In order to test Riemann functionality " +
                     "bernhard module must be installed")
    def test_riemann_exception_handling(self, RiemannMock, LoggingErrorMock,
                                        LoggingInfoMock, LoggingWarnMock):

        # Riemann exceptions should be properly handled/reported:
        def dump_exception(host, port, transport):
            raise bernhard.TransportError("Raising test exception for " +
                                          "{0}:{1} pair".format(host, port))

        RiemannMock.side_effect = dump_exception

        # Test exception handling during initialization:
        with self.assertRaises(FatalException):  # because there will be no servers left
            pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={
                'static': ['192.168.122.16:5555:udp']},
                riemann_tags=['tag1', 'tag2'],
                riemann_service_name="Test",
                riemann_ttl=360,
                riemann_enabled=True
                )
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()
        RiemannMock.reset_mock()
        RiemannMock.side_effect = None

        child_mocks = []

        def dump_exception(event):
            raise Exception("Raising test exception for event {0}".format(event))

        def register_mocks(host, port, transport):
            child = mock.Mock()
            child.send.side_effect = dump_exception
            child_mocks.append(child)
            return(child)

        RiemannMock.side_effect = register_mocks

        # Test exception handling during event sending:
        pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={
            'static': ['192.168.122.16:5555:udp']},
            riemann_tags=['tag1', 'tag2'],
            riemann_service_name="Test",
            riemann_ttl=360,
            riemann_enabled=True
            )

        pymisc.monitoring.ScriptStatus.notify_immediate("warn",
                                                        "a warning message")
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

    @mock.patch('pymisc.monitoring.bernhard')
    @unittest.skipIf(skip_Riemann, "In order to test Riemann functionality " +
                     "bernhard module must be installed")
    def test_riemann_debug_run(self, RiemannMock, LoggingErrorMock,
                               LoggingInfoMock, LoggingWarnMock):

        pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={
            'static': ['1.2.3.4:1:udp',
                       '2.3.4.5:5555:tcp']
            },
            riemann_tags=['tag1', 'tag2'],
            riemann_service_name="Test",
            riemann_ttl=360,
            riemann_enabled=True,
            debug=True
            )

        pymisc.monitoring.ScriptStatus.notify_immediate("warn",
                                                        "a warning message")

        self.assertFalse(RiemannMock.Client().send.called)

        pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={
            'static': ['1.2.3.4:1:udp',
                       '2.3.4.5:5555:tcp']
            },
            riemann_tags=['tag1', 'tag2'],
            riemann_service_name="Test",
            riemann_ttl=360,
            riemann_enabled=True,
            debug=False
            )

        pymisc.monitoring.ScriptStatus.notify_immediate("warn",
                                                        "a warning message")

        self.assertTrue(RiemannMock.Client().send.called)

    @mock.patch('pymisc.monitoring.bernhard')
    @unittest.skipIf(skip_Riemann, "In order to test Riemann functionality " +
                     "bernhard module must be installed")
    def test_riemann_status_notification(self, RiemannMock, LoggingErrorMock,
                                         LoggingInfoMock, LoggingWarnMock):

        RiemannMock.UDPTransport = 'UDPTransport'
        RiemannMock.TCPTransport = 'TCPTransport'

        pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={
            'static': ['1.2.3.4:1:udp',
                       '2.3.4.5:5555:tcp']
            },
            riemann_tags=['tag1', 'tag2'],
            riemann_service_name="Test",
            riemann_ttl=360,
            riemann_enabled=True
            )

        proper_calls = [mock.call('1.2.3.4', 1, 'UDPTransport'),
                        mock.call('2.3.4.5', 5555, 'TCPTransport')]
        RiemannMock.Client.assert_has_calls(proper_calls)
        RiemannMock.Client.reset_mock()

        # Check if notify_immediate works
        pymisc.monitoring.ScriptStatus.notify_immediate("warn",
                                                        "a warning message")
        self.assertTrue(LoggingInfoMock.called)
        LoggingErrorMock.reset_mock()

        proper_call = mock.call().send({'description': 'a warning message',
                                        'service': 'Test',
                                        'tags': ['tag1', 'tag2'],
                                        'state': 'warn',
                                        'host': platform.uname()[1],
                                        'ttl': 360}
                                       )
        # This call should be issued to *both* connection mocks, but we
        # simplify things here a bit:
        self.assertEqual(2, len([x for x in RiemannMock.Client.mock_calls
                                 if x == proper_call]))
        RiemannMock.Client.reset_mock()

        # update method shoul escalate only up:
        pymisc.monitoring.ScriptStatus.update('warn',
                                              "this is a warning message.")
        pymisc.monitoring.ScriptStatus.update('ok', 'this is OK message.')
        pymisc.monitoring.ScriptStatus.update('unknown',
                                              "this is a not-rated message.")
        pymisc.monitoring.ScriptStatus.update('ok',
                                              "this is an informational message.")

        proper_call = mock.call().send({'description':
                                        'this is a warning message. ' +
                                        'this is a not-rated message.',
                                        'service': 'Test',
                                        'tags': ['tag1', 'tag2'],
                                        'state': 'unknown',
                                        'host': platform.uname()[1],
                                        'ttl': 360}
                                       )
        # This call should be issued to *both* connection mocks, but we
        # simplify things here a bit:
        pymisc.monitoring.ScriptStatus.notify_agregated()
        self.assertEqual(2, len([x for x in RiemannMock.Client.mock_calls
                                 if x == proper_call]))
        RiemannMock.reset_mock()

    @mock.patch('dns.resolver.query')
    @mock.patch('pymisc.monitoring.bernhard')
    @unittest.skipIf(skip_Riemann, "In order to test Riemann functionality " +
                     "bernhard module must be installed")
    def test_srv_resolution(self, RiemannMock, DNSResolverMock, LoggingErrorMock,
                            LoggingInfoMock, LoggingWarnMock):

        RiemannMock.UDPTransport = 'UDPTransport'
        RiemannMock.TCPTransport = 'TCPTransport'

        def dns_data(name, record_type):
            RecordMockUDP = mock.Mock()
            RecordMockUDP.target.to_text.side_effect = lambda: "rieman01.example.com"
            RecordMockUDP.port = 10000

            RecordMockTCP = mock.Mock()
            RecordMockTCP.target.to_text.side_effect = lambda: "rieman02.example.com"
            RecordMockTCP.port = 20000

            RecordMockR1 = mock.Mock()
            RecordMockR1.to_text.side_effect = lambda: "1.2.3.4"

            RecordMockR2 = mock.Mock()
            RecordMockR2.to_text.side_effect = lambda: "2.4.6.8"

            data_hash = {"SRV": {"_riemann._tcp": [RecordMockTCP, ],
                                 "_riemann._udp": [RecordMockUDP, ], },
                         "A": {"rieman01.example.com": [RecordMockR1, ],
                               "rieman02.example.com": [RecordMockR2, ], },
                         }
            return data_hash[record_type][name]

        DNSResolverMock.side_effect = dns_data

        pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={
            'by_srv': ['_riemann._tcp',
                       '_riemann._udp']
            },
            riemann_tags=['tag1', 'tag2'],
            riemann_service_name="Test",
            riemann_ttl=360,
            riemann_enabled=True
            )

        proper_calls = [mock.call('1.2.3.4', 10000, 'UDPTransport'),
                        mock.call('2.4.6.8', 20000, 'TCPTransport')]
        self.assertEqual(len(RiemannMock.Client.call_args_list),
                         len(proper_calls))
        self.assertEqual(sorted(RiemannMock.Client.call_args_list),
                         sorted(proper_calls))

    @mock.patch('dns.resolver.query')
    @mock.patch('pymisc.monitoring.bernhard')
    @unittest.skipIf(skip_Riemann, "In order to test Riemann functionality " +
                     "bernhard module must be installed")
    def test_dns_failure(self, RiemannMock, DNSResolverMock, LoggingErrorMock,
                         LoggingInfoMock, LoggingWarnMock):

        def dns_data(name, record_type):
            raise dns.resolver.NXDOMAIN()

        DNSResolverMock.side_effect = dns_data

        with self.assertRaises(FatalException):
            pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={
                'by_srv': ['_riemann._tcp']
                },
                riemann_tags=['tag1', 'tag2'],
                riemann_service_name="Test",
                riemann_ttl=360,
                riemann_enabled=True
                )

        self.assertTrue(LoggingErrorMock.called)

        def dns_data(name, record_type):
            RecordMockTCP = mock.Mock()
            RecordMockTCP.target.to_text.side_effect = lambda: "rieman01.example.com"
            RecordMockTCP.port = 10000

            if record_type == "SRV" and name == "_riemann._tcp":
                return [RecordMockTCP, ]
            if record_type == "A" and name == "rieman01.example.com":
                raise dns.resolver.NXDOMAIN()

        DNSResolverMock.side_effect = dns_data

        with self.assertRaises(RecoverableException):
            pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={
                'by_srv': ['_riemann._tcp']
                },
                riemann_tags=['tag1', 'tag2'],
                riemann_service_name="Test",
                riemann_ttl=360,
                riemann_enabled=True
                )

    @mock.patch(builtins_path)
    @mock.patch('sys.exit')
    def test_nrpe_status_notification(self, SysExitMock, PrintMock,
                                      LoggingErrorMock, LoggingInfoMock,
                                      LoggingWarnMock):

        pymisc.monitoring.ScriptStatus.initialize(
            riemann_enabled=False,
            nrpe_enabled=True
            )

        # Check if notify_immediate works
        pymisc.monitoring.ScriptStatus.notify_immediate("warn",
                                                        "a warning message")
        SysExitMock.assert_called_once_with(1)
        PrintMock.assert_called_once_with("a warning message")
        self.assertTrue(LoggingWarnMock.called)
        LoggingErrorMock.reset_mock()
        PrintMock.reset_mock()
        SysExitMock.reset_mock()

        # update method should escalate only up:
        pymisc.monitoring.ScriptStatus.update('warn',
                                              "this is a warning message.")
        pymisc.monitoring.ScriptStatus.update('ok', 'this is OK message.')
        pymisc.monitoring.ScriptStatus.update('unknown',
                                              "this is a not-rated message.")
        pymisc.monitoring.ScriptStatus.update('ok',
                                              "this is an informational message.")

        pymisc.monitoring.ScriptStatus.notify_agregated()

        SysExitMock.assert_called_once_with(3)
        PrintMock.assert_called_once_with("this is a warning message. " +
                                          "this is a not-rated message.")
        PrintMock.reset_mock()
        SysExitMock.reset_mock()

        # OK messages should be shown only when everything is OK:
        pymisc.monitoring.ScriptStatus.initialize(
            riemann_enabled=False,
            nrpe_enabled=True
            )
        pymisc.monitoring.ScriptStatus.update('ok', 'this is OK message.')
        pymisc.monitoring.ScriptStatus.update('ok',
                                              "this is an informational message.")
        pymisc.monitoring.ScriptStatus.notify_agregated()
        SysExitMock.assert_called_once_with(0)
        PrintMock.assert_called_once_with("this is OK message. " +
                                          "this is an informational message.")


if __name__ == '__main__':
    unittest.main()
