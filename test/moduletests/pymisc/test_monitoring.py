#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
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
import os
import platform
import sys
major, minor, micro, releaselevel, serial = sys.version_info
if major == 2 and minor < 7:
    import unittest2 as unittest
else:
    import unittest
import mock

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
import pymisc.monitoring


class TestPymiscMonitoring(unittest.TestCase):
    @mock.patch('logging.warn')  # Unused, but masks error messages
    @mock.patch('logging.info')
    @mock.patch('logging.error')
    @mock.patch('pymisc.monitoring.bernhard')
    def test_script_status(self, RiemannMock, LoggingErrorMock,
                           LoggingInfoMock, *unused):
        # There should be at least one tag defined:
        pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={},
                                                  riemann_tags=[])
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

        # There should be at least one Riemann host defined:
        pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={},
                                                  riemann_tags=['tag1', 'tag2'])
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

        # Riemann exceptions should be properly handled/reported:
        def side_effect(host, port):
            raise Exception("Raising exception for {0}:{1} pair")

        RiemannMock.UDPTransport = 'UDPTransport'
        RiemannMock.TCPTransport = 'TCPTransport'
        RiemannMock.Client.side_effect = side_effect

        pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={
            'static': ['192.168.122.16:5555:udp']},
            riemann_tags=['tag1', 'tag2'])
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

        RiemannMock.Client.side_effect = None
        RiemannMock.Client.reset_mock()

        # Mock should only allow legitimate exit_statuses
        pymisc.monitoring.ScriptStatus.notify_immediate("not a real status",
                                                        "message")
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

        pymisc.monitoring.ScriptStatus.update("not a real status", "message")
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

        # Done with syntax checking, now initialize the class properly:
        pymisc.monitoring.ScriptStatus.initialize(riemann_hosts_config={
            'static': ['1.2.3.4:1:udp',
                       '2.3.4.5:5555:tcp']
            },
            riemann_tags=['tag1', 'tag2'])

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
                                        'service': 'pymisc.monitoring',
                                        'tags': ['tag1', 'tag2'],
                                        'state': 'warn',
                                        'host': platform.uname()[1],
                                        'ttl': 90000}
                                       )
        # This call should be issued to *both* connection mocks, but we
        # simplify things here a bit:
        self.assertEqual(2, len([x for x in RiemannMock.Client.mock_calls
                                 if x == proper_call]))
        RiemannMock.Client.reset_mock()

        # update method shoul escalate only up:
        pymisc.monitoring.ScriptStatus.update('warn',
                                              "this is a warning message.")
        pymisc.monitoring.ScriptStatus.update('ok', '')
        pymisc.monitoring.ScriptStatus.update('unknown',
                                              "this is a not-rated message.")
        pymisc.monitoring.ScriptStatus.update('ok',
                                              "this is an informational message.")

        proper_call = mock.call().send({'description':
                                        'this is a warning message.\n' +
                                        'this is a not-rated message.\n' +
                                        'this is an informational message.',
                                        'service': 'pymisc.monitoring',
                                        'tags': ['tag1', 'tag2'],
                                        'state': 'unknown',
                                        'host': platform.uname()[1],
                                        'ttl': 90000}
                                       )
        # This call should be issued to *both* connection mocks, but we
        # simplify things here a bit:
        pymisc.monitoring.ScriptStatus.notify_agregated()
        self.assertEqual(2, len([x for x in RiemannMock.Client.mock_calls
                                 if x == proper_call]))
        RiemannMock.reset_mock()


if __name__ == '__main__':
    unittest.main()
