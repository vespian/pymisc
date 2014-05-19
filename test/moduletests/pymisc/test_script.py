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


# Make it a bit more like python3(in case we are running python2):
from __future__ import absolute_import
from __future__ import division
from __future__ import nested_scopes
from __future__ import print_function
from __future__ import with_statement

# Global imports:
import os
import sys
import time
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
import file_paths as paths
import pymisc.script


class TestPymiscScript(unittest.TestCase):
    @mock.patch('logging.error')
    @mock.patch('sys.exit')
    def test_config_file_parsing(self, SysExitMock, LoggingErrorMock):
        # Test malformed file loading
        pymisc.script.ScriptConfiguration.load_config(
            paths.TEST_MALFORMED_CONFIG_FILE)
        self.assertTrue(LoggingErrorMock.called)
        SysExitMock.assert_called_once_with(1)
        SysExitMock.reset_mock()

        # Test non-existent file loading
        pymisc.script.ScriptConfiguration.load_config(
            paths.TEST_NONEXISTANT_CONFIG_FILE)
        self.assertTrue(LoggingErrorMock.called)
        SysExitMock.assert_called_once_with(1)

        # Load the config file
        pymisc.script.ScriptConfiguration.load_config(paths.TEST_CONFIG_FILE)

        # String:
        self.assertEqual(
            pymisc.script.ScriptConfiguration.get_val("repo_host"),
            "git.foo.net")
        # List of strings
        self.assertEqual(
            pymisc.script.ScriptConfiguration.get_val("riemann_tags"),
            ['abc', 'def'])
        # Integer:
        self.assertEqual(
            pymisc.script.ScriptConfiguration.get_val("warn_treshold"), 30)

        # Key not in config file:
        with self.assertRaises(KeyError):
            pymisc.script.ScriptConfiguration.get_val("not_a_field")

    @mock.patch('logging.warn')
    def test_file_locking(self, LoggingWarnMock, *unused):
        pymisc.script.ScriptLock.init(paths.TEST_LOCKFILE)

        with self.assertRaises(pymisc.script.RecoverableException):
            pymisc.script.ScriptLock.release()

        pymisc.script.ScriptLock.aqquire()

        pymisc.script.ScriptLock.aqquire()
        self.assertTrue(LoggingWarnMock.called)

        self.assertTrue(os.path.exists(paths.TEST_LOCKFILE))
        self.assertTrue(os.path.isfile(paths.TEST_LOCKFILE))
        self.assertFalse(os.path.islink(paths.TEST_LOCKFILE))

        with open(paths.TEST_LOCKFILE, 'r') as fh:
            pid_str = fh.read()
            self.assertGreater(len(pid_str), 0)
            pid = int(pid_str)
            self.assertEqual(pid, os.getpid())

        pymisc.script.ScriptLock.release()

        child = os.fork()
        if not child:
            # we are in the child process:
            pymisc.script.ScriptLock.aqquire()
            time.sleep(10)
            # script should not do any cleanup - it is part of the tests :)
        else:
            # parent
            timer = 0
            while timer < 3:
                if os.path.isfile(paths.TEST_LOCKFILE):
                    break
                else:
                    timer += 0.1
                    time.sleep(0.1)
            else:
                # Child did not create pidfile in 3 s,
                # we should clean up and bork:
                os.kill(child, 9)
                assert False

            with self.assertRaises(pymisc.script.RecoverableException):
                pymisc.script.ScriptLock.aqquire()

            os.kill(child, 11)

            # now it should succed
            pymisc.script.ScriptLock.aqquire()


if __name__ == '__main__':
    unittest.main()
