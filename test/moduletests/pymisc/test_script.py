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
from pymisc.script import RecoverableException
import file_paths as paths
import pymisc.script


@mock.patch('logging.info')
@mock.patch('logging.warn')
@mock.patch('logging.error')
@mock.patch('sys.exit')
class TestConfigFileParsing(unittest.TestCase):
    def test_malformed_config_file(self, SysExitMock, LoggingErrorMock, *unused):
        pymisc.script.ScriptConfiguration.load_config(
            paths.TEST_MALFORMED_CONFIG_FILE)
        self.assertTrue(LoggingErrorMock.called)
        SysExitMock.assert_called_once_with(1)

    def test_nonexistent_config_file(self, SysExitMock, LoggingErrorMock, *unused):
        pymisc.script.ScriptConfiguration.load_config(
            paths.TEST_NONEXISTANT_CONFIG_FILE)
        self.assertTrue(LoggingErrorMock.called)
        SysExitMock.assert_called_once_with(1)

    def test_noninitialized_class(self, SysExitMock, LoggingErrorMock, *unused):
        with self.assertRaises(RecoverableException):
            pymisc.script.ScriptConfiguration.get_val("warn_treshold")

        with self.assertRaises(RecoverableException):
            pymisc.script.ScriptConfiguration.get_config()

    def test_proper_config_file(self, SysExitMock, LoggingErrorMock, *unused):
        pymisc.script.ScriptConfiguration.load_config(paths.TEST_CONFIG_FILE)

        tmp = pymisc.script.ScriptConfiguration.get_config()
        self.assertEqual(tmp,{  'repo_host': 'git.foo.net',
                                'riemann_tags': ['abc', 'def'],
                                'warn_treshold': 30
                                })

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

@mock.patch('logging.info')
@mock.patch('logging.error')
@mock.patch('logging.warn')
class TestNonInitializedFileLocking(unittest.TestCase):
    def test_nolock_release(self, *unused):
        with self.assertRaises(pymisc.script.RecoverableException):
            pymisc.script.ScriptLock.release()

@mock.patch('logging.info')
@mock.patch('logging.error')
@mock.patch('logging.warn')
class TestInitializedFileLocking(unittest.TestCase):
    def setUp(self):
        pymisc.script.ScriptLock.init(paths.TEST_LOCKFILE)

    def tearDown(self):
        try:
            pymisc.script.ScriptLock.release()
        except RecoverableException:
            pass

    def test_double_aqquire(self, LoggingWarnMock, *unused):
        pymisc.script.ScriptLock.aqquire()

        pymisc.script.ScriptLock.aqquire()
        self.assertTrue(LoggingWarnMock.called)

    def test_pidfile_format(self, *unused):
        pymisc.script.ScriptLock.aqquire()
        self.assertTrue(os.path.exists(paths.TEST_LOCKFILE))
        self.assertTrue(os.path.isfile(paths.TEST_LOCKFILE))
        self.assertFalse(os.path.islink(paths.TEST_LOCKFILE))

        with open(paths.TEST_LOCKFILE, 'r') as fh:
            pid_str = fh.read()
            self.assertGreater(len(pid_str), 0)
            pid = int(pid_str)
            self.assertEqual(pid, os.getpid())

    def test_locking(self, *unused):
        child = os.fork()
        if not child:
            # we are in the child process:
            pymisc.script.ScriptLock.aqquire()
            time.sleep(10)
            # script should not do any cleanup - it is part of the test :)
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

class TestTimeout(unittest.TestCase):

    # Workaround for Python2's lack of nonlocal keyword:
    h = {}

    def _test_func(self, arg1, arg2, kwarg1=0, kwarg2=None):

        self.h['called'] = True
        if arg1 == 123 and arg2 == "test_arg2" and kwarg1 == 1 and \
                kwarg2 == "test_kwarg2":
            self.h['args_ok'] = True

    def setUp(self):
        self.h['called'] = False
        self.h['args_ok'] = False

    def test_handler_funciton_invocation_args_match(self):
        pymisc.script.ScriptTimeout.set_timeout(1, self._test_func,
                                                args=[123, "test_arg2"],
                                                kwargs={"kwarg1": 1,
                                                        "kwarg2": "test_kwarg2"})

        time.sleep(2)

        self.assertTrue(self.h['called'])
        self.assertTrue(self.h['args_ok'])

    def test_handler_funciton_invocation_args_mismatch(self):
        pymisc.script.ScriptTimeout.set_timeout(1, self._test_func,
                                                args=[1, "NOK"],
                                                kwargs={"kwarg1": 2,
                                                        "kwarg2": "test_kwarg2"})

        time.sleep(2)

        self.assertTrue(self.h['called'])
        self.assertFalse(self.h['args_ok'])

    def test_timeout_clearing(self):
        pymisc.script.ScriptTimeout.set_timeout(2, self._test_func,
                                                args=[123, "test_arg2"],
                                                kwargs={"kwarg1": 1,
                                                        "kwarg2": "test_kwarg2"})

        time.sleep(1)

        self.assertFalse(self.h['called'])
        self.assertFalse(self.h['args_ok'])

        pymisc.script.ScriptTimeout.clear_timeout()

        time.sleep(2.2)

        self.assertFalse(self.h['called'])
        self.assertFalse(self.h['args_ok'])


if __name__ == '__main__':
    unittest.main()
