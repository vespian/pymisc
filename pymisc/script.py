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
from __future__ import division
from __future__ import nested_scopes
from __future__ import print_function
from __future__ import with_statement

# Imports:
import fcntl
import logging
import os
import signal
import sys
import yaml


class RecoverableException(Exception):
    """
    Class used to create a separate hierarchy of recoverable exceptions.

    Exceptions raised using this class and classess inheriting from it are
    expected to be *non-fatal* *and* *local* to given script/application.
    """
    pass


class FatalException(Exception):
    """
    Class used to create a separate hierarchy of fatal exceptions.

    Exceptions raised using this class and classess inheriting from it are
    expected to be *fatal* *and* *local* to given script/application.
    """
    pass


class ScriptConfiguration(object):
    """
    Simple configuration file handling.

    Based on the YAML format, this class provides basic facilities for
    script/app configuration. It does not validate the configuration file
    format, it is up to the calling script/app to do it.
    """
    _config = dict()

    @classmethod
    def load_config(cls, file_path):
        """
        Args:
            file_path: path to the configuration file to load
        """
        try:
            with open(file_path, 'r') as fh:
                cls._config = yaml.load(fh)
        except IOError as e:
            logging.error("Failed to open config file {0}: {1}".format(
                file_path, e))
            sys.exit(1)
        except (ValueError, yaml.YAMLError) as e:
            logging.error("File {0} is not a proper yaml document: {1}".format(
                file_path, e))
            sys.exit(1)

    @classmethod
    def get_val(cls, key):
        """
        Args:
            key: name of the parameter to fetch
        """
        return cls._config[key]


class ScriptLock(object):
    """
    Basic locking facility for Python.

    Python's lockfile module isn't very usefull, so this class provides it own
    locking. Currently only one lock per script/app is supported.
    """
    _fh = None
    _file_path = None

    @classmethod
    def init(cls, file_path):
        """
        Init class with lock file location.

        Args:
            file_path: path to use when creating lockfile
        """
        cls._file_path = file_path

    @classmethod
    def aqquire(cls):
        if cls._fh:
            logging.warn("File lock already aquired")
            return
        try:
            cls._fh = open(cls._file_path, 'w')
            # flock is nice because it is automatically released when the
            # process dies/terminates
            fcntl.flock(cls._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            if cls._fh:
                cls._fh.close()
            raise RecoverableException("{0} ".format(cls._file_path) +
                                       "is already locked by a different " +
                                       "process or cannot be created.")
        cls._fh.write(str(os.getpid()))
        cls._fh.flush()

    @classmethod
    def release(cls):
        if not cls._fh:
            raise RecoverableException("Trying to release non-existant lock")
        cls._fh.close()
        cls._fh = None
        os.unlink(cls._file_path)


class ScriptTimeout(object):
    """
    Yet another implementation of scipt's timeout using SIGALARM.
    """

    @classmethod
    def set_timeout(cls, timeout, func, args=[], kwargs={}):
        """
        Sets timeout to predefined value.

        On timeout, function "func" is called with passed arguments.

        Args:
            timeout: time after which function "func" should be called.
            func: the function to call
            args: function's positional arguments
            kwargs: function's keyword arguments
        """
        def handler(signalnum, stackframe):
            func(*args, **kwargs)

        signal.signal(signal.SIGALRM, handler)
        signal.alarm(timeout)

    @classmethod
    def clear_timeout(cls):
        """
        Clears the timeout/prevents it occuring.
        """
        signal.alarm(0)
