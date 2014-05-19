#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
# Copyright (c) 2014 Pawel Rozlach
# Copyright (c) 2013 Pawel Rozlach
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
from __future__ import print_function

import coverage
import os
import shutil
import sys
import unittest


def main():
    major, minor, micro, releaselevel, serial = sys.version_info

    if major == 2 and minor < 7:
        print("In order to run tests you need at least Python 2.7")
        sys.exit(1)

    # Cleanup old html report:
    for root, dirs, files in os.walk('test/output_coverage_html/'):
        for f in files:
            if f == '.gitignore' or f == '.empty_dir':
                continue
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))

    # Perform coverage analisys:
    cov = coverage.coverage()

    cov.start()
    # Discover the test and execute them:
    loader = unittest.TestLoader()
    tests = loader.discover('./test/')
    testRunner = unittest.runner.TextTestRunner(descriptions=True, verbosity=1)
    testRunner.run(tests)
    cov.stop()

    cov.html_report()

if __name__ == '__main__':
    main()
