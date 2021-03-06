# -*- coding: utf-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import tempfile

from unittest import TestCase

from prestoadmin.util.application import Application
from prestoadmin.util import constants

EXECUTABLE_NAME = 'foo.py'
APPLICATION_NAME = 'foo'


class ApplicationTest(TestCase):

    def setUp(self):
        # monkey patch the log directory constant so that
        # we force log files to a temporary dir
        self.__old_prestoadmin_log = constants.PRESTOADMIN_LOG_DIR
        self.__temporary_dir_path = tempfile.mkdtemp(
            prefix='app-int-test-'
        )
        constants.PRESTOADMIN_LOG_DIR = self.__temporary_dir_path

        # monkey patch in a fake logging config file
        self.__old_log_dirs = list(constants.LOGGING_CONFIG_FILE_DIRECTORIES)
        constants.LOGGING_CONFIG_FILE_DIRECTORIES.append(
            os.path.join(os.path.dirname(__file__), 'data')
        )

        # basicConfig is a noop if there are already handlers
        # present on the root logger, remove them all here
        self.__old_log_handlers = []
        for handler in logging.root.handlers:
            self.__old_log_handlers.append(handler)
            logging.root.removeHandler(handler)

    def tearDown(self):
        constants.LOGGING_CONFIG_FILE_DIRECTORIES = self.__old_log_dirs

        # restore the log constant
        constants.PRESTOADMIN_LOG_DIR = self.__old_prestoadmin_log

        # clean up the temporary directory
        os.system('rm -rf ' + self.__temporary_dir_path)

        # restore the old log handlers
        for handler in logging.root.handlers:
            logging.root.removeHandler(handler)
        for handler in self.__old_log_handlers:
            logging.root.addHandler(handler)

    def test_log_file_is_created(self):
        with Application(APPLICATION_NAME):
            pass

        log_file_path = os.path.join(
            constants.PRESTOADMIN_LOG_DIR,
            APPLICATION_NAME + '.log'
        )
        self.assertTrue(
            os.path.exists(log_file_path),
            'Expected log file does not exist'
        )
        self.assertTrue(
            os.path.getsize(log_file_path) > 0,
            'Log file is empty'
        )
