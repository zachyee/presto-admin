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

"""
Tests for cluster.py
"""

from fabric.api import env

from prestoadmin.util.cluster import YARN_RM_HOSTNAME_KEY, \
    YARN_RM_WEBAPP_ADDRESS_KEY, get_rm_webapp_address
from prestoadmin.util.exception import ConfigurationError
from prestoadmin.yarn_slider.config import HADOOP_CONF, DIR

from mock import patch

from tests.unit.base_unit_case import BaseUnitCase


class TestCluster(BaseUnitCase):
    def setUp(self):
        super(TestCluster, self).setUp()
        env.conf = {
            DIR: '/opt/slider',
            HADOOP_CONF: '/etc/hadoop/conf'
        }

    def get_side_effect(self, rv_dict):
        def side_effect(path):
            value = rv_dict[path]
            if isinstance(value, dict):
                return value
            else:
                raise value()
        return side_effect

    @patch('prestoadmin.util.cluster.get_config')
    def test_slider_rm_webapp(self, mock_get_config):
        mock_get_config.side_effect = self.get_side_effect(
            {
                '/opt/slider/conf/slider-client.xml': {
                    YARN_RM_WEBAPP_ADDRESS_KEY: 'Head',
                    YARN_RM_HOSTNAME_KEY: 'Shoulders'
                },
                '/etc/hadoop/conf/yarn-site.xml': {
                    YARN_RM_WEBAPP_ADDRESS_KEY: 'Knees',
                    YARN_RM_HOSTNAME_KEY: 'Toes'
                }
            })

        self.assertEqual('Head', get_rm_webapp_address())

    @patch('prestoadmin.util.cluster.get_config')
    def test_slider_rm_hostname(self, mock_get_config):
        mock_get_config.side_effect = self.get_side_effect(
            {
                '/opt/slider/conf/slider-client.xml': {
                    YARN_RM_HOSTNAME_KEY: 'Shoulders'
                },
                '/etc/hadoop/conf/yarn-site.xml': {
                    YARN_RM_WEBAPP_ADDRESS_KEY: 'Knees',
                    YARN_RM_HOSTNAME_KEY: 'Toes'
                }
            })

        self.assertEqual('Shoulders:8088', get_rm_webapp_address())

    @patch('prestoadmin.util.cluster.get_config')
    def test_no_slider(self, mock_get_config):
        mock_get_config.side_effect = self.get_side_effect(
            {
                '/opt/slider/conf/slider-client.xml': IOError,
                '/etc/hadoop/conf/yarn-site.xml': {
                    YARN_RM_WEBAPP_ADDRESS_KEY: 'Knees',
                    YARN_RM_HOSTNAME_KEY: 'Toes'
                }
            })

        self.assertEqual('Knees', get_rm_webapp_address())

    @patch('prestoadmin.util.cluster.get_config')
    def test_yarn_rm_webapp(self, mock_get_config):
        mock_get_config.side_effect = self.get_side_effect(
            {
                '/opt/slider/conf/slider-client.xml': {
                },
                '/etc/hadoop/conf/yarn-site.xml': {
                    YARN_RM_WEBAPP_ADDRESS_KEY: 'Knees',
                    YARN_RM_HOSTNAME_KEY: 'Toes'
                }
            })

        self.assertEqual('Knees', get_rm_webapp_address())

    @patch('prestoadmin.util.cluster.get_config')
    def test_yarn_rm_hostname(self, mock_get_config):
        mock_get_config.side_effect = self.get_side_effect(
            {
                '/opt/slider/conf/slider-client.xml': {
                },
                '/etc/hadoop/conf/yarn-site.xml': {
                    YARN_RM_HOSTNAME_KEY: 'Toes'
                }
            })

        self.assertEqual('Toes:8088', get_rm_webapp_address())

    @patch('prestoadmin.util.cluster.get_config')
    def test_no_config(self, mock_get_config):
        mock_get_config.side_effect = self.get_side_effect(
            {
                '/opt/slider/conf/slider-client.xml': IOError,
                '/etc/hadoop/conf/yarn-site.xml': IOError
            })

        self.assertRaises(ConfigurationError, get_rm_webapp_address)
