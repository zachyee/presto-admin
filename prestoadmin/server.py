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
Module for installing, monitoring, and controlling presto server
using presto-admin
"""
import cgi
import logging
import re
import sys
import urllib2

from fabric.api import task, sudo, env
from fabric.context_managers import settings, hide
from fabric.decorators import runs_once, with_settings, parallel
from fabric.operations import run, os
from fabric.tasks import execute
from fabric.utils import warn, error, abort
from retrying import retry

from prestoadmin import configure_cmds
from prestoadmin import connector
from prestoadmin import main_dir
from prestoadmin import package
from prestoadmin.util.version_util import VersionRange, VersionRangeList, \
    split_version, strip_tag
from prestoadmin.prestoclient import PrestoClient
from prestoadmin.standalone.config import StandaloneConfig, \
    PRESTO_STANDALONE_USER_GROUP
from prestoadmin.util.base_config import requires_config
from prestoadmin.util import constants
from prestoadmin.util.exception import ConfigFileNotFoundError
from prestoadmin.util.fabricapi import get_host_list, get_coordinator_role
from prestoadmin.util.remote_config_util import lookup_port, \
    lookup_server_log_file, lookup_launcher_log_file

from tempfile import mkdtemp
import util.filesystem

__all__ = ['install', 'uninstall', 'upgrade', 'start', 'stop', 'restart',
           'status']

INIT_SCRIPTS = '/etc/init.d/presto'
RETRY_TIMEOUT = 120
SLEEP_INTERVAL = 10
SYSTEM_RUNTIME_NODES = 'select * from system.runtime.nodes'


def old_sysnode_processor(node_info_rows):
    def old_transform(node_is_active):
        return 'active' if node_is_active else 'inactive'
    return get_sysnode_info_from(node_info_rows, old_transform)


def new_sysnode_processor(node_info_rows):
    return get_sysnode_info_from(node_info_rows, lambda x: x)


NODE_INFO_PER_URI_SQL = VersionRangeList(
    VersionRange((0, 0), (0, 128),
                 ('select http_uri, node_version, active from '
                  'system.runtime.nodes where '
                  'url_extract_host(http_uri) = \'%s\'',
                 old_sysnode_processor)),
    VersionRange((0, 128), (sys.maxsize,),
                 ('select http_uri, node_version, state from '
                  'system.runtime.nodes where '
                  'url_extract_host(http_uri) = \'%s\'',
                 new_sysnode_processor))
)

EXTERNAL_IP_SQL = 'select url_extract_host(http_uri) from ' \
                  'system.runtime.nodes WHERE node_id = \'%s\''
CONNECTOR_INFO_SQL = 'select catalog_name from system.metadata.catalogs'
_LOGGER = logging.getLogger(__name__)

DOWNLOAD_DIRECTORY = main_dir
DEFAULT_RPM_NAME = 'presto-server-rpm.rpm'


def _find_or_download_most_recent_presto_rpm():
    newest_rpm_release = 'https://repository.sonatype.org/service/local/artifact/maven' \
                         '/content?r=central-proxy&g=com.facebook.presto' \
                         '&a=presto-server-rpm&e=rpm&v=RELEASE'
    return _find_or_download_rpm(newest_rpm_release)


def _check_if_valid_version(rpm_version):
    return re.match('^[0-9]+(\.[0-9]+){1,2}[tf]?$', rpm_version)


def _check_good_response_status(response_status):
    return response_status == 200


def _get_content_length(url_response):
    try:
        headers = url_response.info()
        return int(headers['Content-Length'])
    except (KeyError, ValueError):
        return None


def _get_download_file_name(url_response, version=None):
    try:
        headers = url_response.info()
        content_disposition = headers['Content-Disposition']
        values, params = cgi.parse_header(content_disposition)
        return params['filename']
    except KeyError:
        if not version:
            return DEFAULT_RPM_NAME
        else:
            return 'presto-server-rpm-' + version + '.rpm'


def _print_download_status(bytes_read, total_bytes):
    percent = float(bytes_read) / total_bytes
    percent = round(percent * 100, 2)
    print 'Downloaded %d of %d bytes. (%0.2f%%)' % \
          (bytes_read, total_bytes, percent)


def _find_downloaded_rpm(download_file_name):
    download_file_path = os.path.join(DOWNLOAD_DIRECTORY, download_file_name)

    if os.path.isfile(download_file_path):
        print 'Found rpm at: %s' % download_file_path
        return download_file_path
    else:
        return None


def _download_rpm(url_response, download_file_path):
    content_length = _get_content_length(url_response)
    print 'Downloading rpm from %s.\n' \
          'This can take a few minutes.' % url_response.geturl()

    with open(download_file_path, 'wb') as local_file:
        bytes_read = 0
        block_size = 16 * 1024 * 1024
        while True:
            download_buffer = url_response.read(block_size)
            if not download_buffer:
                break
            bytes_read += len(download_buffer)
            local_file.write(download_buffer)
            if content_length:
                _print_download_status(bytes_read, content_length)
        print "Downloaded %d bytes." % bytes_read

    print 'Rpm downloaded to: %s' % download_file_path
    return download_file_path


def _find_or_download_rpm(url, version=None):
    """
    Args:
        url:      The url of the presto rpm to be downloaded.
        version:  An optional version number.
                  If the server doesn't respond with the file name that is being
                  requested, this allows the downloaded file to have the correct
                  version attached to its name (presto-server-rpm-'version'.rpm)
                  rather than the default name

    If downloading the presto rpm at the given url would overwrite an existing rpm,
    this function returns the path to the existing rpm. However, if the rpm that
    would be downloaded takes the default rpm name, it will overwrite the existing
    rpm because there is no way to know if the default rpm name is of the same version
    as the requested rpm.

    Returns:
        Upon success, the path to the downloaded or found presto rpm
        Upon failure, None
    """
    try:
        url_response = urllib2.urlopen(url)
    except ValueError:
        return None

    if not _check_good_response_status(url_response.getcode()):
        return None

    download_file_name = _get_download_file_name(url_response, version)
    download_file_path = os.path.join(DOWNLOAD_DIRECTORY, download_file_name)

    downloaded_rpm_path = _find_downloaded_rpm(download_file_name)
    if downloaded_rpm_path and download_file_name != DEFAULT_RPM_NAME:
        return downloaded_rpm_path

    return _download_rpm(url_response, download_file_path)


def _find_or_download_rpm_version_facebook(rpm_version):
    rpm_version_fb = rpm_version[:-1]
    download_url = 'http://search.maven.org/remotecontent?filepath=com/facebook/presto/' \
                   'presto-server-rpm/' + rpm_version_fb + '/presto-server-rpm-' + \
                   rpm_version_fb + '.rpm'
    return _find_or_download_rpm(download_url, rpm_version_fb)


def _find_or_download_rpm_version_teradata(rpm_version):
    abort('Download for teradata presto rpms is not currently supported.\n'
          'Try again after downloading the rpm and specifying the local path to the rpm')


def _find_or_download_rpm_version(rpm_version):
    """
    Attempt to find or download the given rpm version.

    Default to using Facebook rpm if 'f'aceboook and 't'eradata
    are not specified in rpm_version.
    """
    if not _check_if_valid_version(rpm_version):
        return None

    if rpm_version[-1] != 'f' and rpm_version[-1] != 't':
        rpm_version += 'f'
        if not _check_if_valid_version(rpm_version):
            return None

    if rpm_version[-1] == 'f':
        download_rpm = _find_or_download_rpm_version_facebook(rpm_version)
    elif rpm_version[-1] == 't':
        download_rpm = _find_or_download_rpm_version_teradata(rpm_version)
    else:
        return None

    return download_rpm


def get_path_to_presto_rpm(rpm_specifier):
    """
    This function will attempt to find the rpm at the given location by rpm_specifier.
    It will check if rpm_specifier is 'release', a version number, or a url.
    In these cases, this function will download the rpm, if necessary, and return a path
    to the rpm.

    If rpm_specifier is none of the above, then it is assumed that it is a local path
    and the function simply returns rpm_specifier.
    """
    if rpm_specifier == "release":
        path_to_release_rpm = _find_or_download_most_recent_presto_rpm()
        if path_to_release_rpm:
            return path_to_release_rpm

    path_to_version_rpm = _find_or_download_rpm_version(rpm_specifier)
    if path_to_version_rpm:
        return path_to_version_rpm

    path_to_url_rpm = _find_or_download_rpm(rpm_specifier)
    if path_to_url_rpm:
        return path_to_url_rpm

    return rpm_specifier


@task
@runs_once
@requires_config(StandaloneConfig)
def install(rpm_specifier):
    """
    Copy and install the presto-server rpm to all the nodes in the cluster and
    configure the nodes.

    The topology information will be read from the config.json file. If this
    file is missing, then the coordinator and workers will be obtained
    interactively. Install will fail for invalid json configuration.

    The connector configurations will be read from the directory
    /etc/opt/prestoadmin/connectors. If this directory is missing or empty
    then no connector configuration is deployed.

    Install will fail for incorrectly formatted configuration files. Expected
    format is key=value for .properties files and one option per line for
    jvm.config

    Parameters:
        rpm_specifier - String specifying location of presto rpm to copy and install
                        to nodes in the cluster. The string can specify a presto rpm
                        in the following ways:
                        
                        1.  Path to a local copy
                        2.  Url to download
                        3.  Version number to download
                        4.  'release' to download the most recent release

                        Before downloading an rpm, install will attempt to find a local
                        copy with a matching version number to the requested rpm. If such
                        a match is found, it will use the local copy instead of downloading
                        the rpm again.

        --nodeps -      (optional) Flag to indicate if server install
                        should ignore checking Presto rpm package
                        dependencies. Equivalent to adding --nodeps
                        flag to rpm -i.
    """
    path_to_rpm = get_path_to_presto_rpm(rpm_specifier)
    package.check_if_valid_rpm(path_to_rpm)
    return execute(deploy_install_configure, path_to_rpm, hosts=get_host_list())


def deploy_install_configure(local_path):
    package.deploy_install(local_path)
    update_configs()
    wait_for_presto_user()


def add_tpch_connector():
    tpch_connector_config = os.path.join(constants.CONNECTORS_DIR,
                                         'tpch.properties')
    util.filesystem.write_to_file_if_not_exists('connector.name=tpch',
                                                tpch_connector_config)


def update_configs():
    configure_cmds.deploy()

    add_tpch_connector()
    try:
        connector.add()
    except ConfigFileNotFoundError:
        _LOGGER.info('No connector directory found, not adding connectors.')


@retry(stop_max_delay=3000, wait_fixed=250)
def wait_for_presto_user():
    ret = sudo('getent passwd presto', quiet=True)
    if not ret.succeeded:
        raise Exception('Presto package was not installed successfully. '
                        'Presto user was not created.')


@task
@requires_config(StandaloneConfig)
def uninstall():
    """
    Uninstall Presto after stopping the services on all nodes

    Parameters:
        --nodeps -              (optional) Flag to indicate if server uninstall
                                should ignore checking Presto rpm package
                                dependencies. Equivalent to adding --nodeps
                                flag to rpm -e.
    """
    stop()

    if package.is_rpm_installed('presto'):
        package.rpm_uninstall('presto')
    elif package.is_rpm_installed('presto-server'):
        package.rpm_uninstall('presto-server')
    elif package.is_rpm_installed('presto-server-rpm'):
        package.rpm_uninstall('presto-server-rpm')
    else:
        abort('Unable to uninstall package on: ' + env.host)


@task
@requires_config(StandaloneConfig)
def upgrade(new_rpm_path, local_config_dir=None, overwrite=False):
    """
    Copy and upgrade a new presto-server rpm to all of the nodes in the
    cluster. Retains existing node configuration.

    The existing topology information is read from the config.json file.
    Unlike install, there is no provision to supply topology information
    interactively.

    The existing cluster configuration is collected from the nodes on the
    cluster and stored on the host running presto-admin. After the
    presto-server packages have been upgraded, presto-admin pushes the
    collected configuration back out to the hosts on the cluster.

    Note that the configuration files in /etc/opt/prestoadmin are not updated
    during upgrade.

    :param new_rpm_path -       The path to the new Presto RPM to
                                install
    :param local_config_dir -   (optional) Directory to store the cluster
                                configuration in. If not specified, a temp
                                directory is used.
    :param overwrite -          (optional) if set to True then existing
                                configuration will be orerwriten.

    :param --nodeps -           (optional) Flag to indicate if server upgrade
                                should ignore checking Presto rpm package
                                dependencies. Equivalent to adding --nodeps
                                flag to rpm -U.
    """
    stop()

    if not local_config_dir:
        local_config_dir = mkdtemp()
        print('Saving cluster configuration to %s' % local_config_dir)

    configure_cmds.gather_directory(local_config_dir, overwrite)
    filenames = connector.gather_connectors(local_config_dir, overwrite)

    package.deploy_upgrade(new_rpm_path)

    configure_cmds.deploy_all(local_config_dir)
    connector.deploy_files(
        filenames,
        os.path.join(local_config_dir, env.host, 'catalog'),
        constants.REMOTE_CATALOG_DIR, PRESTO_STANDALONE_USER_GROUP)


def service(control=None):
    if check_presto_version() != '':
        return False
    if control == 'start' and is_port_in_use(env.host):
        return False
    _LOGGER.info('Executing %s on presto server' % control)
    ret = sudo('set -m; ' + INIT_SCRIPTS + ' ' + control)
    return ret.succeeded


def check_status_for_control_commands():
    client = PrestoClient(env.host, env.user)
    print('Waiting to make sure we can connect to the Presto server on %s, '
          'please wait. This check will time out after %d minutes if the '
          'server does not respond.'
          % (env.host, (RETRY_TIMEOUT / 60)))
    if check_server_status(client):
        print('Server started successfully on: ' + env.host)
    else:
        error('Server failed to start on: ' + env.host +
              '\nPlease check ' + lookup_server_log_file(env.host) + ' and ' +
              lookup_launcher_log_file(env.host))


def is_port_in_use(host):
    _LOGGER.info("Checking if port used by Prestoserver is already in use..")
    try:
        portnum = lookup_port(host)
    except Exception:
        _LOGGER.info("Cannot find port from config.properties. "
                     "Skipping check for port already being used")
        return 0
    with settings(hide('warnings', 'stdout'), warn_only=True):
        output = run('netstat -ln |grep -E "\<%s\>" |grep LISTEN' % str(portnum))
    if output:
        _LOGGER.info("Presto server port already in use. Skipping "
                     "server start...")
        error('Server failed to start on %s. Port %s already in use'
              % (env.host, str(portnum)))
    return output


@task
@requires_config(StandaloneConfig)
def start():
    """
    Start the Presto server on all nodes

    A status check is performed on the entire cluster and a list of
    servers that did not start, if any, are reported at the end.
    """
    if service('start'):
        check_status_for_control_commands()


@task
@requires_config(StandaloneConfig)
def stop():
    """
    Stop the Presto server on all nodes
    """
    service('stop')


def stop_and_start():
    if check_presto_version() != '':
        return False
    sudo('set -m; ' + INIT_SCRIPTS + ' stop')
    if is_port_in_use(env.host):
        return False
    _LOGGER.info('Executing start on presto server')
    ret = sudo('set -m; ' + INIT_SCRIPTS + ' start')
    return ret.succeeded


@task
@requires_config(StandaloneConfig)
def restart():
    """
    Restart the Presto server on all nodes.

    A status check is performed on the entire cluster and a list of
    servers that did not start, if any, are reported at the end.
    """
    if stop_and_start():
        check_status_for_control_commands()


def check_presto_version():
    """
    Checks that the Presto version is suitable.

    Returns:
        Error string if applicable
    """
    if not presto_installed():
        not_installed_str = 'Presto is not installed.'
        warn(not_installed_str)
        return not_installed_str

    return ''


def presto_installed():
    with settings(hide('warnings', 'stdout'), warn_only=True):
        package_search = run('rpm -q presto')
        if not package_search.succeeded:
            package_search = run('rpm -q presto-server-rpm')
        return package_search.succeeded


def get_presto_version():
    with settings(hide('warnings', 'stdout'), warn_only=True):
        version = run('rpm -q --qf \"%{VERSION}\\n\" presto')
        # currently we have two rpm names out so we need this retry
        if not version.succeeded:
            version = run('rpm -q --qf \"%{VERSION}\\n\" presto-server-rpm')
        version = version.strip()
        _LOGGER.debug('Presto rpm version: ' + version)
        return version


def check_server_status(client):
    """
    Checks if server is running for env.host. Retries connecting to server
    until server is up or till RETRY_TIMEOUT is reached

    Parameters:
        client - client that executes the query

    Returns:
        True or False
    """
    result = True
    time = 0
    while time < RETRY_TIMEOUT:
        result = client.execute_query(SYSTEM_RUNTIME_NODES)
        if not result:
            run('sleep %d' % SLEEP_INTERVAL)
            _LOGGER.debug('Status retrieval for the server failed after '
                          'waiting for %d seconds. Retrying...' % time)
            time += SLEEP_INTERVAL
        else:
            break
    return result


def run_sql(client, sql):
    status = client.execute_query(sql)
    if status:
        return client.get_rows()
    else:
        # TODO: Check if we can get some error cause from server response and
        # log that to the user
        _LOGGER.error('Querying server failed')
        return []


def execute_connector_info_sql(client):
    """
    Returns [[catalog_name], [catalog_2]..] from catalogs system table

    Parameters:
        client - client that executes the query
    """
    return run_sql(client, CONNECTOR_INFO_SQL)


def execute_external_ip_sql(client, uuid):
    """
    Returns external ip of the host with uuid after parsing the http_uri column
    from nodes system table

    Parameters:
        client - client that executes the query
        uuid - node_id of the node
    """
    return run_sql(client, EXTERNAL_IP_SQL % uuid)


def get_sysnode_info_from(node_info_row, state_transform):
    """
    Returns system node info dict from node info row for a node

    Parameters:
        node_info_row -

    Returns:
        Node info dict in format:
        {'http://node1/statement': [presto-main:0.97-SNAPSHOT, True]}
    """
    output = {}
    for row in node_info_row:
        if row:
            output[row[0]] = [row[1], state_transform(row[2])]

    _LOGGER.info('Node info: %s ', output)
    return output


def get_connector_info_from(client):
    """
    Returns installed connectors

    Parameters:
        client - client that executes the query

    Returns:
        comma delimited connectors eg: tpch, hive, system
    """
    syscatalog = []
    connector_info = execute_connector_info_sql(client)
    for conn_info in connector_info:
        if conn_info:
            syscatalog.append(conn_info[0])
    return ', '.join(syscatalog)


def is_server_up(status):
    if status:
        return 'Running'
    else:
        return 'Not Running'


def get_roles_for(host):
    roles = []
    for role in ['coordinator', 'worker']:
        if host in env.roledefs[role]:
            roles.append(role)
    return roles


def print_node_info(node_status, connector_status):
    for k in node_status:
        print('\tNode URI(http): ' + str(k) +
              '\n\tPresto Version: ' + str(node_status[k][0]) +
              '\n\tNode status:    ' + str(node_status[k][1]))
        if connector_status:
            print('\tConnectors:     ' + connector_status)


def get_ext_ip_of_node(client):
    node_properties_file = os.path.join(constants.REMOTE_CONF_DIR,
                                        'node.properties')
    with settings(hide('stdout')):
        node_uuid = run('sed -n s/^node.id=//p ' + node_properties_file)
    external_ip_row = execute_external_ip_sql(client, node_uuid)
    external_ip = ''
    if len(external_ip_row) > 1:
        warn_more_than_one_ip = 'More than one external ip found for ' \
                                + env.host + '. There could be multiple ' \
                                'nodes associated with the same node.id'
        _LOGGER.debug(warn_more_than_one_ip)
        warn(warn_more_than_one_ip)
        return external_ip
    for row in external_ip_row:
        if row:
            external_ip = row[0]
    if not external_ip:
        _LOGGER.debug('Cannot get external IP for ' + env.host)
        external_ip = 'Unknown'
    return external_ip


def print_status_header(external_ip, server_status, host):
    print('Server Status:')
    print('\t%s(IP: %s, Roles: %s): %s' % (host, external_ip,
                                           ', '.join(get_roles_for(host)),
                                           is_server_up(server_status)))


@parallel
def collect_node_information():
    client = PrestoClient(get_coordinator_role()[0], env.user)
    with settings(hide('warnings')):
        error_message = check_presto_version()
    if error_message:
        external_ip = 'Unknown'
        is_running = False
    else:
        with settings(hide('warnings', 'aborts', 'stdout')):
            try:
                external_ip = get_ext_ip_of_node(client)
            except:
                external_ip = 'Unknown'
            try:
                is_running = service('status')
            except:
                is_running = False
    return external_ip, is_running, error_message


def get_status_from_coordinator():
    client = PrestoClient(get_coordinator_role()[0], env.user)
    try:
        coordinator_status = run_sql(client, SYSTEM_RUNTIME_NODES)
        connector_status = get_connector_info_from(client)
    except BaseException as e:
        # Just log errors that come from a missing port or anything else; if
        # we can't connect to the coordinator, we just want to print out a
        # minimal status anyway.
        _LOGGER.warn(e.message)
        coordinator_status = []
        connector_status = []

    with settings(hide('running')):
        node_information = execute(collect_node_information,
                                   hosts=get_host_list())

    for host in get_host_list():
        if isinstance(node_information[host], Exception):
            external_ip = 'Unknown'
            is_running = False
            error_message = node_information[host].message
        else:
            (external_ip, is_running, error_message) = node_information[host]

        print_status_header(external_ip, is_running, host)
        if error_message:
            print('\t' + error_message)
        elif not coordinator_status:
            print('\tNo information available: unable to query coordinator')
        elif not is_running:
            print('\tNo information available')
        else:
            version_string = get_presto_version()
            version = strip_tag(split_version(version_string))
            query, processor = NODE_INFO_PER_URI_SQL.for_version(version)
            # just get the node_info row for the host if server is up
            node_info_row = run_sql(client, query % external_ip)
            node_status = processor(node_info_row)
            if node_status:
                print_node_info(node_status, connector_status)
            else:
                print('\tNo information available: the coordinator has not yet'
                      ' discovered this node')


@task
@runs_once
@requires_config(StandaloneConfig)
@with_settings(hide('warnings'))
def status():
    """
    Print the status of presto in the cluster
    """
    get_status_from_coordinator()
