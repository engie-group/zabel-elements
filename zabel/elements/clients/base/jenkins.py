# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""CloudBeesJenkins.

A class wrapping CloudBeesJenkin APIs.

There can be as many CloudBeesJenkins instances as needed.

This module depends on the public **requests** library.  It also depends
on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.
"""

from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Union

from xml.etree import cElementTree as ET

import requests

from zabel.commons.exceptions import ApiError
from zabel.commons.sessions import prepare_session
from zabel.commons.utils import (
    api_call,
    dict_to_xml,
    ensure_instance,
    ensure_nonemptystring,
    ensure_noneorinstance,
    join_url,
    xml_to_dict,
)


########################################################################
########################################################################

# CloudBees Jenkins low-level api


class CloudBeesJenkins:
    """Mostly a Jenkins low-level API wrapper, but taking into account
    the presence of an Operations Center (i.e., when there are more than
    one Jenkins master).

    This library uses an Operations Center as its entry point.

    There are three levels of APIs:

    - the Operations Center level
    - the managed master level
    - anything below (project/subproject/...)

    It is up to the caller to ensure inter-level consistency while
    handling groups and roles.

    Item creations and handling functions make use of two functions
    provided by the _zabel.commons.utils_ module: `xml_to_dict` and
    `dict_to_xml`.

    Things to check: <https://github.com/cloudbees/jenkins-scripts>

    ```python
    >>> from zabel.elements.clients import Jenkins
    >>>
    >>> url = 'https://pse.example.com'
    >>> jenkins = Jenkins(url, user, token)
    >>> jenkins.list_oc_managedmasters()
    ```
    """

    def __init__(
        self,
        url: str,
        user: str,
        token: str,
        cookies: Optional[Dict[str, str]] = None,
        verify: bool = True,
    ) -> None:
        """Create a CloudBeesJenkins instance object.

        # Required parameters

        - url: a non-empty string, the URL of the top-level Jenkins
          Operations Center
        - user: a string, the account used to access the API
        - token: a string, the token used to access the API

        Sample `url` value:

        `'https://pse.example.com'`

        # Optional parameters

        - cookies: a dictionary or None (None by default)
        - verify: a boolean (True by default)

        `verify` can be set to False if disabling certificate checks for
        Jenkins communication is required.  Tons of warnings will occur
        if this is set to False.
        """
        ensure_nonemptystring('url')
        ensure_instance('user', str)
        ensure_instance('token', str)
        ensure_noneorinstance('cookies', dict)

        self.url = url
        self.auth = (user, token)
        self.cookies = cookies
        self.verify = verify
        self.crumb: Optional[Dict[str, str]] = None
        self.crumb_master: Optional[str] = None
        self._endpoints: Dict[str, str] = {}
        self.session = prepare_session(self.auth, self.cookies, verify=verify)

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {self.url!r}, {self.auth[0]!r}>'

    ####################################################################
    # cbj operations center global features
    #
    # list_oc_groups
    # list_oc_roles
    # list_oc_users
    # list_oc_managedmasters
    # list_oc_folders
    # get_oc_metrics
    # run_oc_script
    # get_version

    MM_CLASS = 'com.cloudbees.opscenter.server.model.ManagedMaster'
    CB_FOLDER = 'com.cloudbees.hudson.plugins.folder.Folder'

    @api_call
    def list_oc_groups(self) -> List[Dict[str, Any]]:
        """Return the Operations Center list of groups.

        # Returned value

        A list of _groups_.  Each group is a dictionary with the
        following entries:

        - description: a string
        - name: a string
        - url: a string
        - members: a list of strings
        - roles: a list of strings
        - roleAssignments: a list of dictionaries
        - users: a list of strings
        - groups: a list of strings
        """
        result = self._get_json(
            join_url(self.url, 'cjoc/groups'), params={'depth': '1'}
        )
        return result['groups']  # type: ignore

    @api_call
    def list_oc_roles(self) -> List[Dict[str, Any]]:
        """Return the Operations Center list of roles.

        # Returned value

        A list of _roles_.  Each role is a dictionary with the following
        entries:

        - description: a string
        - id: a string
        - filterable: a boolean
        - shortUrl: a string
        - grantedPermissions: a list of strings
        """
        result = self._get_json(
            join_url(self.url, 'cjoc/roles'), params={'depth': '1'}
        )
        return result['roles']  # type: ignore

    @api_call
    def _list_oc_users(self) -> List[Dict[str, Any]]:
        """Return the Operations Center list of known users.

        DEPRECATED - No longer used.

        # Returned value

        A list of u_sers_.  Each user is a dictionary with the following
        entries:

        - user: a dictionary
        - project: None or ...
        - lastChange: None or ...

        The dictionary in the `user` key has the following entries:

        - fullName: a string
        - absoluteUrl: a string
        """
        result = self._get_json(join_url(self.url, 'cjoc/asynchPeople'))
        return result['users']  # type: ignore

    @api_call
    def list_oc_managedmasters(self, depth: int = 0) -> List[Dict[str, Any]]:
        """Returns a list of all managed masters.

        This method retrieves all managed masters, irrespective of their
        locations on the Operations Center.

        # Optional parameters

        - depth: an integer (`0` by default)

        # Returned value

        A list of _managed masters_.  Managed masters in the list are
        dictionaries with the following entries, assuming the default
        value for `depth`:

        - _class: a string
        - name: a string
        - url: a string
        """
        ensure_instance('depth', int)

        result = self._get_json(
            join_url(self.url, 'cjoc/view/Controllers'),
            params={'depth': str(depth)},
        )
        return result['jobs']  # type: ignore

    @api_call
    def list_oc_folders(self) -> List[Dict[str, Any]]:
        """Return the Operations Center list of folders.

        # Returned value

        A list of _folders_.  Each folder is a dictionary with the
        following entries:

        - _class: a string
        - url: a string
        - name: a string

        Folders will have a `_class` value of:

        `'com.cloudbees.hudson.plugins.folder.Folder'`
        """
        response = self._get_json(join_url(self.url, 'cjoc'))
        return [
            job for job in response['jobs'] if job['_class'] == self.CB_FOLDER
        ]

    @api_call
    def get_oc_metrics(self) -> Dict[str, Any]:
        """Return the Operations Center metrics.

        More info on metrics is available here:

        - <https://wiki.jenkins.io/display/JENKINS/Metrics+Plugin>
        - <https://go.cloudbees.com/docs/cloudbees-documentation/cje-user-guide/index.html#monitoring>

        # Returned value

        A dictionary with the following entries:

        - version: a string
        - gauges: a dictionary
        - counters: a dictionary
        - histograms: a dictionary
        - meters: a dictionary
        - timers: a dictionary

        `gauges` is a dictionary with one entry per metric.  Each metric
        is a dictionary with one entry, `value`.

        `counters` is a dictionary with one entry per counter.  Each
        counter is a dictionary with one entry, `count`.
        """
        return self._get_json(
            join_url(self.url, 'cjoc/metrics/currentUser/metrics')
        )

    @api_call
    def run_oc_script(self, script: str) -> str:
        """Execute a groovy script on the Operations Center.

        # Required parameters

        - script: a non-empty string

        # Returned value

        A string (what was produced by running the script).  It is up to
        the caller to process this returned string.
        """
        ensure_nonemptystring('script')

        return self._post(
            join_url(join_url(self.url, 'cjoc'), 'scriptText'),
            data={'script': script},
        ).text

    @api_call
    def get_version(self, path: str = 'cjoc') -> str:
        """Return the Operations Center or managed master version.

        By default, looks for the Operations Center version.

        # Optional parameters

        - path: a string, where to look for managed master (`'cjoc'` by
          default)

        # Returned value

        A string.  For example, `'2.60.3.1'`.
        """
        ensure_nonemptystring('path')

        return (
            self.session().get(join_url(self.url, path)).headers['X-Jenkins']
        )

    ####################################################################
    # cbj managedmasters
    #
    # list_managedmasters
    # get_managedmaster_status
    # get_managedmaster_endpoint
    # list_managedmaster_projects
    # list_managedmaster_roles
    # list_managedmaster_users
    # list_managedmaster_plugins
    # install_managedmaster_plugins
    # provision_and_start_managedmaster
    # stop_managedmaster
    # acknowledge_managedmaster_error
    # get_managedmaster_metrics
    # ping_managedmaster
    # build_managedmaster_job
    # get_managedmaster_queueitem
    # get_managedmaster_buildinfo

    @api_call
    def list_managedmasters(self, path: str = 'cjoc') -> List[Dict[str, Any]]:
        """Return the list of managed masters.

        This method only retrieves managed masters that are at the
        highest level of the specified path.

        # Optional parameters

        - path: a string, where to look for managed masters (`cjoc` by
          default)

        # Returned value

        A list of _managed masters_.  Each managed master is a
        dictionary with at least 3 keys:

        - _class: a string
        - url: a string
        - name: a string

        Managed masters will have a _class value of:

        `'com.cloudbees.opscenter.server.model.ManagedMaster'`
        """
        ensure_nonemptystring('path')

        response = self._get_json(join_url(self.url, path))
        return [
            job for job in response['jobs'] if job['_class'] == self.MM_CLASS
        ]

    @api_call
    def get_managedmaster_status(
        self, managedmaster_url: str
    ) -> Dict[str, Any]:
        """Return the manager status.

        # Required parameters

        - managedmaster_url: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - _class: a string
        - actions: a list of dictionaries
        - approved: a boolean
        - description: a string
        - displayName: a string
        - displayNameOrNull: a string or None
        - endpoint: a string
        - fullDisplayName: a string (an URL)
        - fullName: a string
        - healthReport: a list of dictionaries
        - name: a string
        - online: a boolean
        - state: a string
        - url: a string (an URL)
        - validActions: a list of strings
        """
        ensure_nonemptystring('managedmaster_url')

        return self._get_json(managedmaster_url)

    def get_managedmaster_endpoint(self, managedmaster_url: str) -> str:
        """Return managedmaster endpoint.

        Endpoints are cached, as they do not change.

        # Required parameters

        - managedmaster_url: a non-empty string

        # Returned value

        A string, the endpoint (an URL).

        # Raised exceptions

        May raise an _ApiError_ exception if master is initializing.
        """
        ensure_nonemptystring('managedmaster_url')

        if managedmaster_url not in self._endpoints:
            endpoint = self._get_json(managedmaster_url)['endpoint']
            if not endpoint:
                raise ApiError(
                    'Endpoint not available for managed master %s'
                    % managedmaster_url
                )
            self._endpoints[managedmaster_url] = endpoint
        return self._endpoints[managedmaster_url]

    @api_call
    def list_managedmaster_projects(
        self, managedmaster_url: str
    ) -> List[Dict[str, Any]]:
        """Return the list of projects for the specified managed master.

        # Required parameters

        - managedmaster_url: a non-empty string

        # Returned value

        A list of _projects_.  Each project is a dictionary with the
        following entries:

        - _class: a string
        - name: a string
        - url: a string
        - color: a string

        The first three entries are always present.
        """
        ensure_nonemptystring('managedmaster_url')

        result = self._get_json(
            self.get_managedmaster_endpoint(managedmaster_url)
        )
        return result['jobs']  # type: ignore

    @api_call
    def list_managedmaster_roles(
        self, managedmaster_url: str
    ) -> List[Dict[str, Any]]:
        """Return the list of roles for the specified managed master.

        # Required parameters

        - managedmaster_url: a non-empty string

        # Returned value

        A list of _roles_.  Each role is a dictionary with the following
        entries:

        - description: a string
        - id: a string
        - filterable: a boolean
        - shortUrl: a string
        - grantedPermissions: a list of strings

        The returned roles are expanded.
        """
        ensure_nonemptystring('managedmaster_url')

        result = self._get_json(
            join_url(
                self.get_managedmaster_endpoint(managedmaster_url), 'roles'
            ),
            params={'depth': '1'},
        )
        return result['roles']  # type: ignore

    @api_call
    def list_managedmaster_users(
        self, managedmaster_url: str
    ) -> List[Dict[str, Any]]:
        """Return the list of users for the specified managed master.

        # Required parameters

        - managedmaster_url: a non-empty string

        # Returned value

        A list of _users_.  Each master user is a dictionary with the
        following entries:

        - project: a dictionary or None
        - user: a dictionary
        - lastChange: an integer or None

        If `project` is None (or if `lastChange` is None), no activity
        from this user has been recorded.

        The dictionary for the `user` key contains the following
        entries:

        - absoluteUrl: a string
        - fullName: a string
        """
        ensure_nonemptystring('managedmaster_url')

        result = self._get_json(
            join_url(
                self.get_managedmaster_endpoint(managedmaster_url),
                'asynchPeople',
            ),
            params={'depth': '1'},
        )
        return result['users']  # type: ignore

    @api_call
    def list_managedmaster_plugins(
        self, managedmaster_url: str
    ) -> List[Dict[str, Any]]:
        """Return the list of installed plugins.

        # Required parameters

        - managedmaster_url: a non-empty string

        # Returned value

        A list of _plugins_.  Each plugin is a dictionary with the
        following entries:

        - enabled: a boolean
        - supportsDynamicLoad: a string
        - requiredCoreVersion: a string
        - deleted: a boolean
        - bundled: a boolean
        - backupVersion:
        - longName: a string
        - active: a boolean
        - hasUpdate: a boolean
        - dependencies: a list of dictionaries
        - version: a string
        - pinned: a boolean
        - url: a string
        - downgradable: a boolean
        - shortName a string

        The `dependencies` dictionaries have the following entries:

        - optional: a boolean
        - shortName: a string
        - version: a string
        """
        ensure_nonemptystring('managedmaster_url')

        result = self._get_json(
            join_url(
                self.get_managedmaster_endpoint(managedmaster_url),
                'pluginManager',
            ),
            params={'depth': '2'},
        )
        return result['plugins']  # type: ignore

    @api_call
    def install_managedmaster_plugin(
        self, managedmaster_url: str, plugin: str
    ) -> bool:
        """Install the requested plugin.

        You may have to safe-restart the managed master after plugin
        installation.

        # Required parameters

        - managedmaster_url: a non-empty string
        - plugin: a non-empty string

        `plugin` is the plugin short name.

        # Returned value

        A boolean.  True if the installation was successful.
        """
        ensure_nonemptystring('managedmaster_url')
        ensure_nonemptystring('plugin')

        return (
            self._post(
                join_url(
                    self.get_managedmaster_endpoint(managedmaster_url),
                    'pluginManager/installNecessaryPlugins',
                ),
                # ???? add @latest or @current ?
                data=bytes(
                    '<jenkins><install plugin="{plugin}" /></jenkins>'.format(
                        plugin=plugin
                    ),
                    encoding='utf-8',
                ),
                headers={'Content-Type': 'application/xml'},
            ).status_code
            == 200
        )

    @api_call
    def provision_and_start_managedmaster(
        self, managedmaster_url: str
    ) -> None:
        """Provision and start managed master.

        # Required parameters

        - managedmaster_url: a non-empty string
        """
        ensure_nonemptystring('managedmaster_url')

        self._post(
            join_url(managedmaster_url, 'provisionAndStartAction'),
            data={"Submit": "Yes"},
        )

    @api_call
    def stop_managedmaster(self, managedmaster_url: str) -> bool:
        """Stop managed master.

        # Required parameters

        - managedmaster_url: a non-empty string

        # Returned value

        A boolean.  True if the command was successful.
        """
        ensure_nonemptystring('managedmaster_url')

        return (
            self._post(
                join_url(managedmaster_url, 'stopAction'),
                data={'Submit': 'Wait'},
            ).status_code
            == 200
        )

    @api_call
    def acknowledge_managedmaster_error(self, managedmaster_url: str) -> None:
        """Acknowledge error on managed master.

        # Required parameters

        - managedmaster_url: a non-empty string
        """
        ensure_nonemptystring('managedmaster_url')

        self._post(
            join_url(managedmaster_url, 'acknowledgeErrorAction'),
            data={"Submit": "Yes"},
        )

    @api_call
    def get_managedmaster_metrics(
        self, managedmaster_url: str
    ) -> Dict[str, Any]:
        """Return managed master metrics.

        # Required parameters

        - managedmaster_url: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - version: a string
        - gauges: a dictionary
        - counters: a dictionary
        - histograms: a dictionary
        - meters: a dictionary
        - timers: a dictionary

        `gauges` is a dictionary with one entry per metric.  Each metric
        is a dictionary with one entry, `value`.

        `counters` is a dictionary with one entry per counter.  Each
        counter is a dictionary with one entry, `count`.

        More info on metrics is available here:

        - <https://wiki.jenkins.io/display/JENKINS/Metrics+Plugin>
        - <https://go.cloudbees.com/docs/cloudbees-documentation/cje-user-guide/index.html#monitoring>
        """
        ensure_nonemptystring('managedmaster_url')

        return self._get_json(
            join_url(
                self.get_managedmaster_endpoint(managedmaster_url),
                'metrics/currentUser/metrics',
            )
        )

    @api_call
    def run_managedmaster_script(
        self, managedmaster_url: str, script: str
    ) -> str:
        """Execute a groovy script on the managed master.

        # Required parameters

        - managedmaster_url: a non-empty string
        - script: a non-empty string

        # Returned value

        A string (what was produced by running the script).  It
        is up to the caller to process this returned string.
        """
        ensure_nonemptystring('managedmaster_url')
        ensure_nonemptystring('script')

        return self._post(
            join_url(
                self.get_managedmaster_endpoint(managedmaster_url),
                'scriptText',
            ),
            data={'script': script},
        ).text

    @api_call
    def ping_managedmaster(
        self, managedmaster_url: str, path: str = ''
    ) -> bool:
        """Check if managed master is fully up and running.

        # Required parameters

        - managedmaster_url: a non-empty string

        # Optional parameters

        - path: a string (empty by default)

        # Returned value

        A boolean.  True if the managed master is fully up and running,
        False otherwise.
        """
        ensure_nonemptystring('managedmaster_url')
        ensure_instance('path', str)

        return (
            self.session()
            .get(
                join_url(
                    self.get_managedmaster_endpoint(managedmaster_url), path
                )
            )
            .status_code
            == 200
        )

    @api_call
    def build_managedmaster_job(
        self,
        managedmaster_url: str,
        path: str,
        params: Optional[Mapping[str, str]] = None,
    ) -> int:
        """Build job.

        # Required parameters

        - managedmaster_url: a non-empty string
        - path: a non-empty string

        # Optional parameters

        - params: a dictionary or None (None by default)

        # Returned value

        An integer, the _queueitem_ number.  This queueitem number is
        only valid for about five minutes after the job completes.

        Use #get_managedmaster_queueitem() for more details on job
        execution.
        """
        ensure_nonemptystring('managedmaster_url')
        ensure_nonemptystring('path')
        ensure_noneorinstance('params', dict)

        return int(
            self._post(
                join_url(
                    join_url(
                        self.get_managedmaster_endpoint(managedmaster_url),
                        path,
                    ),
                    'build',
                ),
                params=params,
            )
            .headers['location']
            .strip('/')
            .split('/')[-1]
        )

    @api_call
    def get_managedmaster_queueitem(
        self, managedmaster_url: str, queueitem: int
    ) -> Dict[str, Any]:
        """Get queueitem info.

        # Required parameters

        - managedmaster_url: a non-empty string
        - queueitem: an integer

        # Returned value

        A dictionary with the following entries:

        - _class: a string
        - actions: a list of dictionaries
        - blocked: a boolean
        - buildable: a boolean
        - cancelled: a boolean
        - executable: a dictionary or None
        - id: an integer
        - inQueueSince: an integer (a timestamp)
        - params: a string
        - stuck: a boolean
        - task: a dictionary
        - url: a string
        - why: a dictionary or None

        If the queueitem is still waiting for an executor, the `why`
        entry will not be None.

        One the queueitem is running (or has completed), `executable`
        will hold information on the corresponding build.

        The `executable` entry, if not None, has the following entries:

        - _class: a string
        - number: an integer
        - url: a string
        """
        ensure_nonemptystring('managedmaster_url')
        ensure_instance('queueitem', int)

        return self._get_json(
            join_url(
                self.get_managedmaster_endpoint(managedmaster_url),
                f'queue/item/{queueitem}',
            )
        )

    @api_call
    def get_managedmaster_buildinfo(
        self, managedmaster_url: str, path: str, number: int
    ) -> Dict[str, Any]:
        """Get build info.

        # Required parameters

        - managedmaster_url: a non-empty string
        - path: a non-empty string
        - number: an integer

        # Returned value

        A dictionary with the following entries:

        - _class: a string
        - actions: a list of dictionaries
        - artifacts: a list
        - building: a boolean
        - changeSets: a list
        - culprits: a list
        - description: a string or None
        - displayName: a string
        - duration: an integer
        - estimatedDuration: an integer
        - executor: None or ...
        - fullDisplayName: a string
        - id: a string
        - keepLog: a boolean
        - nextBuild: a dictionary or None
        - number: an integer
        - previousBuild: a dictionary or None
        - queueId: an integer
        - result: a string or None
        - timestamp: an integer (a timestamp)
        - url: a string
        """
        ensure_nonemptystring('managedmaster_url')
        ensure_nonemptystring('path')
        ensure_instance('number', int)

        return self._get_json(
            join_url(
                join_url(
                    self.get_managedmaster_endpoint(managedmaster_url), path
                ),
                str(number),
            )
        )

    ####################################################################
    # cbj projects
    #
    # list_project_jobs
    # create_project_job
    # list_project_roles
    # add_project_role_filter
    # list_project_groups
    # create_project_group
    # grant_project_group_role
    # get_project_domains
    # create_project_domain
    # list_domain_credentials
    # create_domain_credential
    # delete_domain_credential
    # add_group_user
    # delete_group_user

    @api_call
    def list_project_jobs(self, project_url: str) -> List[Dict[str, Any]]:
        """Return the list of jobs that are direct children of project.

        # Required parameters

        - project_url: a non-empty string

        # Returned value

        A list of _jobs_.  Each job is a dictionary with at least 3
        keys:

        - _class: a string
        - url: a string
        - name: a string

        If a job class is
        `'com.cloudbees.hudson.plugins.folder.Folder'`, it means it is
        a sub-project, and it may contains other jobs.

        # Raised exceptions

        If the specified project is not a folder, an _ApiError_ is
        raised.
        """
        ensure_nonemptystring('project_url')

        return self._get_json(project_url)['jobs']  # type: ignore

    @api_call
    def create_project_job(
        self,
        project_url: str,
        job_name: str,
        config: Union[str, Dict[str, Any]],
    ) -> None:
        """Create a job in project.

        The project must already exists.

        # Required parameters

        - project_url: a non-empty string
        - job_name: a non-empty string
        - config: an XML dict or an XML string

        The `config` dictionary must follow the 'XML' dictionary
        conventions.

        # Returned value

        None.

        # Raised exceptions

        An _ApiError_ exception is raised if a job or folder with the
        specified name already exists.
        """
        ensure_nonemptystring('project_url')
        ensure_nonemptystring('job_name')
        ensure_instance('config', (str, dict))

        if isinstance(config, str):
            data = config.strip()
        else:
            data = '<?xml version="1.0" encoding="UTF-8"?>' + dict_to_xml(
                config
            )

        result = self._post(
            join_url(project_url, f'createItem?name={job_name}'),
            data=bytes(data, encoding='utf-8'),
            headers={'Content-Type': 'application/xml'},
        )
        return result  # type: ignore

    @api_call
    def list_project_roles(self, project_url: str) -> List[Dict[str, Any]]:
        """Return the list of roles for the specified project.

        # Required parameters

        - project_url: a string

        # Returned value

        A list of _roles_.  Each role is a dictionary with the following
        entries:

        - description: a string
        - id: a string
        - filterable: a boolean
        - shortUrl: a string
        - grantedPermissions: a list of strings

        The returned roles are expanded.
        """
        ensure_nonemptystring('project_url')

        result = self._get_json(
            join_url(project_url, 'roles'), params={'depth': '1'}
        )
        return result['roles']  # type: ignore

    @api_call
    def create_project_group(self, project_url: str, group: str) -> None:
        """Create a group in project.

        The project must already exist.

        # Required parameters

        - project_url: a non-empty string
        - group: a non-empty string

        # Returned value

        None.
        """
        ensure_nonemptystring('project_url')
        ensure_nonemptystring('group')

        result = self._post(
            join_url(project_url, f'groups/createGroup?name={group}')
        )
        return result  # type: ignore

    @api_call
    def grant_project_group_role(
        self,
        project_url: str,
        group: str,
        role: str,
        offset: int = 0,
        inherited: Optional[bool] = False,
    ) -> None:
        """Grant a role to group in project.

        The project and group must already exist.

        # Required parameters

        - project_url: a non-empty string
        - group: a non-empty string
        - role: a non-empty string

        # Returned value

        None.
        """
        ensure_nonemptystring('project_url')
        ensure_nonemptystring('group')
        ensure_nonemptystring('role')
        ensure_instance('offset', int)
        ensure_noneorinstance('inherited', bool)

        result = self._post(
            join_url(
                project_url,
                f'groups/{group}/grantRole?role={role}&offset={offset}&inherited={inherited is True}',
            )
        )
        return result  # type: ignore

    @api_call
    def add_project_role_filter(self, project_url: str, role: str) -> None:
        """Add role filter to project.

        # Required parameters

        - project_url: a non-empty string
        - role: a non-empty string

        # Returned value

        None.
        """
        ensure_nonemptystring('project_url')
        ensure_nonemptystring('role')

        result = self._post(
            join_url(project_url, f'groups/addRoleFilter?name={role}')
        )
        return result  # type: ignore

    @api_call
    def list_project_groups(self, project_url: str) -> List[Dict[str, Any]]:
        """Return the list of groups for the specified project.

        # Required parameters

        - project_url: a non-empty string

        # Returned value

        A list of _groups_.  Each group is a dictionary with the
        following entries:

        - description: a string
        - name: a string
        - url: a string
        - members: a list of strings
        - roles: a list of strings
        - roleAssignments: a list of dictionaries
        - users: a list of strings
        - groups: a list of strings

        The returned groups are expanded.
        """
        ensure_nonemptystring('project_url')

        result = self._get_json(
            join_url(project_url, 'groups'), params={'depth': '1'}
        )
        return result['groups']  # type: ignore

    @api_call
    def get_project_domains(
        self, project_url: str
    ) -> Dict[str, Dict[str, Any]]:
        """Return the domains for the specified project.

        # Required parameters

        - project_url: a non-empty string

        # Returned value

        A dictionary with the following possible entries:

        - system: a dictionary
        - folder: a dictionary

        Some entries may be missing.

        The `system` and `folder` dictionaries have the same format.
        They contain the following entries:

        - _class: a string
        - domains: a dictionary

        Each entry in the `domains` dictionary is a domain. The key is
        the domain name, and the value is a dictionary with a `_class`
        entry.

        The `'_'` domain is the default domain.
        """
        ensure_nonemptystring('project_url')

        result = self._get_json(
            join_url(project_url, 'credentials'), params={'depth': '1'}
        )
        return result['stores']  # type: ignore

    @api_call
    def create_project_domain(
        self, project_url: str, config: str, system: bool = False
    ) -> None:
        """Create new domain for project.

        # Required parameters

        - project_url: a non-empty string
        - config: a non-empty 'XML' string

        # Optional parameters

        - system: a boolean (False by default)

        Non-system domains are located in the 'folder' store.  System
        domains are located in the 'system' store.

        # Returned value

        None.

        # Raised exceptions

        An _ApiError_ exception is raised if the domain already exists.
        """
        ensure_nonemptystring('project_url')
        ensure_instance('config', str)
        ensure_instance('system', bool)

        store = 'system' if system else 'folder'
        data = config.strip()

        result = self._post(
            join_url(project_url, f'/credentials/store/{store}/createDomain'),
            data=bytes(data, encoding='utf-8'),
            headers={'Content-Type': 'application/xml'},
        )
        return result  # type: ignore

    @api_call
    def list_domain_credentials(self, domain_url: str) -> List[Dict[str, Any]]:
        """Return the list of credentials for domain.

        # Required parameters

        - domain_url: a non-empty string

        # Returned value

        A list of _credentials_.  A credential is a dictionary with the
        following entries:

        - id: a string, the credential id
        - displayName: a string
        - typeName: a string
        - description: a string
        - fingerprint: ?
        - fullname: a string

        Credentials as returned by this function contain no sensible
        items (passwords, secret files, private keys, ...)
        """
        ensure_nonemptystring('domain_url')

        result = self._get_json(domain_url, params={'depth': '2'})
        return result['credentials']  # type: ignore

    @api_call
    def get_domain_credential(
        self, domain_url: str, credential_id: str
    ) -> str:
        """Get credential configuration.

        # Required parameters

        - domain_url: a non-empty string
        - credential_id: a non-empty string

        # Returned value

        A string, the XML configuration element.  Refer to
        #create_domain_credential() for more details on this value.

        Secrets in the returned value, if any, will be redacted.
        """
        ensure_nonemptystring('domain_url')
        ensure_nonemptystring('credential_id')

        return (
            self.session()
            .get(
                join_url(domain_url, f'credential/{credential_id}/config.xml')
            )
            .text
        )

    @api_call
    def create_domain_credential(self, domain_url: str, config: str) -> None:
        """Create a credential in a domain.

        The domain must already exists.

        It may be used to add credentials to a credentials folder.

        # Required parameters

        - domain_url: a non-empty string
        - config: an 'XML' string

        `domain_url` is something like:

        ```
        'https://jenkins.example.com/FOO/job/Bar/credentials/store/folder/domain/Test'
        ```

        `config` is something like:

        ```xml
        <?xml version="1.0"?>
        <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl
          plugin="credentials@2.1.13">
         <id>ML</id>
         <description>my creds</description>
         <username>me</username>
         <password>
           foobar
         </password>
        </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
        ```

        TODO: check password validity (spaces striped? ...)

        # Returned value

        None.

        # Raised exceptions

        An _ApiError_ exception is raised if the credentials already
        exists.
        """
        ensure_nonemptystring('domain_url')
        ensure_instance('config', str)

        result = self._post(
            join_url(domain_url, 'createCredentials'),
            data=bytes(config.strip(), encoding='utf-8'),
            headers={'Content-Type': 'application/xml'},
        )
        return result  # type: ignore

    @api_call
    def delete_domain_credential(
        self, domain_url: str, credential_id: str
    ) -> bool:
        """Delete a credential in a domain.

        # Required parameters

        - domain_url: a non-empty string
        - credential_id: a non-empty string

        # Returned value

        A boolean.  True if successful.
        """
        ensure_nonemptystring('domain_url')
        ensure_nonemptystring('credential_id')

        return self.delete_item(
            join_url(domain_url, f'credential/{credential_id}')
        )

    @api_call
    def add_group_user(self, group_url: str, user: str) -> None:
        """Add user to group.

        # Required parameters

        - group_url: a non-empty string
        - user: a non-empty string

        May not be the cleanest way to do it (using a form action).
        """
        ensure_nonemptystring('group_url')
        ensure_nonemptystring('user')

        self._post(join_url(group_url, 'submitNewUser'), data={'user': user})

    @api_call
    def delete_group_user(self, group_url: str, user: str) -> None:
        """Delete user from group.

        # Requirement parameters

        - group_url: a non-empty string
        - user: a non-empty string

        May not be the cleanest way to do it (using a form action).
        """

        ensure_nonemptystring('group_url')
        ensure_nonemptystring('user')

        self._post(
            join_url(group_url, 'submitRemoveMember'),
            params={'member': user, 'type': 'USER'},
        )

    @api_call
    def migrate_group_member_as_user(self, group_url: str, user: str) -> None:
        """Migrate member of group as user

        # Requirement parameters

        - group_url: a non-empty string
        - user: a non-empty string
        """

        ensure_nonemptystring('group_url')
        ensure_nonemptystring('user')

        self._post(
            join_url(group_url, 'submitMigrateMember'),
            params={'member': user, 'as': 'user'},
        )

    ####################################################################
    # cbj items
    #
    # get_item_configuration (/config.xml)
    # update_item_configuration (post config.xml)
    # delete_item (/doDelete)
    # TODO rename_item (/doRename)
    # TODO disable_item (/disable)
    # TODO enable_item (/enable)

    @api_call
    def get_item_configuration(self, url: str) -> Dict[str, Any]:
        """Return an 'XML' dictionary containing the item configuration.

        # Required parameters

        - url: a non-empty string, the item url

        # Returned value

        A dictionary that follows the 'XML' dictionary conventions.
        """
        ensure_nonemptystring('url')

        return xml_to_dict(
            ET.XML(self.session().get(join_url(url, 'config.xml')).text)
        )

    @api_call
    def update_item_configuration(
        self, url: str, config: Dict[str, Any]
    ) -> None:
        """Update item configuration.

        # Required parameters

        - url: a non-empty string, the item url
        - config: an 'XML' dictionary
        """
        ensure_nonemptystring('url')
        ensure_instance('config', dict)

        result = self._post(
            join_url(url, 'config.xml'),
            data=bytes(dict_to_xml(config), encoding='utf-8'),
        )
        return result  # type: ignore

    @api_call
    def delete_item(
        self,
        url: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> bool:
        """Delete item.

        # Required parameters

        - url: a non-empty string

        # Returned value

        A boolean.  True if successful.

        # Raised exceptions

        Raises an _ApiError_ exception otherwise.
        """
        ensure_nonemptystring('url')

        result = self._post(join_url(url, 'doDelete'), params=params)
        return result.status_code == 200

    ####################################################################
    # cbj helpers

    def _get(
        self,
        api_url: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> Dict[str, Any]:
        """Returns cloudbeesjenkins api call results.

        # Required parameters

        - api_url: a non-empty string (an URL)

        # Optional parameters

        - params: a dictionary
        """
        return self.session().get(api_url, params=params)

    def _get_json(
        self,
        api_url: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> Dict[str, Any]:
        """Returns cloudbeesjenkins api call results.

        # Required parameters

        - api_url: a non-empty string (an URL)

        # Optional parameters

        - params: a dictionary
        """
        result = (
            self.session()
            .get(join_url(api_url, 'api/json'), params=params)
            .json()
        )
        return result  # type: ignore

    def _post(
        self,
        api_url: str,
        data: Optional[Union[MutableMapping[str, str], bytes]] = None,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        files: Optional[Mapping[str, Any]] = None,
    ) -> requests.Response:
        master = self._extract_master(api_url)
        if self.crumb is None or self.crumb_master != master:
            self.crumb_master = master
            self._initialize_crumb_data()
        _headers = dict(headers or {})
        if self.crumb is not None:
            _headers[self.crumb['crumbRequestField']] = self.crumb['crumb']

        result = self.session().post(
            api_url, data=data, headers=_headers, params=params, files=files
        )
        if result.status_code == 403:
            print('DEBUG: 403 403 403 403 403')
            print('DEBUG: crumb:', self.crumb, '.')
            print('DEBUG: crumb_master:', self.crumb_master, '.')
            print('DEBUG: master:', master, '.')
            print('DEBUG: api_url:', api_url, '.')
            print('DEBUG: headers:', headers, '.')
        return result

    # crumbs helpers

    def _extract_master(self, url: str) -> str:
        # the operations center does not support crumbs. we have to
        # get a crumb from the "right" managed instance
        # ?? url = re.match('https://[^/]+/(\w+).*', url).group(1)
        master = url[len(self.url) + 1 :]
        master = master[: master.find('/')]
        return master

    def _initialize_crumb_data(self) -> None:
        try:
            if self.crumb_master is None:
                raise ApiError('crumb_master is None.')
            self.crumb = (
                self.session()
                .get(
                    join_url(
                        join_url(self.url, self.crumb_master),
                        'crumbIssuer/api/json',
                    ),
                )
                .json()
            )
        except Exception:
            self.crumb = None
