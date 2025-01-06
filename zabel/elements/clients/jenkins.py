# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""CloudBeesJenkins.

A class wrapping CloudBeesJenkins APIs.

There can be as many CloudBeesJenkins instances as needed.

This module depends on the #::.base.jenkins module.
"""

from typing import Any, Dict, Iterable, List

from time import sleep, time

import re

from zabel.commons.exceptions import ApiError
from zabel.commons.utils import (
    api_call,
    ensure_instance,
    ensure_nonemptystring,
    join_url,
)

from .base.jenkins import CloudBeesJenkins as Base


CREDENTIAL_UP_CONFIG_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl
  plugin="credentials">
 <id>{id}</id>
 <description>{description}</description>
 <username>{username}</username>
 <password>{password}</password>
</com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
'''

CREDENTIAL_AC_CONFIG_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<com.cloudbees.jenkins.plugins.awscredentials.AWSCredentialsImpl
   plugin="aws-credentials">
 <scope>GLOBAL</scope>
 <id>{id}</id>
 <description>{description}</description>
 <accessKey>{accesskey}</accessKey>
 <secretKey>{secretkey}</secretKey>
 <iamRoleArn/>
 <iamMfaSerialNumber/>
 <!-- EXTRA -->
</com.cloudbees.jenkins.plugins.awscredentials.AWSCredentialsImpl>
'''

CREDENTIAL_ST_CONFIG_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl
  plugin="plain-credentials">
<id>{id}</id>
<description>{description}</description>
<secret>{text}</secret>
</org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
'''

# curl -X POST \
# https://jenkins.local/job/TEAM-FOLDER/credentials/store/folder/domain/
# _/createCredentials \
# -F secret=@/Users/maksym/secret \
# -F 'json={"": "4",
#           "credentials": {
#               "file": "secret",
#               "id": "test",
#               "description": "HELLO-curl",
#               "stapler-class":
#  "org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl",
#               "$class":
#  "org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl"
#           }
#          }'

# >>> files = {'upload_file': open('file.txt','rb')}
# >>> values = {'DB': 'photcat', 'OUT': 'csv', 'SHORT': 'short'}
# >>>
# >>> r = requests.post(url, files=files, data=values)

CREDENTIAL_FC_CONFIG_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl
   plugin="plain-credentials@1.4">
 <id>{id}</id>
 <description>{description}</description>
 <fileName>{filename}</fileName>
 <secretBytes>
  <secret-redacted/>
 </secretBytes>
</org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl>
'''

PIPELINETRIGGERSJOBPROPERTY = (
    'org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty'
)


class CloudBeesJenkins(Base):
    """CloudBeesJenkins Low-Level Wrapper.

    There can be as many CloudBeesJenkins instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel-commons**
    modules, #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    # Description

    Mostly a Jenkins low-level API wrapper, but taking into account
    the presence of an Operations Center (i.e., when there are more than
    one Jenkins master).

    This class uses an Operations Center as its entry point.

    There are three levels of APIs:

    - the Operations Center level
    - the managed master level
    - anything below (project/subproject/...)

    It is up to the caller to ensure inter-level consistency while
    handling groups and roles.

    Item creations and handling functions make use of two functions
    provided by the #::commons.utils module,
    #::commons.utils#dict_to_xml() and #::commons.utils#xml_to_dict().

    Things to check: <https://github.com/cloudbees/jenkins-scripts>

    # Implemented features

    - buildinfos
    - credentials
    - domains
    - folders
    - groups
    - items
    - jobs
    - managedmasters
    - metrics
    - plugins
    - projects
    - roles
    - scripts
    - users
    - misc. operations (status, ping, version, ...)

    # Sample use

    ```python
    from zabel.elements.clients import CloudBeesJenkins

    url = 'https://pse.example.com'
    jenkins = CloudBeesJenkins(url, user, token)
    jenkins.list_oc_managedmasters()
    ```

    # Attributes

    This class exposes templates that can be used while creating
    domains and credentials.  The credentials attributes all have
    an `id` and `description` parameters.

    | Attribute                       | Description                    |
    | ------------------------------- | ------------------------------ |
    | `DOMAIN_CONFIG_TEMPLATE`        | A template for credentials
                                        domains, with one parameter,
                                        `domain`, that can be used when
                                        calling `create_project_domain`
                                        method.                        |
    | `CREDENTIAL_CONFIG_TEMPLATES`   | A dictionary of templates for
                                        Jenkins credentials that can
                                        be used when calling the
                                        `create_domain_credential`
                                        method.  They have two common
                                        parameters, `id` and
                                        `description`.<br/>
                                        The following templates are
                                        available:<br/>
                                        - `'AC'`: AWS access key /
                                        secret key credentials.
                                        It has two parameters in
                                        addition to `id` and
                                        `description`, `accesskey` and
                                        `secretkey`.<br/>
                                        - `'FC'`: file credentials.
                                        It has one parameter in
                                        addition to `id` and
                                        `description`, `filename`.<br/>
                                        - `'ST'`: secret text
                                        credentials.
                                        It has one parameter in
                                        addition to `id` and
                                        `description`, `text`.<br/>
                                        - `'UP'`: user / password
                                        credentials.
                                        It has two parameters in
                                        addition to `id` and
                                        `description`, `user` and
                                        `password`.                    |
    """

    @api_call
    def update_item_crontab(self, url: str, crontab: str) -> None:
        """Update item crontab.

        # Required parameters

        - url: a non-empty string, the item url
        - crontab: a possibly empty string, the new item crontab
        """
        ensure_nonemptystring('url')
        ensure_instance('crontab', str)

        configuration = self.get_item_configuration(url)
        properties = [
            x['properties']
            for x in configuration['flow-definition']
            if 'properties' in x
        ][0]
        triggers = [
            x[PIPELINETRIGGERSJOBPROPERTY]
            for x in properties
            if PIPELINETRIGGERSJOBPROPERTY in x
        ][0]
        triggers[0]['triggers'][0]['hudson.triggers.TimerTrigger'][0][
            'element text'
        ] = crontab
        self.update_item_configuration(url, configuration)

    @api_call
    def install_managedmaster_plugins(
        self, managedmaster_url: str, plugins: Iterable[str]
    ) -> None:
        """Install the requested plugins.

        # Required parameters

        - managedmaster_url: a non-empty string
        - plugins: a list of non-empty strings

        Items in `plugins` are plugin short names.

        # Returned value

        Returns None.
        """
        ensure_nonemptystring('managedmaster_url')

        for plugin in plugins:
            self.install_managedmaster_plugin(managedmaster_url, plugin)

    @api_call
    def install_managedmaster_plugin_fromfile(
        self, managedmaster_url: str, plugin_url: str
    ) -> bool:
        """Install a specific plugin.

        # Required parameters

        - managedmaster_url: a non-empty string
        - plugin_url: a non-empty string

        # Returned value

        A boolean.  True if successful.
        """
        ensure_nonemptystring('managedmaster_url')
        ensure_nonemptystring('plugin_url')

        with open(plugin_url, 'rb') as plugin:
            files = {'plugin.hpi': plugin.read()}
        return (
            self._post(
                join_url(
                    self.get_managedmaster_endpoint(managedmaster_url),
                    'pluginManager/uploadPlugin',
                ),
                files=files,
            ).status_code
            == 200
        )

    @api_call
    def restart_managedmaster(
        self, managedmaster_url: str, force: bool = False
    ) -> str:
        """Restart managed master.

        Perform a safe restart unless the `force` parameter is set to
        True.

        # Required parameters

        - managedmaster_url: a non-empty string

        # Optional parameters

        - force: a boolean (False by default)
        """
        ensure_nonemptystring('managedmaster_url')
        ensure_instance('force', bool)

        call = 'restart' if force else 'doSafeRestart'
        return self.run_managedmaster_script(
            managedmaster_url, f'Jenkins.getInstance().{call}()'
        )

    @api_call
    def await_managedmaster(
        self, managedmaster_url: str, time_out: int = 120, path: str = ''
    ) -> None:
        """Awaits for managed master readiness.

        # Required parameters

        - managedmaster_url: a non-empty string

        # Optional parameters

        - time_out: an integer (120 by default)
        - path: a string (empty by default)

        `time_out` is in seconds.

        It will check managed master readiness at least once, even if
        `time_out` is set to 0.

        If the managed master is not ready after `time_out` seconds,
        an _ApiError_ ('Timeout exhausted, managed master not ready')
        exception is raised.
        """
        ensure_nonemptystring('managedmaster_url')
        ensure_instance('time_out', int)
        ensure_instance('path', str)

        start = time()
        while True:
            try:
                if self.ping_managedmaster(managedmaster_url, path):
                    return
            except ApiError:
                pass
            if (time() - start) > time_out:
                raise ApiError('Timeout exhausted, managed master not ready')
            sleep(2)

    ####################################################################
    # cbj managedmasters
    #
    # list_managedmaster_groups

    @api_call
    def list_managedmaster_groups(
        self, managedmaster_url: str
    ) -> List[Dict[str, Any]]:
        """Return the list of groups for the specified managed master.

        !!! important
            Not using the managed master endpoint here, as it's not
            what is used, at least with CloudBees Jenkins.

        # Required parameters

        - managedmaster_url: a non-empty string

        # Returned value

        A list of _groups_.  Each group is a dictionary with the
        following entries:

        - description: a string
        - name: a string
        - url: a string
        - members: a list of strings
        - roles: a list of strings
        - roleAssignments: a list of dictionaries

        The returned groups are expanded.
        """
        ensure_nonemptystring('managedmaster_url')

        return self._get_json(
            join_url(managedmaster_url, 'groups'), params={'depth': 1}
        )['groups']

    ####################################################################
    # users
    #
    # delete_user

    @api_call
    def list_oc_users(self) -> List[Dict[str, Any]]:
        """Return the Operations Center list of known users.

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
        groups = self.list_oc_groups()
        users = []
        for group in groups:
            users.extend(group['users'])
        return [
            {'user': {'absoluteUrl': join_url(self.url, f'cjoc/user/{u}')}}
            for u in users
        ]

    @api_call
    def delete_oc_user(self, user_id: str) -> None:
        """Delete an user in the cjoc

        # Required parameters

        - user_id: a non-empty string
        """

        ensure_nonemptystring('user_id')

        response = self._get(join_url(self.url, f'cjoc/user/{user_id}/delete'))
        re_match = re.search(r'data-crumb-value="(\w+)"', response.text)

        if not re_match:
            raise ValueError(
                f"Couldn't get required Jenkins-Crumb for user {user_id}"
            )

        jenkins_crumb = re_match.group(1)
        self.delete_item(
            join_url(self.url, f'cjoc/user/{user_id}'),
            params={'Jenkins-Crumb': jenkins_crumb},
        )

    ####################################################################
    # credentials templates

    DOMAIN_CONFIG_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
    <com.cloudbees.plugins.credentials.domains.Domain plugin="credentials">
    <name>{domain}</name>
    <specifications/>
    </com.cloudbees.plugins.credentials.domains.Domain>'''

    CREDENTIAL_CONFIG_TEMPLATES = {
        'UP': CREDENTIAL_UP_CONFIG_TEMPLATE,
        'AC': CREDENTIAL_AC_CONFIG_TEMPLATE,
        'ST': CREDENTIAL_ST_CONFIG_TEMPLATE,
        'CF': CREDENTIAL_FC_CONFIG_TEMPLATE,
    }
