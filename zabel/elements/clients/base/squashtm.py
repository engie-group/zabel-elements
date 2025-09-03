# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com) and others
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""SquashTM.

A base class wrapping Squash-TM APIs.

There can be as many SquashTM instances as needed.

This module depends on the **requests** public library.  It also depends
on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.

A base class wrapper only implements 'simple' API requests.  It handles
pagination if appropriate, but does not process the results or compose
API requests.
"""

from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

import requests

from zabel.commons.exceptions import ApiError
from zabel.commons.sessions import prepare_session
from zabel.commons.utils import (
    api_call,
    add_if_specified,
    ensure_in,
    ensure_instance,
    ensure_noneorinstance,
    ensure_nonemptystring,
    ensure_noneornonemptystring,
    join_url,
    BearerAuth,
)

########################################################################
########################################################################

# SquashTM low-level api

PROJECT_PERMISSIONS = [
    'validator',
    'project_viewer',
    'advanced_tester',
    'project_manager',
    'test_designer',
    'test_runner',
    'test_editor',
]


class SquashTM:
    """SquashTM Low-Level Wrapper.

    There can be as many SquashTM instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    ## Reference URLs

    - <https://www.squashtest.org/fr/actualites/faq-squash-tm/fonctionnalites/api-squash-tm-documentation>
    - <https://squash-tm.tools.digital.engie.com/squash/api/rest/latest/docs/api-documentation.html>

    ## Implemented features

    - campaigns (read-only)
    - executions (read-only)
    - iterations (read-only)
    - projects
    - requirements (read-only)
    - teams
    - testcasefolders (read-only)
    - testcases (read-only)
    - teststeps (read-only)
    - testsuites (read-only)
    - users

    ## Examples

    ```python
    from zabel.elements.clients import SquashTM

    url = 'https://squash-tm.example.com/squash/api/rest/latest/'
    user = '...'
    token = '...'
    tm = SquashTM(url, basic_auth=(user, token))
    tm.list_projects()
    ```
    """

    def __init__(
        self,
        url: str,
        user: Optional[str] = None,
        token: Optional[str] = None,
        *,
        basic_auth: Optional[Tuple[str, str]] = None,
        bearer_auth: Optional[str] = None,
        verify: bool = True,
    ) -> None:
        """Create a SquashTM instance object.

        You can only specify either `basic_auth` or `bearer_auth`.

        The `user` and `token` parameters are deprecated.
        Use `basic_auth` instead.

        # Required parameters

        - url: a non-empty string
        - user: __deprecated__ a string or None (None by default)
        - token: __deprecated__ a string or None (None by default)
        - basic_auth: a tuple of two strings (user, token) or None
        - bearer_auth: a string or None

        # Optional parameters

        - verify: a boolean (True by default)

        # Usage

        The `url` parameter is the top-level API point.  For example:

            'https://squash-tm.example.com/squash/api/rest/latest'

        `verify` can be set to False if disabling certificate checks for
        SquashTM communication is required.  Tons of warnings will occur
        if this is set to False.
        """
        ensure_nonemptystring('url')
        ensure_noneornonemptystring('user')
        ensure_noneornonemptystring('token')
        ensure_noneornonemptystring('bearer_auth')
        ensure_noneorinstance('basic_auth', tuple)
        ensure_instance('verify', bool)

        if basic_auth and bearer_auth:
            raise ValueError(
                'You can only specify either basic_auth or bearer_auth.'
            )
        if (user or token) and (basic_auth or bearer_auth):
            raise ValueError(
                'You can only specify either basic_auth or bearer_auth, and you should not use user and/or token.'
            )

        self.url = url
        if user:
            self.auth = (user, token)
        elif basic_auth:
            self.auth = basic_auth
        else:
            self.auth = BearerAuth(bearer_auth)
        self.verify = verify
        self.session = prepare_session(self.auth, verify=verify)

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {self.url!r}, {self.auth[0]!r}>'

    ####################################################################
    # squash-tm projects
    #
    # list_projects
    # get_project
    # create_project
    # delete_project
    # get_project_permissions
    # add_project_permission
    # list_project_requirements
    # list_project_campaigns
    # list_project_testcases

    @api_call
    def list_projects(self) -> List[Dict[str, Any]]:
        """Return the projects list.

        # Returned value

        A list of _projects_.  Each project is a dictionary with the
        following two entries:

        - id: an integer
        - name: a string

        It may contain additional entries.
        """
        return self._collect_data('projects', 'projects')

    @api_call
    def get_project(self, project_id: int) -> Dict[str, Any]:
        """Return project details.

        # Required parameters

        - project_id: an integer

        # Returned value

        A dictionary with the following entries:

        - active: a boolean
        - attachments: a list
        - description: a string
        - id: an integer
        - label: a string
        - name: a string
        - _links: a dictionary
        - _type: a string (`'project'`)
        """
        ensure_instance('project_id', int)

        return self._get(f'projects/{project_id}')  # type: ignore

    @api_call
    def delete_project(self, project_id: int) -> None:
        """Delete project.

        # Required parameters

        - project_id: an integer
        """
        ensure_instance('project_id', int)

        self._delete(f'projects/{project_id}')

    @api_call
    def list_project_requirements(
        self, project_id: int
    ) -> List[Dict[str, Any]]:
        """Return project requirements.

        # Required parameters

        - project_id: an integer

        # Returned value

        A list of _requirements_.  Each requirement is a dictionary.
        """
        ensure_instance('project_id', int)

        return self._collect_data(
            f'projects/{project_id}/requirements', 'requirements'
        )

    @api_call
    def list_project_campaigns(self, project_id: int) -> List[Dict[str, Any]]:
        """Return project campaigns.

        # Required parameters

        - project_id: an integer

        # Returned value

        A list of _campaigns_.  Each campaign is a dictionary.
        """
        ensure_instance('project_id', int)

        return self._collect_data(
            f'projects/{project_id}/campaigns', 'campaigns'
        )

    @api_call
    def list_project_testcases(self, project_id: int) -> List[Dict[str, Any]]:
        """Return project test cases.

        # Required parameters

        - project_id: an integer

        # Returned value

        A list of _test cases_.  Each test case is a dictionary.
        """
        ensure_instance('project_id', int)

        return self._collect_data(
            f'projects/{project_id}/test-cases', 'test-cases'
        )

    @api_call
    def create_project(
        self, name: str, label: str, description: str
    ) -> Dict[str, Any]:
        """Create project.

        # Required parameters

        - name: a non-empty string
        - label: a string
        - description: a non-empty string

        # Returned value

        A dictionary.  Please refer to #get_project() for more
        information.
        """
        ensure_nonemptystring('name')
        ensure_instance('label', str)
        ensure_nonemptystring('description')

        data = {
            '_type': 'project',
            'name': name,
            'label': label,
            'description': description,
        }
        result = self._post('projects', json=data)
        return result  # type: ignore

    @api_call
    def get_project_permissions(self, project_id: int) -> Dict[str, List[int]]:
        """Return project permissions.

        # Required parameters

        - project_id: an integer

        # Returned value

        A dictionary with one entry per defined permission.  Keys are
        permission names and values are lists of items.

        Items in the lists are either _teams_ or _users_.
        """
        ensure_instance('project_id', int)

        result = self._get(f'projects/{project_id}/permissions').json()
        return result['content']  # type: ignore

    @api_call
    def add_project_permission(
        self, project_id: int, permission: str, ids: Iterable[int]
    ) -> Dict[str, Any]:
        """Add users and teams to project permission.

        # Required parameters

        - project_id: an integer
        - permission: a non-empty string
        - ids: a list of integers

        # Returned value

        A dictionary.
        """
        ensure_instance('project_id', int)
        ensure_in('permission', PROJECT_PERMISSIONS)
        ensure_instance('ids', list)

        result = self._post(
            f'projects/{project_id}/permissions/{permission}',
            params={'ids': ','.join(str(i) for i in ids)},
        )
        return result  # type: ignore

    ####################################################################
    # squash-tm teams
    #
    # list_teams
    # get_team
    # create_team
    # delete_team
    # list_team_members
    # add_team_members
    # remove_team_members

    @api_call
    def list_teams(self) -> List[Dict[str, Any]]:
        """Return the teams list.

        # Returned value

        A list of _teams_.  Each team is a dictionary with at least the
        two following entries:

        - id: an integer
        - name: a string
        """
        return self._collect_data('teams', 'teams')

    @api_call
    def get_team(self, team_id: int) -> Dict[str, Any]:
        """Return team details.

        # Required parameters

        - team_id: an integer

        # Returned value

        A dictionary with the following entries:

        - created_by: a string
        - created_on: a string
        - description: a string
        - id: an integer
        - last_modified_by: a string
        - last_modified_on: a string
        - members: a list
        - name: a string
        - _links: a dictionary
        - _type: a string
        """
        ensure_instance('team_id', int)

        return self._get(f'teams/{team_id}')  # type: ignore

    @api_call
    def create_team(self, name: str, description: str) -> Dict[str, Any]:
        """Create a new team.

        # Required parameters

        - name: a non-empty string
        - description: a non-empty string

        # Returned value

        A dictionary.  Please refer to #get_team() for more
        information.
        """
        ensure_nonemptystring('name')
        ensure_nonemptystring('description')

        data = {'_type': 'team', 'name': name, 'description': description}
        result = self._post('teams', json=data)
        return result  # type: ignore

    @api_call
    def delete_team(self, team_id: int) -> None:
        """Delete team.

        # Required parameters

        - team_id: an integer
        """
        ensure_instance('team_id', int)

        return self._delete(f'teams/{team_id}')  # type: ignore

    @api_call
    def list_team_members(self, team_id: int) -> List[Dict[str, Any]]:
        """Return list of team members.

        # Required parameters

        - team_id: an integer

        # Returned value

        A list of _users_.  Please refer to #get_user() for more
        information.
        """
        ensure_instance('team_id', int)

        return self._collect_data(f'teams/{team_id}/members', 'members')

    @api_call
    def add_team_members(
        self, team_id: int, members_ids: Iterable[int]
    ) -> None:
        """Add members to team.

        Unknown or invalid IDs, as well as IDs already in team, are
        silently ignored.

        # Required parameters

        - team_id: an integer
        - members_ids: a list of integers
        """
        ensure_instance('team_id', int)
        ensure_instance('members_ids', list)

        result = self._post(
            f'teams/{team_id}/members',
            params={'userIds': ','.join(str(m) for m in members_ids)},
        )
        return result  # type: ignore

    @api_call
    def remove_team_members(
        self, team_id: int, members_ids: Iterable[int]
    ) -> None:
        """Remove members from team.

        Member IDs not part of the team are silently ignored.

        # Required parameters

        - team_id: an integer
        - members_ids: a list of integers
        """
        ensure_instance('team_id', int)
        ensure_instance('members_ids', list)

        result = self._delete(
            f'teams/{team_id}/members',
            params={'userIds': ','.join(str(m) for m in members_ids)},
        )
        return result  # type: ignore

    ####################################################################
    # squash-tm users
    #
    # list_users
    # get_user
    # create_user
    # delete_user
    # update_user

    @api_call
    def list_users(self) -> List[Dict[str, Any]]:
        """Return the users list.

        # Returned value

        A list of _users_.  Each user is a dictionary with at least the
        following entries:

        - active: a boolean
        - group: a string (`'user'` or `'admin'`)
        - id: an integer
        - login: a string
        """
        return self._collect_data('users', 'users')

    @api_call
    def get_user(self, user_id: int) -> Dict[str, Any]:
        """Return user details.

        # Required parameters

        - user_id: an integer

        # Returned value

        A dictionary with the following entries:

        - active: a boolean
        - created_by: a string
        - created_on: a string
        - email: a string
        - first_name: a string
        - group: a string
        - id: an integer
        - last_connected_on: a string
        - last_modified_by: a string
        - last_modified_on: a string
        - last_name: a string
        - login: a string
        - teams: a list
        - _links: a dictionary
        - _type: a string (`'user'`)
        """
        ensure_instance('user_id', int)

        return self._get(f'users/{user_id}')  # type: ignore

    @api_call
    def create_user(
        self,
        login: str,
        password: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        email: Optional[str] = None,
        group: str = 'user',
    ) -> Dict[str, Any]:
        """Create a new user.

        # Required parameters

        - login: a non-empty string
        - password: a non-empty string

        # Optional parameters

        - first_name: a non-empty string or None (None by default)
        - last_name: a non-empty string or None (None by default)
        - email: a non-empty or None  (None by default)
        - group: a non-empty string, either `'user'` or `'admin'`
          (`'user'` by default)

        If `last_name` is not provided (or is None), it will default to
        the value of `login`.

        # Returned value

        A dictionary.  Please refer to #get_user() for more
        information.
        """
        ensure_nonemptystring('login')
        ensure_nonemptystring('password')
        ensure_noneornonemptystring('first_name')
        ensure_noneornonemptystring('last_name')
        ensure_noneornonemptystring('email')
        ensure_in('group', ['user', 'admin'])

        data = {
            '_type': 'user',
            'login': login,
            'password': password,
            'last_name': last_name or login,
            'first_name': first_name or '',
            'email': email or '',
            'group': group,
        }
        result = self._post('users', json=data)
        return result  # type: ignore

    @api_call
    def delete_user(self, user_id: int) -> None:
        """Delete user.

        # Required parameters

        - user_id: an integer
        """
        ensure_instance('user_id', int)

        return self._delete(f'users/{user_id}')  # type: ignore

    @api_call
    def update_user(
        self,
        user_id: int,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        email: Optional[str] = None,
        active: Optional[bool] = None,
        login: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update user.

        # Required parameters

        - user_id: an integer

        # Optional parameters

        - first_name: a non-empty string or None (None by default)
        - last_name: a non-empty string or None (None by default)
        - email: a non-empty string or None (None by default)
        - active: a boolean or None (None by default)
        - login: a string or None (None by default)

        # Returned value

        A dictionary.  Please refer to #get_user() for more
        information.
        """
        ensure_instance('user_id', int)
        ensure_noneornonemptystring('first_name')
        ensure_noneornonemptystring('last_name')
        ensure_noneornonemptystring('email')
        ensure_noneorinstance('active', bool)
        ensure_noneornonemptystring('login')

        data = {'_type': 'user'}
        add_if_specified(data, 'first_name', first_name)
        add_if_specified(data, 'last_name', last_name)
        add_if_specified(data, 'email', email)
        add_if_specified(data, 'active', active)
        add_if_specified(data, 'login', login)

        result = self._patch(f'users/{user_id}', json=data)
        return result  # type: ignore

    ####################################################################
    # squash-tm campaigns
    #
    # list_campaigns
    # get_campaign
    # list_campaign_iterations
    # get_campaign_testplans

    @api_call
    def list_campaigns(self) -> List[Dict[str, Any]]:
        """Return the campaigns list.

        # Returned value

        A list of _campaigns_.  Each campaign is a dictionary with at
        least the two following entries:

        - id: an integer
        - name: a string
        """
        return self._collect_data('campaigns', 'campaigns')

    @api_call
    def get_campaign(self, campaign_id: int) -> Dict[str, Any]:
        """Return campaign details.

        # Required parameters

        - campaign_id: an integer

        # Returned value

        A dictionary with the following entries:

        - actual_end_auto: boolean
        - actual_end_date: a string
        - actual_start_auto: boolean
        - actual_start_date: a string
        - attachments: a list
        - created_by: a string
        - created_on: a string
        - custom_fields: a list
        - description: a string
        - id: an integer
        - iterations: a dictionary
        - iterations: a list of dictionaries
        - last_modified_by: a string
        - last_modified_on: a string
        - name: a string
        - parent: a dictionary
        - path: a string
        - project: a dictionary
        - reference: a string
        - status: a string
        - _links: a dictionary
        - _type: a string
        """
        ensure_instance('campaign_id', int)

        return self._get(f'campaigns/{campaign_id}')  # type: ignore

    @api_call
    def list_campaign_iterations(
        self, campaign_id: int
    ) -> List[Dict[str, Any]]:
        """Return iterations of a campaign.

        # Returned value

        A list of campaign _iterations_.  Each iteration is a
        dictionary with at least the two following entries:

        - id: an integer
        - name: a string
        """
        ensure_instance('campaign_id', int)

        return self._collect_data(
            f'campaigns/{campaign_id}/iterations', 'iterations'
        )

    @api_call
    def list_campaign_testplan(self, campaign_id: int) -> List[Dict[str, Any]]:
        """Return the test-plan of a campaign.

        # Returned value

        A list of _testplan items_.  Each test-plan item is a dictionary
        with at least the two following entries:

        - id: an integer
        - name: a string
        """
        ensure_instance('campaign_id', int)

        return self._collect_data(
            f'campaigns/{campaign_id}/test-plan', 'campaign-test-plan-items'
        )

    ####################################################################
    # squash-tm requirements
    #
    # list_requirements
    # get_requirement

    @api_call
    def list_requirements(self) -> List[Dict[str, Any]]:
        """Return the requirements list.

        # Returned value

        A list of _requirements_.  Each requirement is a dictionary with
        at least the two following entries:

        - id: an integer
        - name: a string
        """
        return self._collect_data('requirements', 'requirements')

    @api_call
    def get_requirement(self, requirement_id: int) -> Dict[str, Any]:
        """Return requirement details.

        # Required parameters

        - requirement_id: an integer

        # Returned value

        A dictionary with the following entries:

        - current_version: a dictionary
        - id: an integer
        - mode: a string
        - name: a string
        - parent: a dictionary
        - path: a string
        - project: a dictionary
        - versions: a list of dictionaries
        - _links: a dictionary
        - _type: a string
        """
        ensure_instance('requirement_id', int)

        return self._get(f'requirements/{requirement_id}')  # type: ignore

    ####################################################################
    # squash-tm test cases
    #
    # list_testcases
    # get_testcase

    @api_call
    def list_testcases(self) -> List[Dict[str, Any]]:
        """Return the test-cases list.

        # Returned value

        A list of _test-cases_.  Each test-case is a dictionary with at
        least the two following entries:

        - id: an integer
        - name: a string
        """
        return self._collect_data('test-cases', 'test-cases')

    @api_call
    def get_testcase(self, testcase_id: int) -> Dict[str, Any]:
        """Return test-case details.

        # Required parameters

        - testcase_id: an integer

        # Returned value

        A dictionary with the following entries:

        - attachments: a string
        - created_by: a string
        - created_on: a string
        - custom_fields: a list of dictionaries
        - datasets: a list
        - description: a string
        - id: an integer
        - importance: a string
        - iterations: a dictionary
        - kind:a string
        - language: a string
        - last_modified_by: a string
        - last_modified_on: a string
        - name: a string
        - nature: a dictionary
        - parameters: a list
        - parent: a dictionary
        - path: a string
        - prerequisite: a string
        - project: a dictionary
        - reference: a string
        - script: a string
        - status: a string
        - steps: a list of dictionaries
        - type: a dictionary
        - verified_requirements: a string
        - _links: a dictionary
        - _type: a string
        """
        ensure_instance('testcase_id', int)

        return self._get(f'test-cases/{testcase_id}')  # type: ignore

    ####################################################################
    # squash-tm Test suites
    #
    # get_testsuite_testplan
    # get_testsuite

    @api_call
    def get_testsuite_testplan(
        self, testsuite_id: int
    ) -> List[Dict[str, Any]]:
        """Return the test-plan of a test suite.

        # Returned value

        A list of ???.  A test-suite is a
        dictionary with at least the two following entries:

        - TBD
        """
        ensure_instance('testsuite_id', int)

        return self._collect_data(
            f'test-suites/{testsuite_id}/test-plan', 'test-plan'
        )

    @api_call
    def get_testsuite(self, testsuite_id: int) -> Dict[str, Any]:
        """Return test-suite details.

        # Required parameters

        - testsuite_id: an integer

        # Returned value

        A dictionary with the following entries:

        - attachments: a dictionary
        - created_by: a string
        - created_on: a string
        - custom_fields: a dictionary
        - description: a string
        - id: an integer
        - last_modified_by: a string
        - last_modified_on: a string
        - name: a string
        - parent: a dictionary
        - path: a string
        - project: a dictionary
        - test_plan: a list of dictionaries
        - _links: a dictionary
        - _type: a string
        """
        ensure_instance('testsuite_id', int)

        return self._get(f'test-suites/{testsuite_id}')  # type: ignore

    ####################################################################
    # squash-tm test steps
    #
    # get_teststep

    @api_call
    def get_teststep(self, teststep_id: int) -> Dict[str, Any]:
        """Return test step details.

        # Required parameters

        - teststep_id: an integer

        # Returned value

        A dictionary with the following entries:

        - attachments: a dictionary
        - custom_fields: a list
        - expected_result: a string
        - id: an integer
        - index: a string
        - test_case: a dictionary
        - _links: a dictionary
        - _type: a string
        """
        ensure_instance('teststep_id', int)

        return self._get(f'test-steps/{teststep_id}')  # type: ignore

    ####################################################################
    # squash-tm test case folders
    #
    # list_testcasefolders
    # get_testcasefolder
    # get_testcasefolder_content

    @api_call
    def list_testcasefolders(self) -> List[Dict[str, Any]]:
        """Return the test-case folders list.

        # Returned value

        A list of _test-case folders_.  Each test-case folder is a
        dictionary with at least the two following entries:

        - id: an integer
        - name: a string
        """
        return self._collect_data('test-case-folders', 'test-case-folders')

    @api_call
    def get_testcasefolder(self, testcasefolder_id: int) -> Dict[str, Any]:
        """Return test-case folder details.

        # Required parameters

        - testcasefolder_id: an integer

        # Returned value

        A dictionary with the following entries:

        - attachments: a string
        - created_by: a string
        - created_on: a string
        - description: a string
        - id: an integer
        - last_modified_by: a string
        - last_modified_on: a string
        - name: a string
        - parent: a dictionary
        - path: a string
        - project: a dictionary
        - _links: a dictionary
        - _type: a string
        """
        ensure_instance('testcasefolder_id', int)

        return self._get(f'test-case-folders/{testcasefolder_id}')  # type: ignore

    @api_call
    def get_testcasefolder_content(
        self, testcasefolder_id: int
    ) -> List[Dict[str, Any]]:
        """Return content of a test-case folder.

        # Required parameters

        - testcasefolder_id: an integer

        # Returned value

        A list of dictionaries with the following entries:

        - id: an integer
        - name: a string
        - reference: a string
        - _links: a dictionary
        - _type: a string
        """
        ensure_instance('testcasefolder_id', int)

        return self._collect_data(
            f'test-case-folders/{testcasefolder_id}/content', 'content'
        )

    ####################################################################
    # squash-tm executions
    #
    # get_execution

    @api_call
    def get_execution(self, execution_id: int) -> Dict[str, Any]:
        """Return execution details.

        # Required parameters

        - execution_id: an integer

        # Returned value

        A dictionary with the following entries:

        - attachments: a dictionary
        - comment: a string
        - custom_fields: a list
        - dataset_label: a string
        - description: a string
        - execution_mode: a string
        - execution_order: an integer
        - execution_status: a string
        - execution_steps: a list of dictionaries
        - id: an integer
        - importance: a string
        - language: a string
        - last_excuted_by: a string
        - last_executed_on: a string
        - nature: a dictionary
        - prerequisite: a string
        - reference: a string
        - script_name: a string
        - test_case_custom_fields: a list
        - test_case_status: a string
        - test_plan_item: a dictionary
        - type: a dictionary
        - _links: a dictionary
        - _type: a string
        """
        ensure_instance('execution_id', int)

        return self._get(f'executions/{execution_id}')  # type: ignore

    @api_call
    def list_execution_executionsteps(
        self, execution_id: int
    ) -> List[Dict[str, Any]]:
        """Return the execution steps of an execution

        # Returned value

        A list of _execution steps_.  Each execution step is a
        dictionary with at least the two following entries:

        - TBD
        """
        ensure_instance('execution_id', int)

        return self._collect_data(
            f'executions/{execution_id}/execution-steps', 'execution-steps'
        )

    ####################################################################
    # squash-tm executions-steps
    #
    # get_executionstep

    @api_call
    def get_executionstep(self, executionstep_id: int) -> Dict[str, Any]:
        """Return execution step details.

        # Required parameters

        - executionstep_id: an integer

        # Returned value

        A dictionary with the following entries:

        - action: a string
        - attachments: a dictionary
        - comment: a string
        - custom_fields: a list
        - execution: a dictionary
        - execution_status: a string
        - execution_step_order: an integer
        - expected_result: a string
        - id: an integer
        - last_executed_by: a string
        - last_executed_on: a string
        - referenced_test_step: a dictionary
        - test_step_custom_fields: a string
        - _links: a dictionary
        - _type: a string
        """
        ensure_instance('executionstep_id', int)

        return self._get(f'execution-steps/{executionstep_id}')  # type: ignore

    ####################################################################
    # squash-tm iterations
    #
    # get_iteration_testplan
    # list_iteration_testsuites
    # get_iteration

    @api_call
    def get_iteration_testplan(
        self, iteration_id: int
    ) -> List[Dict[str, Any]]:
        """Return the test-plan of an iteration

        # Returned value

        A list of ???.  A test-plan of an iteration. A test-plan is a
        dictionary with at least the following entries:

        - TBD
        """
        ensure_instance('iteration_id', int)

        return self._collect_data(
            f'iterations/{iteration_id}/test-plan', 'test-plan'
        )

    @api_call
    def list_iteration_testsuites(
        self, iteration_id: int
    ) -> List[Dict[str, Any]]:
        """Return the test-suites list of an iteration

        # Returned value

        A list of _test-suites_.  Each test-suite is a dictionary with
        at least the following entries:

        - TBD
        """
        ensure_instance('iteration_id', int)

        return self._collect_data(
            f'iterations/{iteration_id}/test-suites', 'test-suites'
        )

    @api_call
    def get_iteration(self, iteration_id: int) -> Dict[str, Any]:
        """Return iteration details.

        # Required parameters

        - iteration_id: an integer

        # Returned value

        A dictionary with the following entries:

        - actual_end_auto: a string
        - actual_end_date: a string
        - actual_start_auto: a string
        - actual_start_date: a string
        - attachments: a string
        - created_by: a string
        - created_on: a string
        - custom_fields: a list of dictionaries
        - description: a string
        - id: an integer
        - last_modified_by: a string
        - last_modified_on: a string
        - name: a string
        - parent: a dictionary
        - reference: a string
        - test_suites: a list of dictionaries
        - _links: a dictionary
        - _type: a string
        """
        ensure_instance('iteration_id', int)

        return self._get(f'iterations/{iteration_id}')  # type: ignore

    ####################################################################
    # squash-tm private helpers

    def _get(self, api: str) -> requests.Response:
        """Returns squash-tm api call results, as JSON."""
        api_url = join_url(self.url, api)
        return self.session().get(api_url)

    def _post(
        self,
        api: str,
        json: Optional[Mapping[str, Any]] = None,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().post(api_url, json=json, params=params)

    def _patch(self, api: str, json: Mapping[str, Any]) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().patch(api_url, json=json)

    def _delete(
        self,
        api: str,
        data: Optional[Union[Mapping[str, str], bytes]] = None,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().delete(api_url, data=data, params=params)

    def _collect_data(self, api: str, key: str) -> List[Any]:
        """Return SquashTM API call results, collecting key values.

        The API call is expected to return a JSON structure.
        """
        page_size = 1000
        page = 0

        try:
            req = self._get(f'{api}?size={page_size}').json()
        except ValueError:
            raise ApiError(
                'Unexpected response, was expecting JSON (%s)'
                % join_url(self.url, api)
            ) from None

        # no '_embedded' part of 'totalElements' is zero.
        values: List[Any] = (
            req['_embedded'][key] if req['page']['totalElements'] else []
        )
        while 'page' in req and len(values) < req['page']['totalElements']:
            page += 1
            req = self._get(f'{api}?size={page_size}&page={page}').json()
            if req:
                values += req['_embedded'][key]
            else:
                raise ApiError('Empty response (%s)' % join_url(self.url, api))

        return values
