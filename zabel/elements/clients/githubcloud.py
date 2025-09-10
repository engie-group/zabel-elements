# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0
"""GitHubCloud.

A class wrapping the GitHub Cloud APIs.

This module depends ont the **requests** public library. It also depends
on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.
"""

from typing import Any, Dict, List, Optional

from base64 import b64decode, b64encode

from nacl import public

from zabel.commons.utils import (
    api_call,
    ensure_nonemptystring,
    ensure_instance,
    ensure_in,
)
from .base.githubcloud import GitHubCloud as Base


class GitHubCloud(Base):
    """GitHub Enterprise Cloud Low-Level Wrapper.

    A class wrapping the GitHub Enterprise Cloud APIs.

    There can be as many GitHub Enterprise Cloud instances as needed.

    This module depends on the **requests** public library. It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions, and
    #::zabel.commons.utils.

    ## Reference URLs

    - <https://docs.github.com/en/enterprise-cloud@latest/rest?apiVersion=2022-11-28>
    - <https://docs.github.com/en/enterprise-cloud@latest/graphql>

    ## Examples

    Standard use on github.com:

    ```python
    from zabel.elements.clients import GitHubCloud

    url = 'https://api.github.com'
    token = '...'
    ghc = GitHubCloud(url, bearer_auth=token)
    ghc.list_organizations('my_enterprise')
    ```
    """

    @api_call
    def create_enterprise_organization(
        self,
        organization_name: str,
        enterprise_name: str,
        admins: List[str],
        profile_name: str = '',
    ) -> Dict[str, Any]:
        """Create an organization in an enterprise.

        # Required parameters

        - organization_name: the name of the organization
        - enterprise_name: the name of the enterprise
        - admins: a list of admin usernames

        # Optional parameters

        - profile_name: The profile name, `''` by default

        # Returned value

        An _organization_.  An organization is a dictionary.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('enterprise_name')
        ensure_instance('admins', list)
        ensure_instance('profile_name', str)

        enterprise = self.get_enterprise(enterprise_name)
        if not enterprise:
            raise ValueError(f'Enterprise {enterprise_name} not found')
        return self.create_organization(
            organization_name,
            enterprise['id'],
            admins,
            enterprise['billingEmail'],
            profile_name,
        )

    ####################################################################
    # GitHub organization secret
    #
    # create_or_update_organization_secret

    @api_call
    def create_or_update_organization_secret(
        self,
        organization_name: str,
        secret_name: str,
        secret_value: str,
        visibility: str = 'all',
        repositories_ids: Optional[List[int]] = None,
    ) -> bool:
        """Create or update the organization's secret.

        # Required parameters

        - organization_name: a non-empty string
        - secret_name: a non-empty string
        - secret_value: a non-empty string

        # Optional parameters

        - visibility: a string, one of `'all'`, `'private'`, or
          `'selected'` (`'all'` by default)
        - repositories_ids: a list of integers (None by default)

        # Returned value

        A dictionary with the following entries:

        - name: a string
        - created_at: a string
        - updated_at: a string
        - visibility: a string
        - selected_repositories_url: a string
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('secret_name')
        ensure_nonemptystring('secret_value')
        ensure_in('visibility', ('all', 'private', 'selected'))
        if visibility == 'selected':
            ensure_instance('repositories_ids', list)

        orga_key = self.get_organization_public_key(organization_name)

        public_key_bytes = b64decode(orga_key['key'])

        public_key_obj = public.PublicKey(public_key_bytes)
        sealed_box = public.SealedBox(public_key_obj)
        encrypted_value = sealed_box.encrypt(secret_value.encode())
        encrypted_value_base64 = b64encode(encrypted_value).decode()

        data = {
            'encrypted_value': encrypted_value_base64,
            'key_id': orga_key['key_id'],
            'visibility': visibility,
        }

        if visibility == 'selected':
            data['selected_repository_ids'] = repositories_ids

        response = self._put(
            f'orgs/{organization_name}/actions/secrets/{secret_name}',
            json=data,
        )
        return response.status_code in [201, 204]
