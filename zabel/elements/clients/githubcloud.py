from typing import List, Optional
from base64 import b64decode, b64encode
from nacl import public

from .base.githubcloud import GitHubCloud as Base
from zabel.commons.utils import (
    api_call,
    ensure_nonemptystring,
    ensure_instance,
    ensure_in,
)


class GitHubCloud(Base):

    @api_call
    def create_enterprise_organization(
        self,
        organization: str,
        enterprise_name: str,
        admins: List[str],
        profile_name: Optional[str] = '',
    ):
        """Create an organization in an enterprise.

        # Required parameters:

        - organization: The name of the organization
        - enterprise_name: The name of the enterprise
        - admins: List of admin usernames

        # Optional parameters:

        - profile_name: The profile name


        """

        ensure_nonemptystring('organization')
        ensure_nonemptystring('enterprise_name')
        ensure_instance('admins', list)

        enterprise = (
            self.get_enterprise(enterprise_name)
            .get('data', {})
            .get('enterprise')
        )
        if not enterprise:
            raise ValueError(f'Enterprise {enterprise_name} not found')
        return self.create_organization(
            organization,
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
        organization: str,
        secret_name: str,
        secret_value: str,
        visibility: str = 'all',
        repositories_ids: Optional[List[int]] = None,
    ) -> bool:
        """Create or update the organization's secret.

        # Required parameters

        - organizatio: a non-empty string
        - secret_name: a non-empty string
        - secret_value: a non-empty string

        # Optional parameters

        - visibility: a string, one of 'all', 'private', or 'selected' ('all' by default)

        # Returned value

        A dictionary with the following entries:

        - name: a string
        - created_at: a string
        - updated_at: a string
        - visibility: a string
        - selected_repositories_url: a string
        """
        ensure_nonemptystring('organization')
        ensure_nonemptystring('secret_name')
        ensure_nonemptystring('secret_value')
        ensure_in('visibility', ('all', 'private', 'selected'))

        orga_key = self.get_organization_public_key(organization)

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
            f'orgs/{organization}/actions/secrets/{secret_name}',
            json=data,
        )
        return response.status_code in [201, 204]
