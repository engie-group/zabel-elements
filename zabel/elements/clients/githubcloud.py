from typing import List, Optional
from .base.githubcloud import GitHubCloud as Base
from zabel.commons.utils import (
    api_call,
    ensure_nonemptystring,
    ensure_instance,
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
