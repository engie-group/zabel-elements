from typing import List, Optional
from .base.githubcloud import GitHubCloud as Base
from zabel.commons.utils import api_call, ensure_nonemptystring


class GitHubCloud(Base):

    @api_call
    def create_enterprise_organization(
        self,
        organization: str,
        enterprise_name: str,
        admins: List[str],
        profile_name: Optional[str] = '',
    ):
        """Create an organization in an enterprise"""

        ensure_nonemptystring('organization')
        ensure_nonemptystring('enterprise_name')
        enterprise = (
            self.get_enterprise(enterprise_name)
            .get('data', {})
            .get('enterprise')
        )
        if not enterprise:
            raise ValueError(f'Enterprise {enterprise_name} not found')
        self.create_organization(
            organization, admins, enterprise['billingEmail'], enterprise['id'], profile_name
        )
