from typing import List
from .github import GitHub
from zabel.commons.utils import (
    api_call,
    ensure_nonemptystring,
    add_if_specified,
)


class GitHubCloud(GitHub):

    def __init__(self, url: str, bearer_auth: str):
        super().__init__(url, bearer_auth=bearer_auth)

    @api_call
    def list_organizations(self, enterprise: str):
        query = """
        query($enterprise: String!) {
            enterprise(slug: $enterprise) {
                organizations(first: 100) {
                    nodes {
                        login
                        name
                        url
                        archivedAt
                        createdAt
                        updatedAt
                        description
                        id
                        membersWithRole(first: 10) {
                            totalCount
                        }
                    }
                }
            }
        }
        """
        variables = {"enterprise": enterprise}
        return self._post(
            'graphql', json={"query": query, "variables": variables}
        )

    @api_call
    def get_admin_stats(self, enterprise_or_org: str):
        ensure_nonemptystring('enterprise_or_org')

        return self._get(
            f'enterprise-installation/{enterprise_or_org}/server-statistics'
        )

    @api_call
    def create_organization(
        self,
        organization_name: str,
        admins: List[str],
        billing_email: str,
        enterprise_id: str,
        profile_name='',
    ):
        query = '''
        mutation($organization:CreateEnterpriseOrganizationInput!) {
            createEnterpriseOrganization(input:$organization) {
                enterprise {
                id
            }
            }
        }'''
        organization = {
            'adminLogins': admins,
            'billingEmail': billing_email,
            'enterpriseId': enterprise_id,
            'login': organization_name,
        }
        add_if_specified(organization, 'profileName', profile_name)
        return self._post(
            'graphql',
            json={'query': query, 'variables': {'organization': organization}},
        )

    @api_call
    def get_enterprise(self, enterprise_name: str):
        """Returns the enterprise details

        # Required parameters:

        - enterprise_name: The name of the enterprise

        """

        query = """
        query($enterprise: String!) {
            enterprise(slug: $enterprise) {
                id
                name
                description
                url
                slug
                billingEmail
                createdAt
            }
        }"""
        return self._post(
            'graphql',
            json={
                "query": query,
                "variables": {"enterprise": enterprise_name},
            },
        )
