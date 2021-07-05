#!/usr/bin/env python3
# coding:utf-8

from urllib.parse import urlencode
import requests, json, hvac, sys, os


class Vault:
    """Vault."""

    def __init__(
        self,
        url,
        login,
        password,
    ):
        """
        # Required parameters
        - url: url of the vault (a string)
        - user: a user name (a string)
        - password: a user password (a string)
        - bu : user Business Unit (a string)
        - project : In which plateform work the user walnut, livin... (a string)
        - team : user team is he in developer, infrastructure team...  (a string)
        - gaia : unique ID give by Engie (a string)
        - role : a name for which kind of access he have admins, users, readers (a string)
        - engine : what kind of secret engine (a string)
        - approle_name : a name for the authentification method in vault (a string)
        - role_name : name of a role in the approle method in  (a string)
        - policy : the name of the policy that we give for the approle role (a string)

        # Sample use
            - Create an entity :
                URL = "https://vault.dev.tools.digital.engie.com"
                vault = Vault(
                    URL, password, bu, project, team, gaia, role,
                    engine_to_deploy, approle_name, role_name, policy
                )
                vault.create_alias()
        """
        self.url = url
        self.password = password
        self.login = login
        self.token = self.get_token()
        self.client = None

    def get_token(self):
        """Function that will retrieve the tokens so that TPM can take actions."""
        url_tpm = self.url + "/v1/auth/userpass/login/" + self.login
        data = {"password": self.password}
        response = requests.post(url_tpm, json=data)
        data = response.text
        utf8string = data.encode("utf-8")
        res = json.loads(utf8string)
        for i in res["auth"].items():
            if "client_token" in i:
                return str(list(i)[1])
        return None

    def _client(self):
        """singleton instance, only if needed."""
        if self.client is None:
            self.client = hvac.Client(url=self.url, token=self.token)
        return self.client

    def get_accessor_id(self):
        """Function that will return the accessor ID of the OIDC authentication method activated in the vault."""
        auth_methods = self._client().sys.list_auth_methods()
        accessor_id = auth_methods["oidc/"]["accessor"]
        return accessor_id

    def list_entities(self):
        """Function that will list existing entities in vault.
        - return : it return a request object that can provide infomations with :
            - .headers = the header of the http answer.
            - .status_code = http status code.
            - .content = what the server send back to the requester.
        """
        header = {"X-Vault-Token": self.token}
        url_entity_list = self.url + "/v1/identity/entity/name?list=true"
        return requests.get(url_entity_list, headers=header)

    def get_entity(self, entity):
        """Function that will read entity information in vault.
        - entity : ID of the user.
        - return : it return a request object that can provide infomations with :
            - .headers = the header of the http answer.
            - .status_code = http status code.
            - .content = what the server send back to the requester.
        """
        header = {"X-Vault-Token": self.token}
        url_entity_name = self.url + "/v1/identity/entity/name/" + entity
        return requests.get(url_entity_name, headers=header)

    def get_group(self, project, team, role):
        """Function that will read group information in vault.
        - project : name of the project.
        - team : name of a team in the project.
        - role : admins, users or readers (different level of the RBAC).
        - return : it return a request object that can provide infomations with :
            - .headers = the header of the http answer.
            - .status_code = http status code.
            - .content = what the server send back to the requester.
        The first return, send back a URL in order to be use later on the function that call this function.
        """
        header = {"X-Vault-Token": self.token}
        # Read Group by Name.
        url_group_name = (
            self.url
            + "/v1/identity/group/name/"
            + project
            + "-"
            + team
            + "-"
            + role
        )
        return requests.get(url_group_name, headers=header)

    def get_group_admin(self, name):
        """Function that will read admins group information in vault.
        - name : the name of the admins group.
        - return : it return a request object that can provide infomations with :
            - .headers = the header of the http answer.
            - .status_code = http status code.
            - .content = what the server send back to the requester.
        The first return, send back a URL in order to be use later on the function that call this function.
        """
        header = {"X-Vault-Token": self.token}
        # Read Group by Name.
        url_group_name = self.url + "/v1/identity/group/name/" + name
        return requests.get(url_group_name, headers=header)

    def list_aliases(self):
        """Function that will list aliases of entities in vault.
        - return : it return a request object that can provide infomations with :
            - .headers = the header of the http answer.
            - .status_code = http status code.
            - .content = what the server send back to the requester.
        """
        header = {"X-Vault-Token": self.token}
        # List entity aliases by ID.
        url_alias_list = self.url + "/v1/identity/entity-alias/id?list=true"
        return requests.get(url_alias_list, headers=header)

    def list_policies(self):
        """Function that will list policies in vault.
        - return : it return a request object that can provide infomations with :
            - .headers = the header of the http answer.
            - .status_code = http status code.
            - .content = what the server send back to the requester.
        """
        header = {"X-Vault-Token": self.token}
        # List all policies.
        url_policies_list = self.url + "/v1/sys/policy"
        return requests.get(url_policies_list, headers=header)

    def list_groups(self):
        """Function that will read or list group in vault.
        - return : it return a request object that can provide infomations with :
            - .headers = the header of the http answer.
            - .status_code = http status code.
            - .content = what the server send back to the requester.
        The first return, send back a URL in order to be use later on the function that call this function.
        """
        header = {"X-Vault-Token": self.token}
        # List Groups by ID
        url_group_list = self.url + "/v1/identity/group/id?list=true"
        return requests.get(url_group_list, headers=header)

    def list_roleid(self, project, team, approle_name, role_name):
        """Function that will read RoleID of AppRole authentification in vault.
        - project : name of the project.
        - team : name of a team in the project.
        - approle_name : name of the approle mount.
        - role_name : name of the role in approle_name.
        - return : it return a request object that can provide infomations with :
            - .headers = the header of the http answer.
            - .status_code = http status code.
            - .content = what the server send back to the requester.
        """
        approle = project + "-" + team + "-" + approle_name
        header = {"X-Vault-Token": self.token}
        # Read AppRole Role ID.
        url = (
            self.url
            + "/v1/auth/"
            + approle
            + "/role/"
            + role_name
            + "/role-id"
        )
        return requests.get(url, headers=header)

    def create_entity(self, entity):
        """Function which first of all see if the GAIA put in the arguments exists in the entities
        (1 entity = 1 user) and return its ID. Secondly, if the entity does not exist, it will create it and return its ID."""
        # Creation of the entity with the user's GAIA.
        url_entity = self.url + "/v1/identity/entity"
        header = {"X-Vault-Token": self.token}
        data = {"name": entity}
        http_code = requests.post(url_entity, headers=header, json=data)
        json_return = http_code.json()
        entity_id = json_return["data"]["id"]
        return entity_id

    def create_alias(self, entity, username_okta):
        """Function that will create the alias, this will allow the entity to be linked to the OIDC
        authentication method and will allow when the user is going to connect with OKTA to be linked
        to his entity and to have the correct policies.
        Returns True if everything was fine, False otherwise."""
        header = {"X-Vault-Token": self.token}
        data = {
            "name": username_okta,
            "canonical_id": self.create_entity(entity),
            "mount_accessor": self.get_accessor_id(),
        }
        url_alias = self.url + "/v1/identity/entity-alias"
        http_code = requests.post(url_alias, headers=header, json=data)
        return http_code.status_code

    def create_group(self, project, team, role):
        """Function that will create the admins, users and readers groups for each team within a project."""
        url_group = self.url + "/v1/identity/group"
        header = {"X-Vault-Token": self.token}
        data = {
            "name": project + "-" + team + "-" + role,
            "policies": [project + "-" + team + "-" + role],
        }
        http_code_1 = requests.post(url_group, headers=header, json=data)
        return http_code_1.status_code

    def add_entity_group(self, entity, project, team, role):
        """Function which will add an entity (= a user) in a group without deleting those already present."""
        # We get the list of user already in the group.
        http_code_1 = self.get_group(project, team, role)
        json_return = http_code_1.json()
        group_member = json_return["data"]["member_entity_ids"]
        # We get the ID of the entity that we want to add to the group.
        entity_id = self.get_entity(entity)
        json_return = entity_id.json()
        entity_id = json_return["data"]["id"]
        group_member.append(entity_id)
        # We send back to vault the list of entities.
        header = {"X-Vault-Token": self.token}
        url_group_name = (
            self.url
            + "/v1/identity/group/name/"
            + project
            + "-"
            + team
            + "-"
            + role
        )
        data = {"member_entity_ids": group_member}
        http_code_2 = requests.post(url_group_name, headers=header, json=data)
        return http_code_2.status_code

    def remove_entity_group(self, entity, project, team, role):
        """Function that will remove entities from groups."""
        # We get the list of user already in the group.
        group = self.get_group(project, team, role)
        json_return = group.json()
        group_member = json_return["data"]["member_entity_ids"]
        # We get the ID of the entity that we want to remove to the group.
        entity_id = self.get_entity(entity)
        json_return = entity_id.json()
        entity_id = json_return["data"]["id"]
        return_http_code = []
        url_group_name = (
            self.url
            + "/v1/identity/group/name/"
            + project
            + "-"
            + team
            + "-"
            + role
        )
        for ids in group_member:
            if "canonical_id" in ids.keys():
                canonical_id = ids["canonical_id"]
                group_member.remove(canonical_id)
                header = {"X-Vault-Token": self.token}
                data = {"member_entity_ids": group_member}
                http_code = requests.post(
                    url_group_name, headers=header, json=data
                )
                return_http_code.append(http_code.status_code)
        return return_http_code

    def delete_entity(self, entity):
        """Function who delete an entity."""
        url_entity = self.url + "/v1/identity/entity"
        header = {'X-Vault-Token': self.token}
        http_code = requests.delete(url_entity, headers=header)
        return http_code.status_code

    def delete_group(self, project, team, role):
        """Function that remove groups from a team."""
        # The group IDs are placed in a list.
        group_name = project + "-" + team + "-" + role
        url_group_id = self.url + "/v1/identity/group/name/" + group_name
        header = {"X-Vault-Token": self.token}
        http_code = requests.delete(url_group_id, headers=header)
        return http_code.status_code

    def create_policy(self, project, team, role):
        """Function to create the admins, users and readers policies for each team."""
        client = hvac.Client(url=self.url, token=self.token)
        policy = project + "-" + team + "-" + role
        http_code = client.sys.create_or_update_policy(
            name=policy, policy="""# Policy create by TPM"""
        )
        return http_code.status_code

    def update_tpm_policy(self, secret_engine_name):
        """Function that allows you to update the TPM policy when creating a new secret to be
        able to interact with it.
        - name : the name of the secret engine.
        """
        policy = (
            """
path "%s/*" {
    capabilities = ["create", "update", "delete"]
}
"""
            % secret_engine_name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(name="tpm-policy")["data"][
            "rules"
        ]
        if 'path "' + secret_engine_name + '/*"' in hvac_policy_rules:
            print("secret " + secret_engine_name + " already in TPM policy.")
        else:
            send_new_policy = hvac_policy_rules + policy
            client.sys.create_or_update_policy(
                name="tpm-policy", policy=send_new_policy
            )
            print("secret " + secret_engine_name + " add in TPM policy")

    def update_admin_policy(self, policy_name, secret_engine_name):
        """Function that will update the admins policy by adding the path and capabilities of the new secret engine.
        - name : the name of the secret engine.
        """
        policy = (
            """
path "%s/*" {
    capabilities = ["create", "update", "delete", "list", "read"]
}
"""
            % secret_engine_name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(
            name=policy_name + "-" + "admins"
        )["data"]["rules"]
        condition = 'path "' + secret_engine_name + '/*"'
        if condition in hvac_policy_rules:
            print(
                "secret " + secret_engine_name + " already in admins policy."
            )
        else:
            send_new_policy = hvac_policy_rules + policy
            client.sys.create_or_update_policy(
                name=policy_name + "-" + "admins", policy=send_new_policy
            )
            print("secret " + secret_engine_name + " add in admins policy")

    def update_user_policy(self, policy_name, secret_engine_name):
        """Function that will update the policy user by adding the path and capabilities of the new secret engine.
        - name : the name of the secret engine.
        """
        policy_user = (
            """
path "%s/*" {
    capabilities = ["create", "update", "list", "read"]
}
"""
            % secret_engine_name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(
            name=policy_name + "-" + "users"
        )["data"]["rules"]
        if 'path "' + secret_engine_name + '/*"' in hvac_policy_rules:
            print("secret " + secret_engine_name + " already in users policy.")
        else:
            send_new_policy = hvac_policy_rules + policy_user
            client.sys.create_or_update_policy(
                name=policy_name + "-" + "users", policy=send_new_policy
            )
            print("secret " + secret_engine_name + " add in users policy")

    def update_reader_policy(self, policy_name, secret_engine_name):
        """Function that will update the policy readers by adding the path and capabilities of the new secret engine.
        - name : the name of the secret engine.
        """
        policy_reader = (
            """
path "%s/*" {
    capabilities = ["list", "read"]
}
"""
            % secret_engine_name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(
            name=policy_name + "-" + "readers"
        )["data"]["rules"]
        if 'path "' + secret_engine_name + '/*"' in hvac_policy_rules:
            print(
                "secret " + secret_engine_name + " already in readers policy."
            )
        else:
            send_new_policy = hvac_policy_rules + policy_reader
            client.sys.create_or_update_policy(
                name=policy_name + "-" + "readers", policy=send_new_policy
            )
            print("secret " + secret_engine_name + " add in readers policy")

    def enable_secret_engines(self, project, team, engine):
        """Function that creates the secret engine and calls the functions to add it to the policies."""
        secret_engine_name = project + "-" + team + "-" + engine
        url = self.url + "/v1/sys/mounts/" + secret_engine_name
        header = {"X-Vault-Token": self.token}
        if engine == "kv":
            data = {"type": "kv", "options": {"version": "2"}}
        if engine == "transit":
            data = {"type": "transit"}
        if engine == "ssh":
            data = {"type": "ssh"}
        # We verify if the secret already exist and we continue or not.
        http_code = requests.post(url, headers=header, json=data)
        return http_code.status_code

    def update_policies(self, project, team, engine):
        policy_name = project + "-" + team
        secret_engine_name = project + "-" + team + "-" + engine
        self.update_tpm_policy(secret_engine_name)
        self.update_admin_policy(policy_name, secret_engine_name)
        self.update_user_policy(policy_name, secret_engine_name)
        self.update_reader_policy(policy_name, secret_engine_name)

    def remove_tpm_policy(self, secret_engine_name):
        """Function that will remove the secret engine from the TPM policy.
        - name : the name of the secret engine.
        """
        policy = (
            """
path "%s/*" {
    capabilities = ["create", "update", "delete"]
}
"""
            % secret_engine_name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(name="tpm-policy")["data"][
            "rules"
        ]
        if 'path "' + secret_engine_name + '/*"' not in hvac_policy_rules:
            print("secret " + secret_engine_name + " not in TPM policy.")
        else:
            policy_update = hvac_policy_rules.replace(policy, "")
            client.sys.create_or_update_policy(
                name="tpm-policy", policy=policy_update
            )
            print("secret " + secret_engine_name + " remove in TPM policy")

    def remove_admin_policy(self, policy_name, secret_engine_name):
        """Function that will remove the secret engine from the policy admins.
        - name : the name of the secret engine.
        """
        policy = (
            """
path "%s/*" {
    capabilities = ["create", "update", "delete", "list", "read"]
}
"""
            % secret_engine_name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(
            name=policy_name + "-" + "admins"
        )["data"]["rules"]
        if 'path "' + secret_engine_name + '/*"' not in hvac_policy_rules:
            print("secret " + secret_engine_name + " not in admins policy.")
        else:
            policy_update = hvac_policy_rules.replace(policy, "")
            client.sys.create_or_update_policy(
                name=policy_name + "-" + "admins", policy=policy_update
            )
            print("secret " + secret_engine_name + " remove in admins policy")

    def remove_user_policy(self, policy_name, secret_engine_name):
        """Function that will remove the secret engine from the policy users.
        - name : the name of the secret engine.
        """
        policy = (
            """
path "%s/*" {
    capabilities = ["create", "update", "list", "read"]
}
"""
            % secret_engine_name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(
            name=policy_name + "-" + "users"
        )["data"]["rules"]
        if 'path "' + secret_engine_name + '/*"' not in hvac_policy_rules:
            print("secret " + secret_engine_name + " not in users policy.")
        else:
            policy_update = hvac_policy_rules.replace(policy, "")
            client.sys.create_or_update_policy(
                name=policy_name + "-" + "users", policy=policy_update
            )
            print("secret " + secret_engine_name + " remove in users policy")

    def remove_reader_policy(self, policy_name, secret_engine_name):
        """Function that will remove the secret engine from the policy readers.
        - name : the name of the secret engine.
        """
        policy = (
            """
path "%s/*" {
    capabilities = ["list", "read"]
}
"""
            % secret_engine_name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(
            name=policy_name + "-" + "readers"
        )["data"]["rules"]
        if 'path "' + secret_engine_name + '/*"' not in hvac_policy_rules:
            print("secret " + secret_engine_name + " not in readers policy.")
        else:
            policy_update = hvac_policy_rules.replace(policy, "")
            client.sys.create_or_update_policy(
                name=policy_name + "-" + "readers", policy=policy_update
            )
            print("secret " + secret_engine_name + " remove in readers policy")

    def delete_secret_engines(self, project, team, engine):
        """Function which will delete the secret engine and call the functions to delete it from the policies."""
        policy_name = project + "-" + team
        secret_engine_name = project + "-" + team + "-" + engine
        client = hvac.Client(url=self.url, token=self.token)
        client.sys.disable_secrets_engine(secret_engine_name)
        self.remove_tpm_policy(policy_name)
        self.remove_admin_policy(policy_name, secret_engine_name)
        self.remove_user_policy(policy_name, secret_engine_name)
        self.remove_reader_policy(policy_name, secret_engine_name)

    def enable_approle(self, project, team, approle_name):
        """Function that will enable an approle authentification of a team of a project."""
        # Activation de l'authent approle.
        approle_name = project + "-" + team + "-" + approle_name
        url = self.url + "/v1/sys/auth/" + approle_name
        header = {"X-Vault-Token": self.token}
        data = {"type": "approle"}
        http_code = requests.post(url, headers=header, json=data)
        return http_code.status_code

    def add_approle_role(self, project, team, approle_name, policy, role_name):
        """Function that will create a role in the AppRole authentification, this will allow us to
        generate a RoleID and a SecretID."""
        approle = project + "-" + team + "-" + approle_name
        policy_reader = project + "-" + team + "-" + policy
        policies = "default," + policy_reader
        list_of_policies = policies.split(",")
        url = self.url + "/v1/auth/" + approle + "/role/" + role_name
        header = {"X-Vault-Token": self.token}
        data = {"token_policies": list_of_policies}
        http_code = requests.post(url, headers=header, json=data)
        return http_code.status_code

    def create_or_replace_approle_secret(
        self, project, team, approle_name, role_name
    ):
        """Function that will read the RoleID and generate a SecretID."""
        # Retrieving the roleID.
        http_code_1 = self.list_roleid(project, team, approle_name, role_name)
        roleid_dict = json.loads(http_code_1.text)
        for i in roleid_dict:
            if i == "data":
                roleid = list(roleid_dict[i].values())[0]
        # Creation of the secretID.
        approle = project + "-" + team + "-" + approle_name
        secretid_url = (
            self.url
            + "/v1/auth/"
            + approle
            + "/role/"
            + role_name
            + "/secret-id"
        )
        header = {"X-Vault-Token": self.token}
        http_code_2 = requests.post(secretid_url, headers=header)
        secretid_dict = json.loads(http_code_2.text)
        for i in secretid_dict:
            if i == "data":
                secretid = list(secretid_dict[i].values())[0]
        return roleid, secretid

    def remove_approle_role(self, project, team, approle_name, role_name):
        """Function that will delete a role in the previously created AppRole."""
        approle = project + "-" + team + "-" + approle_name
        url = self.url + "/v1/auth/" + approle + "/role/" + role_name
        header = {"X-Vault-Token": self.token}
        http_code = requests.delete(url, headers=header)
        return http_code.status_code

    def disable_approle(self, project, team, approle_name):
        """Function that disable AppRole authentication for a project."""
        name = project + team + approle_name
        url = self.url + "/v1/sys/auth/" + name
        header = {"X-Vault-Token": self.token}
        http_code = requests.delete(url, headers=header)
        return http_code.status_code

    def delete_policy(self, project, team):
        """Function that will delete all the policies of a team."""
        client = hvac.Client(url=self.url, token=self.token)
        list_policies = client.sys.list_policies()['data']['policies']
        for policy in list_policies:
            if project + "-" + team in policy:
                client.sys.delete_policy(name=policy)
        print("All policies of '" + project + "-" + team + "' were deleted")

    def create_policy_global_admin(self):
        """Function that will create a global admins policy.
        return : http code.
        """
        client = hvac.Client(url=self.url, token=self.token)
        http_code = client.sys.create_or_update_policy(
            name="vault-global-admins",
            policy="""# Policy create by TPM
path "sys" {
    capabilities = ["read", "sudo"]
}

path "sys/*" {
    capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

path "auth/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

path "identity" {
    capabilities = ["read"]
}

path "identity/*" {
    capabilities = [ "create", "read", "update", "delete", "list" ]
}
""",
        )
        return http_code.status_code

    def create_group_global_admin(self):
        """Function that will create a group for the global admins of the vault.
        return : http code.
        """
        url_group = self.url + "/v1/identity/group"
        header = {"X-Vault-Token": self.token}
        data = {
            "name": "vault-global-admins",
            "policies": ["vault-global-admins"],
        }
        http_code = requests.post(url_group, headers=header, json=data)
        return http_code.status_code
