#!/usr/bin/env python3
# coding:utf-8

from urllib.parse import urlencode
import requests, json, hvac, sys, os


class Vault:
    def __init__(
        self,
        url,
        password,
        bu,
        project,
        team,
        gaia,
        role,
        engine,
        approle_name,
        role_name,
        policy,
    ):
        """
        # Required parameters
        - url: url racine du endpoint vault
        - user: a user name (a string)
        - password: a user password (a string)
        """
        self.url = url
        self.password = password
        self.bu = bu
        self.project = project
        self.team = team
        self.gaia = gaia
        self.role = role
        self.token = self.get_token()
        self.engine = engine
        self.approle_name = approle_name
        self.role_name = role_name
        self.policy = policy
        self.engines_available = ["kv", "transit", "ssh"]
        self.name = (
            "engie-" + self.bu + "-" + self.project + "-" + self.team + "-"
        )

    def get_token(self):
        """Function that will retrieve the tokens so that TPM can take actions."""
        url_tpm = self.url + "/v1/auth/userpass/login/tpm"
        data = {"password": self.password}
        response = requests.post(url_tpm, json=data)
        data = response.text
        utf8string = data.encode("utf-8")
        res = json.loads(utf8string)
        for i in res["auth"].items():
            if "client_token" in i:
                return str(list(i)[1])

    def get_accessor_id(self):
        """Function that will return the accessor ID of the OIDC authentication method activated in the vault."""
        client = hvac.Client(url=self.url, token=self.token)
        auth_methods = client.sys.list_auth_methods()
        accessor_id = auth_methods["oidc/"]["accessor"]
        return accessor_id

    def create_entity(self):
        """Function which first of all see if the GAIA put in the arguments exists in the entities
        (1 entity = 1 user) and return its ID. Secondly, if the entity does not exist, it will create it and return its ID."""
        url_entity_list = self.url + "/v1/identity/entity/name?list=true"
        header = {"X-Vault-Token": self.token}
        http_code = requests.get(url_entity_list, headers=header)
        json_return = http_code.json()
        entities_names = json_return["data"]["keys"]
        for names in entities_names:
            if self.gaia in names:
                url_entity_name = (
                    self.url + "/v1/identity/entity/name/" + self.gaia
                )
                header = {"X-Vault-Token": self.token}
                http_code = requests.get(url_entity_name, headers=header)
                json_return = http_code.json()
                entity_id = json_return["data"]["id"]
                return entity_id
        # Creation of the entity with the user's GAIA.
        url_entity = self.url + "/v1/identity/entity"
        header = {"X-Vault-Token": self.token}
        data = {
            "name": self.gaia,
            "metadata": {
                "bu": self.bu,
                "project": self.project,
                "team": self.team,
            },
        }
        http_code = requests.post(url_entity, headers=header, json=data)
        json_return = http_code.json()
        entity_id = json_return["data"]["id"]
        return entity_id

    def create_alias(self):
        """Function that will create the alias, this will allow the entity to be linked to the OIDC
        authentication method and will allow when the user is going to connect with OKTA to be linked
        to his entity and to have the correct policies.
        Returns True if everything was fine, False otherwise."""
        header = {"X-Vault-Token": self.token}
        url_alias_list = self.url + "/v1/identity/entity-alias/id?list=true"
        url_alias = self.url + "/v1/identity/entity-alias"
        http_code = requests.get(url_alias_list, headers=header)
        json_return = http_code.json()
        alias_key = json_return["data"]["keys"]
        # We see if the alias exists to avoid creating duplicates.
        return_http_code = []
        for key in alias_key:
            alias_name = json_return["data"]["key_info"][key]
            if self.gaia + "@engie.com" in alias_name.values():
                print("Aliases for " + self.gaia + " already exist")
            else:
                # We create the alias if it does not exist.
                header = {"X-Vault-Token": self.token}
                data = {
                    "name": self.gaia + "@engie.com",
                    "canonical_id": self.create_entity(),
                    "mount_accessor": self.get_accessor_id(),
                }
                http_code = requests.post(url_alias, headers=header, json=data)
                return_http_code.append(http_code.status_code)
        return return_http_code

    def create_group(self):
        """Function that will create the admin, user and reader groups for each team within a project."""
        url_group_list = self.url + "/v1/identity/group/id?list=true"
        header = {"X-Vault-Token": self.token}
        http_code = requests.get(url_group_list, headers=header)
        json_return = http_code.json()
        types_of_groups = ["admin", "user", "reader"]
        # If no group exists, the fact that there is no group is taken into account.
        if "errors" in json_return:
            return_http_code_1 = []
            for types in types_of_groups:
                url_group = self.url + "/v1/identity/group"
                header = {"X-Vault-Token": self.token}
                data = {
                    "name": "engie-digital-"
                    + self.project
                    + "-"
                    + self.team
                    + "-"
                    + types,
                    "metadata": {"bu": self.bu},
                    "policies": [
                        "engie-digital-"
                        + self.project
                        + "-"
                        + self.team
                        + "-"
                        + types
                    ],
                }
                http_code_1 = requests.post(
                    url_group, headers=header, json=data
                )
                return_http_code_1.append(http_code_1.status_code)
            return return_http_code_1
        # If groups already exist, we create those requested.
        else:
            return_http_code_2 = []
            for types in types_of_groups:
                url_group = self.url + "/v1/identity/group"
                header = {"X-Vault-Token": self.token}
                data = {
                    "name": "engie-digital-"
                    + self.project
                    + "-"
                    + self.team
                    + "-"
                    + types,
                    "metadata": {"bu": self.bu},
                    "policies": [
                        "engie-digital-"
                        + self.project
                        + "-"
                        + self.team
                        + "-"
                        + types
                    ],
                }
                http_code_2 = requests.post(
                    url_group, headers=header, json=data
                )
                return_http_code_2.append(http_code_2.status_code)
            return return_http_code_2

    def add_entity_group(self):
        """Function which will add an entity (= a user) in a group without deleting those already present."""
        url_group_name = (
            self.url
            + "/v1/identity/group/name/engie-digital-"
            + self.project
            + "-"
            + self.team
            + "-"
            + self.role
        )
        header = {"X-Vault-Token": self.token}
        http_code = requests.get(url_group_name, headers=header)
        json_return = http_code.json()
        group_member = json_return["data"]["member_entity_ids"]
        entity_id = self.create_entity()
        group_member.append(entity_id)
        header = {"X-Vault-Token": self.token}
        data = {"member_entity_ids": group_member}
        http_code = requests.post(url_group_name, headers=header, json=data)
        return http_code.status_code

    def remove_entity_group(self):
        """Function that will remove entities from groups."""
        url_group_name = (
            self.url
            + "/v1/identity/group/name/engie-digital-"
            + self.project
            + "-"
            + self.team
            + "-"
            + self.role
        )
        header = {"X-Vault-Token": self.token}
        http_code = requests.get(url_group_name, headers=header)
        json_return = http_code.json()
        group_member = json_return["data"]["member_entity_ids"]
        # on trouve le nom de l'entité à partir de l'ID.
        url_entity_list = self.url + "/v1/identity/entity/name/" + self.gaia
        header = {"X-Vault-Token": self.token}
        http_code = requests.get(url_entity_list, headers=header)
        json_return = http_code.json()
        entities_id = json_return["data"]["aliases"]
        return_http_code = []
        for ids in entities_id:
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

    def delete_entity(self):
        """Function go to delete the alias of the entity then the entity thanks to the information passed in parameter."""
        # We retrieve the ID of the entity.
        url_entity_list = self.url + "/v1/identity/entity/name?list=true"
        header = {"X-Vault-Token": self.token}
        http_code = requests.get(url_entity_list, headers=header)
        json_return = http_code.json()
        entities_names = json_return["data"]["keys"]
        # For each ID present in the vault we delete the one that has the name of the entity.
        return_http_code = []
        for names in entities_names:
            if self.gaia in names:
                url_entity_name = (
                    self.url + "/v1/identity/entity/name/" + self.gaia
                )
                header = {"X-Vault-Token": self.token}
                get_entity = requests.get(url_entity_name, headers=header)
                get_entity_json = get_entity.json()
                entity_id = get_entity_json["data"]["id"]
                url_entity_delete = (
                    self.url + "/v1/identity/entity/id/" + entity_id
                )
                http_code = requests.delete(url_entity_delete, headers=header)
                return_http_code.append(http_code.status_code)
        return return_http_code

    def delete_group(self):
        """Function that remove groups from a team."""
        url_group_list = self.url + "/v1/identity/group/id?list=true"
        header = {"X-Vault-Token": self.token}
        http_code = requests.get(url_group_list, headers=header)
        json_return = http_code.json()
        alias_key = json_return["data"]["keys"]
        # The group IDs are placed in a list.
        lists_of_groups = []
        for key in alias_key:
            alias_name = json_return["data"]["key_info"][key]
            if (
                "engie-digital-" + self.project + "-" + self.team + "-admin"
                in alias_name.values()
            ):
                lists_of_groups.append(key)
            elif (
                "engie-digital-" + self.project + "-" + self.team + "-user"
                in alias_name.values()
            ):
                lists_of_groups.append(key)
            elif (
                "engie-digital-" + self.project + "-" + self.team + "-reader"
                in alias_name.values()
            ):
                lists_of_groups.append(key)
        # For each ID we will delete the group.
        return_http_code = []
        for group in lists_of_groups:
            url_group_id = self.url + "/v1/identity/group/id/" + group
            header = {"X-Vault-Token": self.token}
            http_code = requests.delete(url_group_id, headers=header)
            return_http_code.append(http_code.status_code)
        return return_http_code

    def creation_policy(self):
        """Function to create the admin, user and reader policies for each team."""
        client = hvac.Client(url=self.url, token=self.token)
        policies_to_create = [
            "engie-"
            + self.bu
            + "-"
            + self.project
            + "-"
            + self.team
            + "-admin",
            "engie-"
            + self.bu
            + "-"
            + self.project
            + "-"
            + self.team
            + "-user",
            "engie-"
            + self.bu
            + "-"
            + self.project
            + "-"
            + self.team
            + "-reader",
        ]
        list_policies = client.sys.list_policies()["data"]["policies"]
        return_http_code = []
        for policies in policies_to_create:
            if policies in list_policies:
                return_http_code.append("policy already exist " + policies)
            else:
                http_code = client.sys.create_or_update_policy(
                    name=policies, policy="""# Policy create by TPM"""
                )
                return_http_code.append(http_code.status_code)
        return return_http_code

    def update_tpm_policy(self, name):
        """Function that allows you to update the TPM policy when creating a new secret to be
        able to interact with it."""
        policy = (
            """
path "%s/*" {
    capabilities = ["create", "update", "delete"]
}
    """
            % name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(name="tpm-policy")["data"][
            "rules"
        ]
        if 'path "' + name + '/*"' in hvac_policy_rules:
            print("secret " + name + " already in TPM policy.")
        else:
            send_new_policy = hvac_policy_rules + policy
            client.sys.create_or_update_policy(
                name="tpm-policy", policy=send_new_policy
            )
            print("secret " + name + " add in TPM policy")

    def update_admin_policy(self, name):
        """Function that will update the admin policy by adding the path and capabilities of the new secret engine."""
        policy = (
            """
path "%s/*" {
    capabilities = ["create", "update", "delete", "list", "read"]
}
    """
            % name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(name=self.name + "admin")[
            "data"
        ]["rules"]
        condition = 'path "' + name + '/*"'
        if condition in hvac_policy_rules:
            print("secret " + name + " already in admin policy.")
        else:
            send_new_policy = hvac_policy_rules + policy
            client.sys.create_or_update_policy(
                name=self.name + "admin", policy=send_new_policy
            )
            print("secret " + name + " add in admin policy")

    def update_user_policy(self, name):
        """Function that will update the policy user by adding the path and capabilities of the new secret engine."""
        policy_user = (
            """
path "%s/*" {
    capabilities = ["create", "update", "list", "read"]
}
    """
            % name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(name=self.name + "user")[
            "data"
        ]["rules"]
        if 'path "' + name + '/*"' in hvac_policy_rules:
            print("secret " + name + " already in user policy.")
        else:
            send_new_policy = hvac_policy_rules + policy_user
            client.sys.create_or_update_policy(
                name=self.name + "user", policy=send_new_policy
            )
            print("secret " + name + " add in user policy")

    def update_reader_policy(self, name):
        """Function that will update the policy reader by adding the path and capabilities of the new secret engine."""
        policy_reader = (
            """
path "%s/*" {
    capabilities = ["list", "read"]
}
    """
            % name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(name=self.name + "reader")[
            "data"
        ]["rules"]
        if 'path "' + name + '/*"' in hvac_policy_rules:
            print("secret " + name + " already in reader policy.")
        else:
            send_new_policy = hvac_policy_rules + policy_reader
            client.sys.create_or_update_policy(
                name=self.name + "reader", policy=send_new_policy
            )
            print("secret " + name + " add in reader policy")

    def enable_secret_engines(self):
        """Function that creates the secret engine and calls the functions to add it to the policies."""
        return_http_code = []
        name = self.name + self.engine
        if self.engine in self.engines_available:
            url = self.url + "/v1/sys/mounts/" + name
            header = {"X-Vault-Token": self.token}
            if self.engine == "kv":
                data = {"type": "kv", "options": {"version": "2"}}
            if self.engine == "transit":
                data = {"type": "transit"}
            if self.engine == "ssh":
                data = {"type": "ssh"}
            http_code = requests.post(url, headers=header, json=data)
            return_http_code.append(http_code.status_code)
            self.update_tpm_policy(name)
            self.update_admin_policy(name)
            self.update_user_policy(name)
            self.update_reader_policy(name)
            # The return is for the http answer when you enable the secret engine.
            return return_http_code
        return "Not autorize to create this type of secret engine"

    def delete_tpm_policy(self, name):
        """Function that will remove the secret engine from the TPM policy."""
        policy = (
            """
path "%s/*" {
    capabilities = ["create", "update", "delete"]
}
    """
            % name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(name="tpm-policy")["data"][
            "rules"
        ]
        if 'path "' + name + '/*"' not in hvac_policy_rules:
            print("secret " + name + " not in TPM policy.")
        else:
            policy_update = hvac_policy_rules.replace(policy, "")
            client.sys.create_or_update_policy(
                name="tpm-policy", policy=policy_update
            )
            print("secret " + name + " remove in TPM policy")

    def delete_admin_policy(self, name):
        """Function that will remove the secret engine from the policy admin."""
        policy = (
            """
path "%s/*" {
    capabilities = ["create", "update", "delete", "list", "read"]
}
    """
            % name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(name=self.name + "admin")[
            "data"
        ]["rules"]
        if 'path "' + name + '/*"' not in hvac_policy_rules:
            print("secret " + name + " not in admin policy.")
        else:
            policy_update = hvac_policy_rules.replace(policy, "")
            client.sys.create_or_update_policy(
                name=self.name + "admin", policy=policy_update
            )
            print("secret " + name + " remove in admin policy")

    def delete_user_policy(self, name):
        """Function that will remove the secret engine from the policy user."""
        policy = (
            """
path "%s/*" {
    capabilities = ["create", "update", "list", "read"]
}
    """
            % name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(name=self.name + "user")[
            "data"
        ]["rules"]
        if 'path "' + name + '/*"' not in hvac_policy_rules:
            print("secret " + name + " not in user policy.")
        else:
            policy_update = hvac_policy_rules.replace(policy, "")
            client.sys.create_or_update_policy(
                name=self.name + "user", policy=policy_update
            )
            print("secret " + name + " remove in user policy")

    def delete_reader_policy(self, name):
        """Function that will remove the secret engine from the policy reader."""
        policy = (
            """
path "%s/*" {
    capabilities = ["list", "read"]
}
    """
            % name
        )
        client = hvac.Client(url=self.url, token=self.token)
        hvac_policy_rules = client.sys.read_policy(name=self.name + "reader")[
            "data"
        ]["rules"]
        if 'path "' + name + '/*"' not in hvac_policy_rules:
            print("secret " + name + " not in reader policy.")
        else:
            policy_update = hvac_policy_rules.replace(policy, "")
            client.sys.create_or_update_policy(
                name=self.name + "reader", policy=policy_update
            )
            print("secret " + name + " remove in reader policy")

    def delete_secret_engines(self):
        """Function which will delete the secret engine and call the functions to delete it from the policies."""
        return_http_code = []
        client = hvac.Client(url=self.url, token=self.token)
        name = self.name + self.engine
        secrets_engines_list = client.sys.list_mounted_secrets_engines()[
            "data"
        ]
        for secrets in secrets_engines_list:
            if name in secrets:
                http_code = client.sys.disable_secrets_engine(name)
                return_http_code.append(http_code.status_code)
                self.delete_tpm_policy(name)
                self.delete_admin_policy(name)
                self.delete_user_policy(name)
                self.delete_reader_policy(name)
        return return_http_code, "secret engine " + name + " disable"

    def enable_approle(self):
        """Function that will activate AppRole authentication for a project."""
        # Activation de l'authent approle.
        name = self.name + self.approle_name
        url = self.url + "/v1/sys/auth/" + name
        header = {"X-Vault-Token": self.token}
        data = {"type": "approle"}
        http_code_1 = requests.post(url, headers=header, json=data)
        # On créé également un secret engine avec le même nom que l'approle authent.
        url = self.url + "/v1/sys/mounts/" + name
        header = {"X-Vault-Token": self.token}
        data = {"type": "kv", "options": {"version": "2"}}
        http_code_2 = requests.post(url, headers=header, json=data)
        # We update the TPM policy to access the secret and interact with it.
        self.update_tpm_policy(name)
        self.update_admin_policy(name)
        self.update_user_policy(name)
        self.update_reader_policy(name)
        return http_code_1.status_code, http_code_2.status_code

    def creation_approle_role(self):
        """Function that will create a role in the AppRole previously created, this will allow us to
        generate a RoleID and a SecretID."""
        name = self.name + self.approle_name
        policy = self.name + self.policy
        policies = "default," + policy
        list_of_policies = policies.split(",")
        url = self.url + "/v1/auth/" + name + "/role/" + self.role_name
        header = {"X-Vault-Token": self.token}
        data = {"token_policies": list_of_policies}
        http_code = requests.post(url, headers=header, json=data)
        return http_code.status_code

    def roleid_secretid(self):
        """Function that will generate a RoleID and a SecretID and place them in a secret."""
        # Retrieving the roleID.
        path = self.name + self.approle_name
        url1 = (
            self.url
            + "/v1/auth/"
            + path
            + "/role/"
            + self.role_name
            + "/role-id"
        )
        header = {"X-Vault-Token": self.token}
        http_code_1 = requests.get(url1, headers=header)
        roleid_dict = json.loads(http_code_1.text)
        for i in roleid_dict:
            if i == "data":
                roleid = list(roleid_dict[i].values())[0]
        # Creation of the secretID.
        url2 = (
            self.url
            + "/v1/auth/"
            + path
            + "/role/"
            + self.role_name
            + "/secret-id"
        )
        header = {"X-Vault-Token": self.token}
        http_code_2 = requests.post(url2, headers=header)
        secretid_dict = json.loads(http_code_2.text)
        for i in secretid_dict:
            if i == "data":
                secretid = list(secretid_dict[i].values())[0]
        # The RoleID and SecretID are entered in the secret of the team.
        self.update_secret(path, "roleid", roleid, "secretid", secretid)
        return http_code_1.status_code, http_code_2.status_code

    def update_secret(self, path, key1, value1, key2, value2):
        """Update of RoleID and SecretID secrets."""
        url = self.url + "/v1/" + path + "/data/approle"
        header = {"X-Vault-Token": self.token}
        data = {"data": {key1: value1, key2: value2}}
        http_code = requests.post(url, headers=header, json=data)
        print(http_code.status_code)

    def suppression_approle_role(self):
        """Function that will delete a role in the previously created AppRole."""
        name = self.name + self.approle_name
        url = self.url + "/v1/auth/" + name + "/role/" + self.role_name
        header = {"X-Vault-Token": self.token}
        http_code = requests.delete(url, headers=header)
        return http_code.status_code

    def disable_approle(self):
        """Function that disable AppRole authentication for a project."""
        name = self.name + self.approle_name
        url = self.url + "/v1/sys/auth/" + name
        header = {"X-Vault-Token": self.token}
        http_code = requests.delete(url, headers=header)
        # We update the TPM policy to delete the access to the secret.
        self.delete_tpm_policy(name)
        self.delete_admin_policy(name)
        self.delete_user_policy(name)
        self.delete_reader_policy(name)
        os.system(
            "vault secrets disable -address=" + self.url + " " + name + "/"
        )
        # The return senf back the http code when he disable the authent method.
        return http_code.status_code


if __name__ == "__main__":
    URL = "https://vault.dev.tools.digital.engie.com"
    vault = Vault(
        URL,
        "[,J52-Cg5q3DH6!Rvgr(",
        sys.argv[4],
        sys.argv[5],
        sys.argv[6],
        sys.argv[7],
        sys.argv[8],
        sys.argv[9],
        sys.argv[10],
        sys.argv[11],
        sys.argv[12],
    )

####
# A quoi corresponde les argv.
####
# BU = sys.argv[4] ; PROJECT = sys.argv[5] ; TEAM = sys.argv[6] ; GAIA = sys.argv[7] ; ; ROLE = sys.argv[8] ; ENGINE_TO_DEPLOY = sys.argv[9] ; APPROLE_NAME = sys.argv[10] ; ROLE_NAME = sys.argv[11], POLICY = sys.argv[12]

####
# Commandes pour tester.
####
# if sys.argv[2] == "create":
#     if sys.argv[3] == "entity":
#         # ./vault.py dev create entity digital walnut infra rv5791 admin kv jenkins application2 reader
#         print(vault.create_alias())
#     elif sys.argv[3] == "group":
#         # ./vault.py dev create group digital walnut infra rv5791 admin kv jenkins application2 reader
#         print(vault.create_group())
# elif sys.argv[2] == "add":
#     # ./vault.py dev add entity digital walnut infra rv5791 admin kv jenkins application2 reader
#     print(vault.add_entity_group())
# elif sys.argv[2] == "remove":
#     # ./vault.py dev remove entity digital walnut infra rv5791 admin kv jenkins application2 reader
#     print(vault.remove_entity_group())
# elif sys.argv[2] == "delete":
#     if sys.argv[3] == "entity":
#         # ./vault.py dev delete entity digital walnut infra rv5791 admin kv jenkins application2 reader
#         print(vault.delete_entity())
#     elif sys.argv[3] == "group":
#         # ./vault.py dev delete group digital walnut infra rv5791 admin kv jenkins application2 reader
#         print(vault.delete_group())

# if sys.argv[2] == "create":
#     # ./vault.py dev create group digital walnut infra rv5791 admin kv jenkins application2 reader
#     # ./vault.py dev create group digital walnut infra rv5791 admin transit jenkins application2 reader
#     # ./vault.py dev create group digital walnut infra rv5791 admin ssh jenkins application2 reader
#     print(vault.creation_policy())
#     print(vault.enable_secret_engines())
# elif sys.argv[2] == "delete":
#     # ./vault.py dev delete group digital walnut infra rv5791 admin kv jenkins application2 reader
#     # ./vault.py dev delete group digital walnut infra rv5791 admin transit jenkins application2 reader
#     # ./vault.py dev delete group digital walnut infra rv5791 admin ssh jenkins application2 reader
#     print(vault.delete_secret_engines())

# if sys.argv[2] == "enable_approle":
#     # ./vault.py dev enable_approle group digital walnut infra rv5791 admin kv jenkins application3 reader
#     print(vault.enable_approle())
# elif sys.argv[2] == "creation_approle_role":
#     # ./vault.py dev creation_approle_role group digital walnut infra rv5791 admin kv jenkins application3 reader
#     print(vault.creation_approle_role())
# elif sys.argv[2] == "roleid_secretid":
#     # ./vault.py dev roleid_secretid group digital walnut infra rv5791 admin kv jenkins application3 reader
#     print(vault.roleid_secretid())
# elif sys.argv[2] == "suppression_approle_role":
#     # ./vault.py dev suppression_approle_role group digital walnut infra rv5791 admin kv jenkins application3 reader
#     print(vault.suppression_approle_role())
# elif sys.argv[2] == "disable_approle":
#     # ./vault.py dev disable_approle group digital walnut infra rv5791 admin kv jenkins application3 reader
#     print(vault.disable_approle())

