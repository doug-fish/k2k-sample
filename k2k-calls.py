# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from keystoneclient.auth.identity import v3
from keystoneclient import session
from keystoneclient.v3 import client
from keystoneclient.v3.contrib.federation import service_providers


def main():
    auth_url = os.environ.get("OS_AUTH_URL")
    username = os.environ.get("OS_USERNAME")
    password = os.environ.get("OS_PASSWORD")
    domain = os.environ.get("OS_DOMAIN") or "Default"

    if auth_url is None or username is None or password is None:
        print ("need to set env variables")
        return

    idp_session = session.Session(verify=False)
    # Get authorization plugin for unscoped password
    idp_u_auth = v3.Password(auth_url=auth_url,
                             username=username,
                             password=password,
                             user_domain_name=domain)

    # Get idp unscoped token
    idp_u_auth_ref = idp_u_auth.get_access(idp_session)

    # Get unscoped client
    idp_u_client = client.Client(session=idp_session,
                                 auth=idp_u_auth)

    # Find projects
    idp_projects = idp_u_client.projects.list(
        user=idp_u_auth_ref.user_id)

    # As a shortcut just take the first one
    # Robust processing includes checking each project
    # to make sure user is authorized and project is
    # enabled
    idp_project = idp_projects[0]

    # Get a project scoped auth
    idp_s_auth = v3.Token(auth_url=auth_url,
                          token=idp_u_auth_ref.auth_token,
                          project_id=idp_project.id)

    # Get project scoped token
    idp_s_auth.get_access(idp_session)

    # Get project scoped client
    idp_s_client = client.Client(session=idp_session,
                                 auth=idp_s_auth)

    idp_manager = service_providers.ServiceProviderManager(idp_s_client)
    # Get a list of sp keystones
    for provider in idp_manager.list():
        try:
            remote_login(provider, idp_s_auth)
        except Exception as e:
            print (e)


def remote_login(provider, idp_s_auth):
    sp_session = session.Session(verify=False)
    sp_u_auth = v3.Keystone2Keystone(idp_s_auth,
                                     provider.id)
    sp_u_auth_ref = sp_u_auth.get_access(sp_session)

    sp_u_client = client.Client(session=sp_session,
                                auth=sp_u_auth)
    projects = sp_u_client.federation.projects.list()

    # As a shortcut just take the first one
    # Robust processing includes checking each project
    # to make sure user is authorized and project is
    # enabled
    sp_project = projects[0]

    sp_s_auth = v3.Token(sp_u_auth.auth_url,
                         sp_u_auth_ref.auth_token,
                         project_id=sp_project.id)

    sp_s_auth.get_access(sp_session)

    sp_s_client = client.Client(session=sp_session,
                                auth=sp_s_auth)

    # Proof that it works!
    print ("services on remote machine:")
    print (sp_s_client.services.list())


if __name__ == '__main__':
    main()
