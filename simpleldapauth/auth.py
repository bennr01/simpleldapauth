"""
This module contains the top level ldap auth logic.

IMPORTANT: this file contains modified code from the Kadi4Mat project published by the Karlsruhe Institute of Technology
Original file: kadi/modules/accounts/providers/ldap.py
Changes:
     - reduce everything to the 'LDAPProvider.authenticate' method and make it a standalone function, renaming it.
     - remove all code not needed for this authentication
     - change code to use this package's configuration mechanic
     - adjust configuration tool
""" 
from .ldap import make_server, make_connection, make_upn, bind


# Copyright 2020 Karlsruhe Institute of Technology
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



def ldap_login(ldapconfig, username, password):
    """
    Perform a login.

    @param ldapconfig: the config for connection and authentication
    @type ldapconfig: L{simpleldapauth.config.LdapConfig}
    @param username: username to use for auth
    @type username: L{str}
    @param password: password to use for auth
    @type password: L{str}
    @return: True on successful login, False otherwise
    @rtype: L{bool}
    """
    server = make_server(
        ldapconfig.host,
        port=ldapconfig.port,
        use_ssl=ldapconfig.use_ssl,
        validate_cert="REQUIRED" if ldapconfig.validate_cert else "NONE",
    )
    if server is None:
        return False
    user = "{}={},{}".format(ldapconfig.username_attr, username, ldapconfig.user_dn)
    if ldapconfig.active_directory:
        user = make_upn(username, ldapconfig.user_dn)
    conn = make_connection(server, user=user, password=password)
    if conn is None or not bind(conn):
        return False
    conn.unbind()
    return True

