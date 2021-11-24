"""
LDAP related functions.

IMPORTANT: This module is a modified version of the Kadi4Mat code published by the Karlsruhe Institute of Technology.
Original file: kadi/lib/ldap.py
Changes:
    - file modified to remove all uses of 'flask'
    - match documentation syntax to the rest of the project
"""
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

import ssl

import ldap3 as ldap
from ldap3.utils.dn import parse_dn


def make_upn(username, dn):
    """Create a user principal name (UPN) for use in an Active Directory.

    @param username: The name of a user to use as a prefix for the UPN.
    @type username: L{str}
    @param dn: A DN to parse in order to retrieve the suffix of the UPN.
    @type dn: L{str}
    @return: The UPN in the form of ``"<username>@<domain>"`` or ``None`` if the given
        DN could not be parsed or does not contain any domain components.
    @rtype: L{str} or L{None}
    """
    try:
        rdns = parse_dn(dn)
    except:
        return None

    dcs = []
    for rdn in rdns:
        if rdn[0].lower() == "dc":
            dcs.append(rdn[1])

    if len(dcs) == 0:
        return None

    return f"{username}@{'.'.join(dcs)}"


def bind(connection):
    """Try to authenticate with a server given an LDAP connection.

    By default, LDAP connections are anonymous. The BIND operation establishes an
    authentication state between a client and a server.

    @param connection: The connection object, see also :func:`make_connection`.
    @type connection: L{ldap3.Connection}
    @return: ``True`` if the BIND operation was successful, ``False`` otherwise.
    @rtype: L{bool}
    """
    try:
        return connection.bind()
    except Exception as e:
        print(e)
        unbind(connection)
        return False


def unbind(connection):
    """Disconnect a given LDAP connection.

    @param connection: The connection object, see also :func:`make_connection`.
    @type connection: L{ldap3.Connection}
    """
    try:
        connection.unbind()
    except:
        pass


def make_server(host, port=389, use_ssl=False, validate_cert="REQUIRED"):
    r"""Create a new LDAP ``Server`` object.

    @param host: The host name or IP address of the LDAP server.
    @type host: L{str}
    @param port: (optional) The port the LDAP server is listening on.
    @type port: L{int}
    @param use_ssl: (optional) Flag indicating whether the whole connection should be
        secured via SSL.
    @type use_ssl: L{bool}
    @param validate_cert: (optional) Whether the certificate of the server should be
        validated. One of ``"NONE"``, ``"OPTIONAL"`` or ``"REQUIRED"``.
    @type validate_cert: L{str}
    @return: The new ``Server`` object or ``None`` if it could not be created.
    @rtype: L{ldap3.Server}
    """
    try:
        tls = ldap.Tls(
            validate=getattr(ssl, f"CERT_{validate_cert}", ssl.CERT_REQUIRED)
        )
        return ldap.Server(host, port=port, use_ssl=use_ssl, tls=tls)
    except Exception as e:
        print(e)
        return None


def make_connection(server, user=None, password=None, use_starttls=False):
    r"""Create a new LDAP ``Connection`` object.

    @param server: The server object to use for the connection. See :func:`make_server`.
    @type server: L{ldap3.Server}
    @param user: (optional) The user for simple BIND.
    @type user: L{str} or L{None}
    @param password: (optional) The password of the user for simple BIND.
    @type password: L{str}
    @param use_starttls: (optional) Flag indicating whether the connection should be
        secured via STARTTLS.
    @type use_starttls: L{bool}
    @return: The new ``Connection`` object or ``None`` if it could not be created.
    @rtype: L{ldap3.Connection}
    """
    try:
        connection = ldap.Connection(
            server, user=user, password=password, fast_decoder=False, read_only=True
        )

        if use_starttls:
            connection.start_tls()

    except Exception as e:
        print(e)
        return None

    return connection


def search(
    connection, search_base, search_filter, attribute_map, keep_list_attrs=False
):
    """Perform a search in an LDAP database given a connection.

    @param connection: The LDAP connection to use. See :func:`make_connection`.
    @type connection: L{ldap3.Connection}
    @param search_base: The base of the search request.
    @type search_base: L{str}
    @param search_filter: The filter of the search request.
    @type search_filter: L{str}
    @param attribute_map: A dictionary mapping arbitrary names to LDAP attribute names.
        The former names specify the keys to use for each search result (e.g.
        ``"firstname"``), while the latter names specify the name of the attribute that
        should be extracted from the resulting LDAP entry (e.g. ``"givenName"``).
    @type attribute_map: L{dict}
    @param keep_list_attrs: (optional) Flag to indicate if results that have multiple
        values should be returned as lists or not. If not, only the first value of a
        result will be returned.
    @type keep_list_attrs: L{bool}
    @return: A dictionary similar to the given ``attribute_map`` or ``None`` if no
        results could be retrieved. The LDAP attribute names will be replaced by the
        respective result value(s) in the result or with ``None`` if the attribute could
        not be found.
    @rtype: L{dict} or L{None}
    """
    if not connection.bound and not bind(connection):
        return None

    connection.search(search_base, search_filter, attributes=ldap.ALL_ATTRIBUTES)

    if len(connection.entries) != 1:
        return None

    entry = connection.entries[0]

    results = {}
    for attr, ldap_attr in attribute_map.items():
        try:
            value = entry[ldap_attr].value
            if isinstance(value, list) and not keep_list_attrs:
                value = value[0]

            results[attr] = value
        except Exception as e:
            print(e)
            results[attr] = None

    return results


def modify_password(
    connection,
    user, new_password,
    old_password=None,
    active_directory=False
    ):
    """Modify a user's LDAP password using an extended password modification operation.

    @param connection: The LDAP connection to use. See :func:`make_connection`.
    @type connection: L{ldap3.Connection}
    @param user: The user whose password should be changed.
    @type user: L{str}
    @param new_password: The new password of the user.
    @type new_password: L{str}
    @param old_password: (optional) The old password of the user, if the LDAP server
        requires it.
    @type old_password: L{str} or L{None}
    @param active_directory: (optional) Flag indicating whether the LDAP server is an
        Active Directory, which does not support the standard extended password
        modification operation.
    @type active_directory: L{bool}
    @return: A boolean value indicating whether the change was successful.
    @rtype: L{bool}
    """
    if not connection.bound and not bind(connection):
        return False

    if active_directory:
        return connection.extend.microsoft.modify_password(
            user, new_password, old_password=old_password
        )

    return connection.extend.standard.modify_password(
        user=user, new_password=new_password, old_password=old_password
    )
