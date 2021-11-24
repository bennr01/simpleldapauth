"""
LDAP search utilities.

IMPORTANT: this file contains modified code originally from the Kadi4Mat project published by the Karlsruhe Institute of Technology.
Original file: kadi/modules/accounts/providers/ldap.py
Changes:
    - remove pretty much everything other than parts of the "LDAPProvider.authenticate" method
    - rename, modify and repurpose said method so it can be used to read LDAP attributes
    - adjust documentation syntax to match the rest of the project
    - change configuration related code to work with this package's configuration mechaning

"""
import ldap3

from .ldap import make_server, make_connection, make_upn, bind


def get_ldap_attribute(ldapconfig, username, attr_name):
    """
    Get the LDAP attribute of a user.

    @param ldapconfig: information on how to connect and authenticate
    @type ldapconfig: L{simpleldapauth.config.LdapConfig}
    @param username: username to get the attribute for
    @type username: L{str}
    @param attr_name: name of attribute to get
    @type attr_name: L{str}
    @return: the attribute
    @rtype: L{str}
    """
    server = make_server(
        ldapconfig.host,
        port=ldapconfig.port,
        use_ssl=ldapconfig.use_ssl,
        validate_cert="REQUIRED" if ldapconfig.validate_cert else "NONE",
    )
    if server is None:
        raise Exception("Can't connect to LDAP server!")

    bindusername, bindpassword = ldapconfig.bind_username, ldapconfig.bind_password
    binduser = "{}={},{}".format(ldapconfig.username_attr, bindusername, ldapconfig.user_dn)
    if ldapconfig.active_directory:
        binduser = make_upn(bindusername, ldapconfig.user_dn)
    conn = make_connection(server, user=binduser, password=bindpassword)
    if conn is None or not bind(conn):
        raise Exception("Can't connect to LDAP server or bind failed!")

    success = conn.search(
        ldapconfig.user_dn,
        "(&(objectClass=Person)({}={}))".format(ldapconfig.username_attr, username),
        search_scope=ldap3.SUBTREE,
        attributes=[attr_name],
    )
    if not success or (len(conn.entries) == 0):
        return None
    rv = getattr(conn.entries[0], attr_name, None)
    if rv is None:
        return None
    return rv.value
