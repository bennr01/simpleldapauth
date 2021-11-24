"""
This module contains the LDAP connection configuration.
"""
import json

class LdapConfig(object):
    """
    This class manages the LDAP connection information.
    """
    
    def __init__(
        self,
        host,
        user_dn,
        port=636,
        active_directory=False,
        use_ssl=True,
        validate_cert=True,
        username_attr="SAMAccountName",
        bind_username=None,
        bind_password=None,
        ):
        """
        The main constructor.
        
        @param host: host to connect to
        @type host: L{str}
        @param user_dn:
        @type user_dn: L{str}
        @param port: port to connect to
        @type port: L{int}
        @param active_directory: if nonzero, assume server is an active directory_server
        @type active_directory: L{bool}
        @param use_ssl: if nonzero (default), connect via SSL/TLS
        @type use_ssl: L{bool}
        @param validate_cert: if nonzero (default), validate TLS certificate
        @type validate_cert: L{bool}
        @param username_attr: the attribute used as username
        @type username_attr: L{str}
        @param bind_username: if specified, bind with this username
        @type bind_username: L{str}
        @param bind_password: if specified, bind with this password
        @type bind_password: L{str}
        """
        assert isinstance(host, str)
        assert isinstance(user_dn, str)
        assert isinstance(port, int) and port > 0
        assert isinstance(username_attr, str)
        assert isinstance(bind_username, str) or (bind_username is None)
        assert isinstance(bind_password, str) or (bind_password is None)
        self.host = host
        self.user_dn = user_dn
        self.port = port
        self.active_directory = active_directory
        self.use_ssl = use_ssl
        self.validate_cert = validate_cert
        self.username_attr = username_attr
        self.bind_username = bind_username
        self.bind_password = bind_password
            
    @classmethod
    def load_from_path(cls, path):
        """
        Load the ldap connection config from the specified path.
    
        @param path: path to load from
        @type path: L{str}
        @return: the config
        @rtype: L{LdapConfig}
        """
        with open(path, "r") as fin:
            content = json.load(fin)
        return cls(
            host=content["host"],
            user_dn=content["user_dn"],
            port=content.get("port", 636),
            active_directory=content.get("active_directory", False),
            use_ssl=content.get("use_ssl", True),
            validate_cert=content.get("validate_cert", True),
            username_attr=content.get("username_attr", "sAMAccountName"),
            bind_username=content.get("bind_username", None),
            bind_password=content.get("bind_password", None),
        )
