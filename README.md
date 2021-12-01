# Simple LDAP Auth

This package provides a real basic implementation of an LDAP authentication taken from [Kadi4Mat](https://gitlab.com/iam-cms/kadi).

## Motivation

I found myself in need of a simple LDAP authentication for several projects. Kadi4Mat provides a working and flexible implementation for LDAP authentication, but is quite big. So I decided to make a small package, which is based Kadi4Mat's LDAP code and adds a proper configuration.

## Installation

Run `pip install git+ssh://git@github.com/bennr01/simpleldapauth'`.

## Usage

First, create a LDAP configuration file like this:

```json
{
    "host": "example.org",
    "port": 636,
    "user_dn": "",
    "active_directory": false,
    "use_ssl": true,
    "validate_cert": true,
    "username_attr": "sAMAccountName",
    "bind_username": null,
    "bind_password": null
}
```

Then, import the modules: `from simpleldapauth.config import LdapConfig` and `from simpleldapauth.auth import ldap_login`.
Load the configuration: `config = LdapConfig.load_from_path("/path/to/config.json")`.
Finally, you can try to authenticate a user: `ldap_login(config, "some_user", "password_for_user")`.
This will return either `True` or `False`, depending on the success.

## Aknowledgements

90% of this code is taken from [Kadi4Mat](https://gitlab.com/iam-cms/kadi).


## Changes of code compared to original Kadi4Mat version:

- removed everything flask related
- modified files to match used documentation style/syntax
