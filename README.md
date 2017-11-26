OctoPrint LDAP auth Plugin
=========================

This plugin allow users to be connected using an LDAP server.
This system works 

#### Details

When you try to login, OctoPrint search for user in this local database (users.yaml)
- If it found a user, check if this user exists also on LDAP
- If user exists on LDAP, use LDAP bind() to check login / password
- If user not exists on LDAP, use native password system to check it

======================================

- If it not found a user in local database, try to connect directly on LDAP
- If login on LDAP il OK, a new local user is added with role "user" and a random password (password should never be used)
- User is connected

======================================

- An admin (default user for exemple), could change a user permissions or account state.
- Password of LDAP users can't be changed

#### Configuration

You could configure LDAP server in plugin config, or manually in config.yaml

```
accessControl:
  ldap_uri: ldaps://ldap.server.com/
  ldap_tls_reqcert: demand
  ldap_search_base: dc=server,dc=com
```

#### Installation

You can install it using ```pip install https://github.com/malnvenshorn/OctoPrint-FilamentManager/archive/master.zip```

Or with plugin manager into OctoPrint
