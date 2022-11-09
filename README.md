# OctoPrint Auth LDAP Plugin
---

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/battis/OctoPrint-LDAP/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/battis/OctoPrint-LDAP/?branch=master)

#### Prerequisites

Before installing this plugin, consult [the python-ldap documentation for its build prerequisites on your system](https://www.python-ldap.org/en/python-ldap-3.3.0/installing.html#build-prerequisites) or [instructions for installing pre-built binaries on your system](https://www.python-ldap.org/en/python-ldap-3.3.0/installing.html#pre-built-binaries). For example, on Debian-based systems (such as Raspbian), it is necessary to preinstall a collection of supporting libraries in order for python-ldap to install properly:

```bash
apt-get install build-essential python3-dev python2.7-dev libldap2-dev \
    libsasl2-dev slapd ldap-utils python-tox lcov valgrind
```

Minimally, on Raspbian:

```bash
apt-get install libsasl2-dev python-dev libldap2-dev libssl-dev
```

If installing on Windows, you will need to find the proper pre-built binary of python-ldap, as directed in the [python-ldap documentation](https://www.python-ldap.org/en/python-ldap-3.3.0/installing.html#pre-built-binaries).

#### Installation

You can install this via the OctoPrint plugin manager GUI using this URL:

```
https://github.com/gillg/OctoPrint-LDAP/archive/refs/heads/master.zip
```

The plugin may also be installed within the oprint venv using the command

```bash
pip install https://github.com/battis/OctoPrint-LDAP/archive/master.zip
```

#### General Configuration

You could configure LDAP server in plugin config, or manually in config.yaml

```YAML
plugins:
  auth_ldap:
    uri: ldaps://example.com
    auth_user: example\authuser
    auth_password: s00p3rS3KRE7
    search_base: dc=example,dc=com
    ou: Lab Users, Lab Staff
```

#### Details

The plugin extends the `FilebasedUserManager` to becomae an `LDAPUserManager` such that when a user logs in:

  1. The local `users.yaml` user list is consulted first -- and, if the user is present, treated as the authoritative credential record
  2. If the user is not found locally, the LDAP directory is searched for their username and, optionally, their membership ins specific groups is verified.
  3. If the user is found in the LDAP directory, they are optionally cached locally in `users.yaml` as an `LDAPUser` (extending `User`) with configurable default roles in OctoPrint.
  4. An attempt is made to bind the user to the LDAP directory using the provided password, double-checking that the user is still a member of any required groups, if configured. If successful, the user is logged in.

#### Optional Authenticated Search

Most LDAP servers require some level of authentication to perform a search of the directory. Credentials with which to search the directory can be provided:

```YAML
plugins:
  auth_ldap:
    auth_user: example\authuser
    auth_password: s00p3rS3KRE7
```

If no authentication username is provided, an anonymous search will be performed (which may not generate useful results on most servers). The `auth_user` can be provided as a distinguished name (`uid=authuser,dc=example,dc=com`), principal name (`authuser@example.com`) or UID (`example\authuser`), depending on the needs of the system.

#### Default Roles/Activity

By default, all LDAP users are treated as active OctoPrint users. They may be configured to default to being admins as well. If LDAP users are cached locally, individual users may be marked inactive within OctoPrint and denied access.

#### Local Caching

By default, LDAP users are not cached locally, to prevent the potentially complex outcomes described below.

If the LDAP users are cached locally, admin users can manage user permissions and account state within Octoprint. This would allow the default role for LDAP users to be generic OctoPrint users, but for some trusted individuals to have their OctoPrint permissions upgraded to admin locally. Additionally, LDAP users can procure API keys for the system.

As the plugin's group filter (or the group memberships within the LDAP directory) may change over time, LDAP users' group membership is verified against the configured groups, along with their password, on each login.

In `users.yaml`, the LDAP users are stored thus:

```YAML
example_user:
  active: true
  apikey: null
  dn: cn=Example user,dc=example,dc=com
  groups:
  - ldap_lab_users
  - users
  password: null
  settings: {}
  type: LDAP
```

Note that the password hash is stored as null intentionally, to prevent accidental password matching. The assumption being that, if this plugin is disabled, the LDAP users in `users.yaml` are still parseable by the `FilebasedUserManager` (since doing otherwise causes the system to choke), so lingering cached LDAP users could then be treated as standard local users. Fortunately, as password checking is done by hashing the proffered password and comparing with the stored hash... and nothing hashes to null, it is impossible to provide a password for a cached LDAP user that will provide access.

#### Search Base Gotcha

Observationally, I have noticed that the Microsoft LDAP server appears to require the search base to include an organizational unit, as well as the domain controller. (e.g. `OU=All Users,DC=example,DC=com`), while OpenLDAP appears to be less demanding and will simply accept a domain controller as the search base (e.g. `DC=example,DC=com`).

If your users are partitioned into more than one top-level organizational unit within the Microsoft LDAP server, there is no way to configure a wild-card search base -- the only way forward would likely be to update the plugin source to accept multiple search bases and then search against each base in turn. Or create one super-OU to contain your disparate OUs.

#### Groups

In addition to authenticating against the LDAP directory, users may also be filtered for current membership in specific LDAP groups (a.k.a. OUs or Organizational Units). If not specified, no group membership check is performed. Groups are listed as a comma-separated (white space agnostic) list. For example:

```YAML
plugins:
  auth_ldap:
    ou: Lab Users, Lab Staff
```

If local caching is enabled, LDAP OU groups will by synced as OctoPrint groups, to allow for per-group permissions configuration. All synced groups are subgroups of a parent OctoPrint group. By default the parent group is `LDAP-Authorized Users` with key `ldap` and the synced OU-as-groups are named based on the settings configuration (e.g. `Lab Users` OU would become a group named `Lab Users` with key `ldap_lab_users`).

The naming scheme on these groups can be configured directly through config.yaml with the following keys (and default values):

```YAML
plugins:
  auth_ldap:
    ldap_group_key_prefix: ldap_
    ldap_parent_group_description: Generated by Auth LDAP plugin, with membership synced automatically based on LDAP configuration
    ldap_parent_group_key: ldap
    ldap_parent_group_name: LDAP-Authenticated Users
```

#### Configurable Search Filters

As LDAP directory configuration varies, it may be necessary to configure how users are searched for within the directory.

##### User Search Filter

By default, the provided `userid` is searched for using the provided search base and the search filter template `uid=%s`. This may be configured differently on some systems. For example, one alternate search filter template configuration might be:

```YAML
plugins:
  auth_ldap:
    search_filter: userPrincipalName=%s@example.com
```

This would match the provided username as an email address against the `userPrincipalName` field. The `%s` placeholder would be replaced with the provided user id.

##### Group Membership

Membership in LDAP groups is verified by searching for a group with a particular name that has a member with the LDAP distinguished name (DN) that matches the provided user. Two configuration fields affect this matching:

```YAML
plugins:
  auth_ldap:
    ou_filter: cn=%s
    ou_member_filter: uniqueMember=%s
```

This configuration would generate a search filter that would test against each provided OU name in turn, using the user's LDAP-provided DN: `"(&(cn=%s)(uniqueMember=%s))" % (ou_name, dn)`, which would end up looking like `(&(cn=Lab Users)(uniqueMember=uid=example_user,dc=example.dc=com))`

##### Search Term Transform

OctoPrint searches for users in a case-sensitve manner by default. However, it becomes a management issue (if local caching is turned on) to have cached each case-sensitive search for the same user (e.g. `testuser`, `TESTUSER`, `TestUser`, `tEsTuSeR`, etc.). In order to manage this issue, the `search_term_transform` setting allows you to specify a string transformation (e.g. `upper` or `lower`) to be applied to search terms if they are not found already cached.

```YAML
plugins:
  auth_ldap:
    search_term_transform: lower
```

The result of this will be that the user ID entered in the login dialog will be transformed using this call:

```python
userid = getattr(str, "lower")(str(userid))
```

Note that this does not provide a capability for more nuanced transformations at this pouint.

## Contributors

Original design and implementation by [Gillaume Gill](https://github.com/gillg/OctoPrint-LDAP).

Authenticated lookup, configuration and caching by [Seth Battis](https://github.com/battis/OctoPrint-LDAP).

Initial OctoPrint 1.4 compatibility by [Paul K. Stelis](https://github.com/paulkstelis/OctoPrint-LDAP).

