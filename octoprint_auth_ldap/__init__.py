# coding=utf-8
from __future__ import absolute_import

import json
import ldap
from ldap.filter import filter_format
import octoprint.plugin
from octoprint.users import FilebasedUserManager, User, UserManager, UserAlreadyExists
from octoprint.util import atomic_write
import os
import yaml


class LDAPUser(User):
    USER_TYPE = "LDAP"

    def __init__(self, username, active=True, roles=None, dn=None, groups=None, apikey=None, settings=None):
        User.__init__(self, username, None, active, roles, apikey)
        self._dn = dn
        self._groups = groups

    def distinguished_name(self):
        return self._dn

    def groups(self):
        return self._groups


class LDAPUserManager(FilebasedUserManager,
                      octoprint.plugin.SettingsPlugin,
                      octoprint.plugin.TemplatePlugin):

    ###################################################################
    # UserManager overrides

    def findUser(self, userid=None, apikey=None, session=None):
        self._logger.debug("Search for userid=%s, apiKey=%s, session=%s" % (userid, apikey, session))
        user = FilebasedUserManager.findUser(self, userid=userid, apikey=apikey, session=session)

        if user is None and userid is not None:
            self._logger.debug("User %s not found locally, treating as LDAP" % userid)
            search_filter = self.get_plugin_setting("search_filter")

            # operating on the wildly unsafe assumption that the admin who configures this plugin will have their head
            # screwed on right and NOT escaping their search strings... only escaping unsafe user-entered text that is
            # passed directly to search filters
            ldap_user = self.ldap_search(filter_format(search_filter, (userid,)))

            if ldap_user is not None:
                self._logger.debug("%s found as dn=%s" % (userid, ldap_user["dn"]))
                groups = self.group_filter(ldap_user["dn"])
                if isinstance(groups, list):
                    self._logger.debug("Creating new LDAPUser %s" % userid)
                    # TODO: make username configurable or make dn configurable (e.g. could be userPrincipalName?)
                    if self.get_plugin_setting("local_cache"):
                        self.addUser(username=userid, dn=ldap_user["dn"], groups=groups, active=True)
                        user = self._users[userid]
                    else:
                        user = LDAPUser(username=userid, dn=ldap_user["dn"], groups=groups, active=True,
                                        roles=self.default_roles())
        return user

    # this will return either an empty list (i.e. []) (if no groups are specified in configuration) or a list of groups
    # that the user is currently a member of (e.g. ["Lab Users"]), or False if the groups filter is configured and the
    # user is not a member of any configured groups
    def group_filter(self, dn):
        groups = self.get_plugin_setting("groups")
        actual_groups = []
        if groups is not None:
            group_filter = self.get_plugin_setting("group_filter")
            group_member_filter = self.get_plugin_setting("group_member_filter")
            for group in str(groups).split(","):
                result = self.ldap_search("(&" +
                                          "(" + group_filter % group.strip() + ")" +
                                          "(" + (group_member_filter % dn) + ")" +
                                          ")")
                if result is not None:
                    actual_groups.append(group)
            if not actual_groups:
                return False
        return actual_groups

    def default_roles(self):
        roles = []
        if self.get_plugin_setting("default_role_user"):
            roles.append("user")
        if self.get_plugin_setting("default_role_admin"):
            roles.append("admin")
        return roles

    def addUser(self, username, password=None, active=False, roles=None, apikey=None, overwrite=False, dn=None,
                groups=None):
        if not roles:
            roles = self.default_roles()

        if username in self._users.keys() and not overwrite:
            raise UserAlreadyExists(username)

        if dn is not None and password is None:
            if groups is None:
                groups = []
            self._users[username] = LDAPUser(username, active, roles, dn, groups, apikey)
        else:
            self._users[username] = User(username,
                                         UserManager.createPasswordHash(password, settings=self._settings),
                                         active,
                                         roles,
                                         apikey=apikey)
        self._dirty = True
        self._save()

    def checkPassword(self, username, password):
        user = self.findUser(userid=username)
        self._logger.debug("%s is a %s" % (username, type(user)))
        if isinstance(user, LDAPUser):
            # in case group settings changed either in auth_ldap settings OR on LDAP directory
            if user.is_active() and isinstance(self.group_filter(user.distinguished_name()), list):
                self._logger.debug("Checking %s password via LDAP" % username)
                client = self.get_ldap_client(user.distinguished_name(), password)
                return client is not None
            else:
                self._logger.debug("%s is inactive or no longer a member of required groups" % username)
        else:
            self._logger.debug("Checking %s password via file" % username)
            return FilebasedUserManager.checkPassword(self, username, password)
        return False

    # Get a setting, setting to default value if not already set
    def get_plugin_setting(self, key):
        value = self._settings.get(["plugins", "auth_ldap", key])
        if value is None:
            value = self.get_settings_defaults()[key]
            self._settings.set(["plugins", "auth_ldap", key], value)
        return value

    # since the FilebasedUserManager doesn't provide mixins or hooks for overriding loads, we have
    # to copy the original code wholesale and make edits
    def _load(self):
        if os.path.exists(self._userfile) and os.path.isfile(self._userfile):
            self._customized = True
            with open(self._userfile, "r") as f:
                data = yaml.safe_load(f)
                for name in data.keys():
                    attributes = data[name]
                    apikey = None
                    if "apikey" in attributes:
                        apikey = attributes["apikey"]
                    settings = dict()
                    if "settings" in attributes:
                        settings = attributes["settings"]
                    user_type = False
                    if "type" in attributes:
                        user_type = attributes["type"]
                    self._logger.debug("%s loaded as %s" % (name, user_type))
                    if user_type == LDAPUser.USER_TYPE:
                        self._users[name] = LDAPUser(username=name, active=attributes["active"],
                                                     roles=attributes["roles"], groups=attributes["groups"],
                                                     dn=attributes["dn"], apikey=apikey, settings=settings)
                    else:
                        self._users[name] = User(name, attributes["password"], attributes["active"],
                                                 attributes["roles"],
                                                 apikey=apikey, settings=settings)
                    for sessionid in self._sessionids_by_userid.get(name, set()):
                        if sessionid in self._session_users_by_session:
                            self._session_users_by_session[sessionid].update_user(self._users[name])
        else:
            self._customized = False

    # since the FilebasedUserManager doesn't provide mixins or hooks for overriding saves, we have
    # to copy the original code wholesale and make edits
    def _save(self, force=False):
        if not self._dirty and not force:
            return

        data = {}
        for name in self._users.keys():
            user = self._users[name]
            if isinstance(user, LDAPUser):
                data[name] = {
                    "type": LDAPUser.USER_TYPE,
                    "password": None,  # password field has to exist because of how FilebasedUserManager processes
                    # data, but an empty password hash cannot match any entered password (as
                    # whatever the user enters will be hashed... even an empty password.
                    "dn": user.distinguished_name(),
                    "groups": user.groups(),
                    "active": user.is_active(),
                    "roles": user.roles,
                    "apikey": user._apikey,
                    "settings": user.get_all_settings()
                }
            else:
                data[name] = {
                    "password": user._passwordHash,
                    "active": user.is_active(),
                    "roles": user.roles,
                    "apikey": user._apikey,
                    "settings": user.get_all_settings()
                }

        with atomic_write(self._userfile, "wb", permissions=0o600, max_permissions=0o666) as f:
            yaml.safe_dump(data, f, default_flow_style=False, indent="    ", allow_unicode=True)
            self._dirty = False
        self._load()

    ###################################################################
    # LDAP interactions

    def get_ldap_client(self, user=None, password=None):
        uri = self.get_plugin_setting("uri")
        if uri is None:
            self._logger.debug("No LDAP URI")
            return None

        if user is None:
            user = self.get_plugin_setting("auth_user")
            password = self.get_plugin_setting("auth_password")

        try:
            self._logger.debug("Initializing LDAP connection to %s" % uri)
            client = ldap.initialize(uri)
            if self.get_plugin_setting("request_tls_cert"):
                self._logger.debug("Will require TLS certificate")
                client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            else:
                client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            if user is not None:
                self._logger.debug("Binding to LDAP as %s" % user)
                client.bind_s(user, password)
            return client
        except ldap.INVALID_CREDENTIALS:
            self._logger.error("Invalid credentials to bind to LDAP as %s" % user)
        except ldap.LDAPError as e:
            self._logger.error(json.dumps(e.message))
        return None

    def ldap_search(self, filter, base=None, scope=ldap.SCOPE_SUBTREE):
        if base is None:
            base = self.get_plugin_setting("search_base")
        try:
            client = self.get_ldap_client()
            if client is not None:
                self._logger.debug("Searching LDAP, base: %s and filter: %s" % (base, filter))
                result = client.search_s(base, scope, filter)
                client.unbind_s()
                if result:
                    dn, data = result[0]
                    # Dump LDAP search query results to logger
                    # self._logger.debug("dn: %s" % dn)
                    # for key, value in data.iteritems():
                    #     self._logger.debug("%s: %s" % (key, value))
                    return dict(dn=dn, data=data)
        except ldap.LDAPError as e:
            self._logger.error(json.dumps(e.message))
        return None

    # Softwareupdate hook

    def get_update_information(self):
        return dict(
            auth_ldap=dict(
                displayName=self._plugin_name,
                displayVersion=self._plugin_version,

                # version check: github repository
                type="github_release",
                user="gillg",
                repo="OctoPrint-LDAP",
                current=self._plugin_version,

                # update method: pip
                pip="https://github.com/gillg/OctoPrint-LDAP/archive/{target_version}.zip"
            )
        )

    # UserManager hook

    def ldap_user_factory(self, components, settings):
        return LDAPUserManager()

    # SettingsPlugin

    def get_settings_defaults(self):
        return dict(
            auth_password=None,
            auth_user=None,
            default_role_admin=False,
            default_role_user=True,
            group_filter="ou=%s",
            group_member_filter="uniqueMember=%s",
            groups=None,
            local_cache=False,
            request_tls_cert=None,
            search_base=None,
            search_filter="uid=%s",
            uri=None
        )

    def get_settings_restricted_paths(self):
        self._logger.debug("Registering restricted paths")
        return dict(
            admin=[
                ["auth_user"],
                ["default_role_admin"],
                ["default_role_user"],
                ["group_filter"],
                ["group_member_filter"],
                ["groups"],
                ["local_cache"],
                ["request_tls_cert"],
                ["search_base"],
                ["search_filter"],
                ["uri"],
            ],
            user=[],
            never=[["auth_password"]]
        )

    # TemplatePlugin

    def get_template_configs(self):
        return [dict(type="settings", custom_bindings=False)]


__plugin_name__ = "Auth LDAP"


def __plugin_load__():
    global __plugin_implementation__
    __plugin_implementation__ = LDAPUserManager()

    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.users.factory": __plugin_implementation__.ldap_user_factory,
        "octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information
    }
