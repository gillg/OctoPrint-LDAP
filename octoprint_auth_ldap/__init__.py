# coding=utf-8
from __future__ import absolute_import

import json
import ldap
from ldap.filter import filter_format
import io
from octoprint.settings import settings
from octoprint.plugin import SettingsPlugin, TemplatePlugin
from octoprint.access.users import FilebasedUserManager, User, UserManager, UserAlreadyExists
from octoprint.access.groups import FilebasedGroupManager
from octoprint.util import atomic_write
import os
import yaml


# TODO map LDAP groups on to OctoPrint groups?


class LDAPUser(User):
    USER_TYPE = "LDAP"

    # noinspection PyShadowingNames
    def __init__(
            self,
            username,
            active=True,
            permissions=None,
            groups=None,
            apikey=None,
            settings=None,
            dn=None
    ):
        User.__init__(
            self,
            username=username,
            passwordHash=None,
            active=active,
            permissions=permissions,
            groups=groups,
            apikey=apikey,
            settings=settings
        )
        self._distinguished_name = dn

    @property
    def distinguished_name(self):
        return self._distinguished_name


class LDAPUserManager(FilebasedUserManager):

    def __init__(self, plugin, **kwargs):
        self._plugin = plugin
        FilebasedUserManager.__init__(self, group_manager=FilebasedGroupManager(), **kwargs)

    def plugin_settings(self):
        return self._plugin.get_settings()

    """
    -------------------------------------------------------------------
    UserManager overrides
    -------------------------------------------------------------------
    """

    def find_user(self, userid=None, apikey=None, session=None):
        self._logger.debug("Search for userid=%s, apiKey=%s, session=%s" % (userid, apikey, session))
        user = FilebasedUserManager.find_user(self, userid=userid, apikey=apikey, session=session)

        transformation = self.plugin_settings().get(["search_term_transform"])
        if not user and userid and transformation:
            self._logger.debug("Transforming %s using %s" % (userid, transformation))
            transformed = getattr(str, transformation)(str(userid))
            self._logger.debug("Search for user userid=%s" % transformed)
            if transformed != userid:
                userid = transformed
                user = FilebasedUserManager.find_user(self, userid=userid, apikey=apikey, session=session)

        if not user and userid:
            self._logger.debug("User %s not found locally, treating as LDAP" % userid)
            search_filter = self.plugin_settings().get(["search_filter"])

            """
            operating on the wildly unsafe assumption that the admin who configures this plugin will have their head
            screwed on right and we are NOT escaping their search strings... only escaping unsafe user-entered text that
            is passed directly to search filters
            """
            ldap_user = self.ldap_search(filter_format(search_filter, (userid,)))

            if ldap_user is not None:
                self._logger.debug("User %s found as dn=%s" % (userid, ldap_user["dn"]))
                groups = self.group_filter(ldap_user["dn"])
                if isinstance(groups, list):
                    self._logger.debug("Creating new LDAPUser %s" % userid)
                    # TODO: make username configurable or make dn configurable (e.g. could be userPrincipalName?)
                    if self.plugin_settings().get(["local_cache"]):
                        self.add_user(
                            username=userid,
                            dn=ldap_user["dn"],
                            groups=groups,
                            active=True
                        )
                        user = self._users[userid]
                    else:
                        user = LDAPUser(
                            username=userid,
                            dn=ldap_user["dn"],
                            groups=groups,
                            active=True
                        )
        return user

    """
    this will return either an empty list (i.e. []) (if no groups are specified in configuration) or a list of groups
    that the user is currently a member of (e.g. ["Lab Users"]), or False if the groups filter is configured and the
    user is not a member of any configured groups
    """

    def group_filter(self, dn):
        groups = self.plugin_settings().get(["groups"])
        actual_groups = []
        if groups:
            group_filter = self.plugin_settings().get(["group_filter"])
            group_member_filter = self.plugin_settings().get(["group_member_filter"])
            for group in str(groups).split(","):
                result = self.ldap_search("(&" +
                                          "(" + group_filter % group.strip() + ")" +
                                          "(" + (group_member_filter % dn) + ")" +
                                          ")")
                self._logger.debug("Found %s" % json.dumps(result))
                if result is not None:
                    actual_groups.append(group)
            if not actual_groups:
                return False
        return actual_groups

    def default_roles(self):
        roles = []
        if self.plugin_settings().get(["default_role_user"]):
            roles.append("user")
        if self.plugin_settings().get(["default_role_admin"]):
            roles.append("admin")
        return roles

    def add_user(self, username, password=None, active=False, permissions=None, groups=None, apikey=None,
                 overwrite=False,
                 dn=None, ldap_groups=None):
        if not permissions:
            permissions = []
        permissions = self._to_permissions(*permissions)

        if not groups:
            groups = self._group_manager.default_groups
        groups = self._to_groups(*groups)

        if username in self._users.keys() and not overwrite:
            raise UserAlreadyExists(username)

        if dn and not password:
            self._users[username] = LDAPUser(
                username=username,
                active=active,
                permissions=permissions,
                groups=groups,
                dn=dn,
                apikey=apikey
            )
        else:
            self._users[username] = User(
                username=username,
                passwordHash=UserManager.create_password_hash(password, settings=self._settings),
                active=active,
                permissions=permissions,
                groups=groups,
                apikey=apikey
            )
        self._dirty = True
        self._save()

    def check_password(self, username, password):
        user = self.findUser(userid=username)
        self._logger.debug("%s is a %s" % (username, type(user)))
        if isinstance(user, LDAPUser):
            # in case group settings changed either in auth_ldap settings OR on LDAP directory
            groups = self.group_filter(user._distinguished_name)
            if user.is_active and isinstance(groups, list):
                self.change_user_groups(user.get_name(), groups)
                self._logger.debug("Checking %s password via LDAP" % user.get_name())
                client = self.get_ldap_client(user._distinguished_name, password)
                return client is not None
            else:
                self._logger.debug("%s is inactive or no longer a member of required groups" % user.get_name())
        else:
            self._logger.debug("Checking %s password via users.yaml" % user.get_name())
            return FilebasedUserManager.check_password(self, user.get_name(), password)
        return False

    def _load(self):
        if os.path.exists(self._userfile) and os.path.isfile(self._userfile):
            self._customized = True
            with io.open(self._userfile, 'rt', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                for name, attributes in data.items():
                    permissions = []
                    if "permissions" in attributes:
                        permissions = attributes["permissions"]
                    permissions = self._to_permissions(*permissions)

                    groups = {self._group_manager.user_group}  # the user group is mandatory for all logged in users
                    if "groups" in attributes:
                        groups |= set(attributes["groups"])

                    user_type = False
                    if "type" in attributes:
                        user_type = attributes["type"]

                    # migrate from roles to permissions
                    if "roles" in attributes and "permissions" not in attributes:
                        self._logger.info("Migrating user %s to new granular permission system" % name)
                        groups |= set(self._migrate_roles_to_groups(attributes["roles"]))
                        self._dirty = True

                    # because this plugin used to use the groups field, we need to wait to make sure it's safe to do this
                    groups = self._to_groups(*groups)

                    apikey = None
                    if "apikey" in attributes:
                        apikey = attributes["apikey"]

                    user_settings = dict()
                    if "settings" in attributes:
                        user_settings = attributes["settings"]

                    if user_type == LDAPUser.USER_TYPE:
                        self._logger.debug("Loading %s as %s" % (name, LDAPUser.__name__))
                        self._users[name] = LDAPUser(
                            username=name,
                            active=attributes["active"],
                            permissions=permissions,
                            groups=groups,
                            dn=attributes["dn"],
                            apikey=apikey,
                            settings=user_settings
                        )
                    else:
                        self._logger.debug("Loading %s as %s" % (name, User.__name__))
                        self._users[name] = User(
                            username=name,
                            passwordHash=attributes["password"],
                            active=attributes["active"],
                            permissions=permissions,
                            groups=groups,
                            apikey=apikey,
                            settings=user_settings
                        )
                        for session_id in self._sessionids_by_userid.get(name, set()):
                            if session_id in self._session_users_by_session:
                                self._session_users_by_session[session_id].update_user(self._users[name])

            if self._dirty:
                self._save()

        else:
            self._customized = False

    def _save(self, force=False):
        if not self._dirty and not force:
            return

        data = {}
        for name, user in self._users.items():
            if not user or not isinstance(user, User):
                self._logger.debug('Not saving %s' % name)
                continue

            if isinstance(user, LDAPUser):
                self._logger.debug('Saving %s as %s' % (name, LDAPUser.__name__))
                data[name] = {
                    "type": LDAPUser.USER_TYPE,
                    "dn": user.distinguished_name,

                    # password field has to exist because of how FilebasedUserManager processes
                    # data, but an empty password hash cannot match any entered password (as
                    # whatever the user enters will be hashed... even an empty password.
                    "password": None,

                    "active": user._active,
                    "groups": self._from_groups(*user._groups),
                    "permissions": self._from_permissions(*user._permissions),
                    "apikey": user._apikey,
                    "settings": user._settings,

                    # TODO: deprecated, remove in 1.5.0
                    "roles": user._roles
                }
            else:
                self._logger.debug('Saving %s as %s...' % (name, User.__name__))
                data[name] = {
                    "password": user._passwordHash,
                    "active": user._active,
                    "groups": self._from_groups(*user._groups),
                    "permissions": self._from_permissions(*user._permissions),
                    "apikey": user._apikey,
                    "settings": user._settings,

                    # TODO: deprecated, remove in 1.5.0
                    "roles": user._roles
                }

        with atomic_write(self._userfile, mode='wt', permissions=0o600, max_permissions=0o666) as f:
            yaml.safe_dump(data, f, default_flow_style=False, indent=4, allow_unicode=True)
            self._dirty = False
        self._load()

    """
    -------------------------------------------------------------------
    LDAP interactions
    -------------------------------------------------------------------
    """

    def get_ldap_client(self, user=None, password=None):
        uri = self.plugin_settings().get(["uri"])
        if not uri:
            self._logger.debug("No LDAP URI")
            return None

        if not user:
            user = self.plugin_settings().get(["auth_user"])
            password = self.plugin_settings().get(["auth_password"])

        try:
            self._logger.debug("Initializing LDAP connection to %s" % uri)
            client = ldap.initialize(uri)
            if self.plugin_settings().get(["request_tls_cert"]):
                self._logger.debug("Requesting TLS certificate")
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
            self._logger.error(json.dumps(e))
        return None

    def ldap_search(self, ldap_filter, base=None, scope=ldap.SCOPE_SUBTREE):
        if not base:
            base = self.plugin_settings().get(["search_base"])
        try:
            client = self.get_ldap_client()
            if client is not None:
                self._logger.debug("Searching LDAP, base: %s and filter: %s" % (base, ldap_filter))
                result = client.search_s(base, scope, ldap_filter)
                client.unbind_s()
                if result:
                    dn, data = result[0]
                    """
                    # Dump LDAP search query results to logger
                    self._logger.debug("dn: %s" % dn)
                    for key, value in data.iteritems():
                        self._logger.debug("%s: %s" % (key, value))
                    """
                    return dict(dn=dn, data=data)
        except ldap.LDAPError as e:
            self._logger.error(json.dumps(e))
        return None


class AuthLDAPPlugin(SettingsPlugin, TemplatePlugin):

    # noinspection PyShadowingNames
    def ldap_user_factory(self, components, settings):
        return LDAPUserManager(plugin=self)

    def get_settings(self):
        return self._settings

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

    # SettingsPlugin

    def get_settings_defaults(self):
        return dict(
            auth_password=None,
            auth_user=None,
            default_admin_group=False,
            default_user_group=True,
            ldap_group_filter="ou=%s",
            ldap_group_member_filter="uniqueMember=%s",
            Ldap_groups=None,
            local_cache=False,
            request_tls_cert=None,
            search_base=None,
            search_filter="uid=%s",
            search_term_transform=None,
            uri=None
        )

    def get_settings_restricted_paths(self):
        return dict(
            admin=self.get_settings_defaults().keys(),
            user=[],
            never=[]
        )

    def get_settings_version(self):
        return 3

    def on_settings_migrate(self, target, current):
        if target != current:
            self._logger.info(
                "Migrating %s settings from version %s to version %s" % (self._plugin_name, current, target))
            if current is None:
                self.migrate_settings_1_to_2()
            if current != 3:  # intentional fall-through to bring None _and_ 2 to 3 (my kingdom for a switch statement!)
                self.migrate_settings_2_to_3()

    def migrate_settings_1_to_2(self):
        # changing settings location to plugin standard location and renaming to simplify access

        # migrate old settings to new locations and erase old settings
        prev_settings = dict(  # prev_setting_name="new_setting_name"
            ldap_uri="uri",
            ldap_tls_reqcert="request_tls_cert",
            ldap_search_base="search_base",
            ldap_groups="groups"
        )
        for prev_key, key in prev_settings.items():
            prev_value = settings().get(["accessControl", prev_key])
            if prev_value is not None:
                cleaned_prev_value = prev_value
                if prev_key == "ldap_tls_reqcert" and prev_value == "demand":
                    cleaned_prev_value = True
                self._settings.set([key], cleaned_prev_value)
                self._logger.info(
                    "accessControl.%s=%s setting migrated to plugins.%s.%s=%s"
                    % (prev_key, prev_value, self._plugin_name, key, cleaned_prev_value))
            settings().set(["accessControl", prev_key], None)

    def migrate_settings_2_to_3(self):
        # renaming to get rid of roles in favor of local groups, and clarifying LDAP group settings

        # migrate old settings to new locations and erase old settings
        prev_settings = dict(  # prev_setting_name="new_setting_name"
            default_role_admin="default_admin_group",
            default_role_user="default_user_group",
            group_filter="ldap_group_filter",
            group_member_filter="ldap_group_member_filter",
            groups="Ldap_groups",
        )
        for prev_key, key in prev_settings.items():
            prev_value = settings().get([prev_key])
            if prev_value is not None:
                self._settings.set([key], prev_value)
                self._logger.info(
                    "plugin.%s.%s=%s setting migrated to plugins.%s.%s=%s"
                    % (self._plugin_name, prev_key, prev_value, self._plugin_name, key, prev_value))
            settings().set([prev_key], None)

    # TemplatePlugin

    def get_template_configs(self):
        return [dict(type="settings", custom_bindings=False)]


__plugin_name__ = "Auth LDAP"
__plugin_pythoncompat__ = ">=3,<4"


def __plugin_load__():
    # noinspection PyGlobalUndefined
    global __plugin_implementation__
    __plugin_implementation__ = AuthLDAPPlugin()

    # noinspection PyGlobalUndefined
    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.access.users.factory": __plugin_implementation__.ldap_user_factory,
        "octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information
    }
