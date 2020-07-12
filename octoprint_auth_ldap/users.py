# coding=utf-8
from __future__ import absolute_import

import io
import os

import yaml
from ldap.filter import filter_format
from octoprint.access.users import FilebasedUserManager, User, UserAlreadyExists
from octoprint.util import atomic_write
from octoprint_auth_ldap.groups import LDAPGroupManager
from octoprint_auth_ldap.ldap import LDAPConnection, DependentOnLDAPConnection
from octoprint_auth_ldap.tweaks import DependentOnSettingsPlugin


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
        self.distinguished_name = dn

    @property
    def distinguished_name(self):
        return self._distinguished_name

    @distinguished_name.setter
    def distinguished_name(self, dn):
        # TODO throw error on missing/invalid dn?
        self._distinguished_name = dn


class LDAPUserManager(FilebasedUserManager, DependentOnSettingsPlugin, DependentOnLDAPConnection):

    def __init__(self, plugin, ldap: LDAPConnection, **kwargs):
        DependentOnSettingsPlugin.__init__(self, plugin)
        DependentOnLDAPConnection.__init__(self, ldap)
        FilebasedUserManager.__init__(self, group_manager=LDAPGroupManager(plugin=plugin, ldap=ldap), **kwargs)

    @property
    def group_manager(self) -> LDAPGroupManager:
        return self._group_manager

    def find_user(self, userid=None, apikey=None, session=None):
        self.logger.debug("Search for userid=%s, apiKey=%s, session=%s" % (userid, apikey, session))
        user = FilebasedUserManager.find_user(self, userid=userid, apikey=apikey, session=session)

        transformation = self.settings.get(["search_term_transform"])
        if not user and userid and transformation:
            self.logger.debug("Transforming %s using %s" % (userid, transformation))
            transformed = getattr(str, transformation)(str(userid))
            self.logger.debug("Search for user userid=%s" % transformed)
            if transformed != userid:
                userid = transformed
                user = FilebasedUserManager.find_user(self, userid=userid, apikey=apikey, session=session)

        if not user and userid:
            self.logger.debug("User %s not found locally, treating as LDAP" % userid)
            search_filter = self.settings.get(["search_filter"])
            self.group_manager.sync_with_ldap()

            """
            operating on the wildly unsafe assumption that the admin who configures this plugin will have their head
            screwed on right and we are NOT escaping their search strings... only escaping unsafe user-entered text that
            is passed directly to search filters
            """
            ldap_user = self.ldap.search(filter_format(search_filter, (userid,)))

            if ldap_user is not None:
                self.logger.debug("User %s found as dn=%s" % (userid, ldap_user["dn"]))
                groups = self.ldap_group_filter(ldap_user["dn"])
                if isinstance(groups, list):
                    self.logger.debug("Creating new LDAPUser %s" % userid)
                    # TODO: make username configurable or make dn configurable (e.g. could be userPrincipalName?)
                    if self.settings.get(["local_cache"]):
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

    def ldap_group_filter(self, dn):
        ldap_groups = self.settings.get(["ldap_groups"])
        self.logger.debug("Filtering %s against %s" % (dn, ldap_groups))
        actual_ldap_groups = []
        if ldap_groups:
            ldap_group_filter = self.settings.get(["ldap_group_filter"])
            ldap_group_member_filter = self.settings.get(["ldap_group_member_filter"])
            for ldap_group in str(ldap_groups).split(","):
                result = self.ldap.search("(&" +
                                          "(" + ldap_group_filter % ldap_group.strip() + ")" +
                                          "(" + (ldap_group_member_filter % dn) + ")" +
                                          ")")
                self.logger.debug("Found %s" % result)
                if result is not None:
                    actual_ldap_groups.append(ldap_group)
            if not actual_ldap_groups:
                self.logger.debug("%s is not a member of configured LDAP groups" % dn)
                return False
        return actual_ldap_groups

    def add_user(self,
                 username,
                 password=None,
                 active=False,
                 permissions=None,
                 groups=None,
                 apikey=None,
                 overwrite=False,
                 dn=None):
        if dn is None:
            FilebasedUserManager.add_user(
                self,
                username=username,
                password=password,
                active=active,
                permissions=permissions,
                groups=groups,
                apikey=apikey,
                overwrite=overwrite
            )
        else:
            if username in self._users.keys() and not overwrite:
                raise UserAlreadyExists(username)

            if not permissions:
                permissions = []
            permissions = self._to_permissions(*permissions)

            if not groups:
                groups = self._group_manager.default_groups
            groups = self._to_groups(*groups)

            self._users[username] = LDAPUser(
                username=username,
                active=active,
                permissions=permissions,
                groups=groups,
                dn=dn,
                apikey=apikey
            )
            self._dirty = True
            self._save()

    def check_password(self, username, password):
        user = self.findUser(userid=username)
        self.logger.debug("%s is a %s" % (username, type(user)))
        if isinstance(user, LDAPUser):
            # in case group settings changed either in auth_ldap settings OR on LDAP directory
            groups = self.ldap_group_filter(user.distinguished_name)
            if user.is_active and isinstance(groups, list):
                self.change_user_groups(user.get_name(), groups)
                self.logger.debug("Checking %s password via LDAP" % user.get_name())
                client = self.ldap.get_client(user.distinguished_name, password)
                return client is not None
            else:
                self.logger.debug("%s is inactive or no longer a member of required groups" % user.get_name())
        else:
            self.logger.debug("Checking %s password via users.yaml" % user.get_name())
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
                        self.logger.info("Migrating user %s to new granular permission system" % name)
                        groups |= set(self._migrate_roles_to_groups(attributes["roles"]))
                        self._dirty = True

                    # because this plugin used to use the groups field, need to wait to make sure it's safe to do this
                    groups = self._to_groups(*groups)

                    apikey = None
                    if "apikey" in attributes:
                        apikey = attributes["apikey"]

                    user_settings = dict()
                    if "settings" in attributes:
                        user_settings = attributes["settings"]

                    if user_type == LDAPUser.USER_TYPE:
                        self.logger.debug("Loading %s as %s" % (name, LDAPUser.__name__))
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
                        self.logger.debug("Loading %s as %s" % (name, User.__name__))
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
                self.logger.debug('Not saving %s' % name)
                continue

            if isinstance(user, LDAPUser):
                self.logger.debug('Saving %s as %s' % (name, LDAPUser.__name__))
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
                self.logger.debug('Saving %s as %s...' % (name, User.__name__))
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
