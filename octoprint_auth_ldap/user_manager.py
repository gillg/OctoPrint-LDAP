# coding=utf-8
from __future__ import absolute_import

import io
import os

import yaml
from passlib import pwd
from ldap.filter import filter_format
from octoprint.access.users import FilebasedUserManager, User, UserAlreadyExists
from octoprint.util import atomic_write
from octoprint_auth_ldap.constants import LOCAL_CACHE, SEARCH_FILTER, SEARCH_TERM_TRANSFORM, DISTINGUISHED_NAME, OU
from octoprint_auth_ldap.group import LDAPGroup
from octoprint_auth_ldap.group_manager import LDAPGroupManager
from octoprint_auth_ldap.ldap import DependentOnLDAPConnection
from octoprint_auth_ldap.tweaks import DependentOnSettingsPlugin
from octoprint_auth_ldap.user import LDAPUser


class LDAPUserManager(FilebasedUserManager, DependentOnSettingsPlugin, DependentOnLDAPConnection):

    def __init__(self, plugin, ldap, **kwargs):
        DependentOnSettingsPlugin.__init__(self, plugin)
        DependentOnLDAPConnection.__init__(self, ldap)
        FilebasedUserManager.__init__(self, group_manager=LDAPGroupManager(plugin=plugin, ldap=ldap), **kwargs)

    @property
    def group_manager(self):
        return self._group_manager

    def find_user(self, userid=None, apikey=None, session=None, fresh=False):
        self.logger.debug("Search for userid=%s, apiKey=%s, session=%s" % (userid, apikey, session))
        user = FilebasedUserManager.find_user(self, userid=userid, apikey=apikey, session=session)
        user, userid = self._find_user_with_transformation(apikey, session, user, userid)
        if not user and userid:
            user = self._find_user_via_ldap(user, userid)
        return user

    def _find_user_via_ldap(self, user, userid):
        self.logger.debug("User %s not found locally, treating as LDAP" % userid)
        search_filter = self.settings.get([SEARCH_FILTER])
        self.group_manager._refresh_ldap_groups()
        """
                operating on the wildly unsafe assumption that the admin who configures this plugin will have their head
                screwed on right and we are NOT escaping their search strings... only escaping unsafe user-entered text that
                is passed directly to search filters
                """
        ldap_user = self.ldap.search(filter_format(search_filter, (userid,)))
        if ldap_user is not None:
            self.logger.debug("User %s found as dn=%s" % (userid, ldap_user[DISTINGUISHED_NAME]))
            groups = self._group_manager.get_ldap_groups_for(ldap_user[DISTINGUISHED_NAME])
            if isinstance(groups, list):
                self.logger.debug("Creating new LDAPUser %s" % userid)
                if self.settings.get([LOCAL_CACHE]):
                    self.add_user(
                        username=userid,
                        dn=ldap_user[DISTINGUISHED_NAME],
                        groups=groups,
                        active=True
                    )
                    user = self._users[userid]
                else:
                    user = LDAPUser(
                        username=userid,
                        dn=ldap_user[DISTINGUISHED_NAME],
                        groups=groups,
                        active=True
                    )
        return user

    def _find_user_with_transformation(self, apikey, session, user, userid):
        transformation = self.settings.get([SEARCH_TERM_TRANSFORM])
        if not user and userid and transformation:
            self.logger.debug("Transforming %s using %s" % (userid, transformation))
            transformed = getattr(str, transformation)(str(userid))
            self.logger.debug("Search for user userid=%s" % transformed)
            if transformed != userid:
                userid = transformed
                user = FilebasedUserManager.find_user(self, userid=userid, apikey=apikey, session=session)
        return user, userid

    def add_user(self,
                 username,
                 password=pwd.genword(entropy=52, length=20),
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
                passwordHash=LDAPUserManager.create_password_hash(password, settings=self._settings),
                active=active,
                permissions=permissions,
                groups=groups,
                dn=dn,
                apikey=apikey
            )
            self._dirty = True
            self._save()

    def check_password(self, username, password):
        user = self.find_user(userid=username)
        if isinstance(user, LDAPUser):
            # in case group settings changed either in auth_ldap settings OR on LDAP directory
            if user.is_active and (
                self.settings.get([OU]) is None or
                len(self.refresh_ldap_group_memberships_for(user)) > 0
            ):
                self.logger.debug("Checking %s password via LDAP" % user.get_id())
                client = self.ldap.get_client(user.distinguished_name, password)
                authenticated = client is not None
                self.logger.debug("%s was %sauthenticated" % (user.get_name(), "" if authenticated else "not "))
                if authenticated:
                    user._passwordHash = LDAPUserManager.create_password_hash(password, settings=self._settings)
                    self._save(force=True)
                return authenticated
            else:
                self.logger.debug("%s is inactive or no longer a member of required groups" % user.get_id())
        else:
            self.logger.debug("Checking %s password via users.yaml" % user.get_name())
            return FilebasedUserManager.check_password(self, user.get_name(), password)
        return False

    def refresh_ldap_group_memberships_for(self, user):
        current_groups = self.group_manager.get_ldap_groups_for(user)
        cached_groups = list(filter(lambda g: isinstance(g, LDAPGroup), user.groups))
        self.remove_groups_from_user(user.get_id(), list(set(cached_groups) - set(current_groups)))
        self.add_groups_to_user(user.get_id(), list(set(current_groups) - set(cached_groups)))
        self.logger.debug("%s is currently a member of %s" % (user.get_id(), current_groups))
        return current_groups

    def refresh_ldap_group_memberships(self):
        for user in filter(lambda u: isinstance(u, LDAPUser), self.get_all_users()):
            self.refresh_ldap_group_memberships_for(user)

    def _load(self):
        if os.path.exists(self._userfile) and os.path.isfile(self._userfile):
            self._customized = True
            with io.open(self._userfile, 'rt', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                version = data.pop("_version", 1)
                
                for name, attributes in data.items():
                    permissions = self._to_permissions(*attributes.get("permissions", []))
                    groups = attributes.get("groups", {
                        self._group_manager.user_group  # the user group is mandatory for all logged in users
                    })
                    user_type = attributes.get("type", False)

                    # migrate from roles to permissions
                    if "roles" in attributes and "permissions" not in attributes:
                        self.logger.info("Migrating user %s to new granular permission system" % name)
                        groups |= set(self._migrate_roles_to_groups(attributes["roles"]))
                        self._dirty = True

                    # because this plugin used to use the groups field, need to wait to make sure it's safe to do this
                    groups = self._to_groups(*groups)

                    apikey = attributes.get("apikey")
                    user_settings = attributes.get("settings", dict())

                    if user_type == LDAPUser.USER_TYPE:
                        self.logger.debug("Loading %s as %s" % (name, LDAPUser.__name__))
                        self._users[name] = LDAPUser(
                            username=name,
                            passwordHash=attributes["password"],
                            active=attributes["active"],
                            permissions=permissions,
                            groups=groups,
                            dn=attributes[DISTINGUISHED_NAME],
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
                    DISTINGUISHED_NAME: user.distinguished_name,

                    # password field has to exist because of how FilebasedUserManager processes
                    # data, but an empty password hash cannot match any entered password (as
                    # whatever the user enters will be hashed... even an empty password.
                    "password": user._passwordHash,

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
