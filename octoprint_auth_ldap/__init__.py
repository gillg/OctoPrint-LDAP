# coding=utf-8
from __future__ import absolute_import

import octoprint.plugin
from octoprint.users import FilebasedUserManager, User
from octoprint.settings import settings
import ldap
import uuid


# ForumSys has a read-only test LDAP server that is web-facing set up that is super helpful for testing! -- SDB 2019-10-15
# https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/

class LDAPUser(User):
    def __init__(self, username, passwordHash=None, active=True, roles=None, dn=None, apikey=None, settings=None):
        User.__init__(self, username, passwordHash, active, roles, apikey, settings)
        self._dn = dn

    def distinguished_name(self):
        return self._dn


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
            search_filter = self.get_my_setting("search_filter").replace(self.USER_PLACEHOLDER, userid)

            dn = self.ldap_search(search_filter)

            # TODO: map LDAP groups to roles?
            # TODO: make default role configurable
            actual_groups = ["users"]
            if dn is not None:
                self._logger.debug("%s found as dn=%s" % (userid, dn))
                groups = self.get_my_setting("groups")
                if groups is not None:
                    for group in str(groups).split(","):
                        # TODO make search filter configurable (could also be cn=%s)
                        result = self.ldap_search("(&(ou=%s)(uniqueMember=%s))" % (group.strip(), dn))
                        if result is not None:
                            actual_groups.append(group)
                    if actual_groups is ["users"]:
                        return None
                # TODO: mirror LDAP users locally (will this help with logging?)
                self._logger.debug("Creating new LDAPUser %s" % userid)
                user = LDAPUser(username=userid, dn=dn, roles=actual_groups, active=True)

        return user

    def checkPassword(self, username, password):
        user = self.findUser(userid=username)
        if isinstance(user, LDAPUser):
            self._logger.debug("Checking %s password via LDAP" % username)
            client = self.get_ldap_client(user.distinguished_name(), password)
            return client is not None
        else:
            self._logger.debug("Checking %s password via file" % username)
            return FilebasedUserManager.checkPassword(self, username, password)

    # FIXME this is a bit of a hack...
    #       I _think_ there's a collision between the UserManager and SettingsPlugin on self._settings
    def get_my_setting(self, key):
        value = settings().get(["plugins", "auth_ldap", key])
        if value is None:
            value = self.get_settings_defaults()[key]
            self.set_my_setting(key, value)
        return value

    def set_my_setting(self, key, value):
        return settings().set(["plugins", "auth_ldap", key], value)

    ###################################################################
    # LDAP interactions

    def get_ldap_client(self, user=None, password=None):
        uri = self.get_my_setting("uri")
        if uri is None:
            self._logger.debug("No LDAP URI")
            return None
        if user is None:
            user = self.get_my_setting("auth_user")
            password = self.get_my_setting("auth_password")
        try:
            self._logger.debug("Initializing LDAP connection to %s" % uri)
            client = ldap.initialize(uri)
            if user is not None:
                self._logger.debug("Binding to LDAP as %s" % user)
                client.bind_s(user, password)
            return client
        except ldap.INVALID_CREDENTIALS:
            return None

    def ldap_search(self, filter, base=None, scope=ldap.SCOPE_SUBTREE):
        if base is None:
            base = self.get_my_setting("search_base")

        try:
            client = self.get_ldap_client()
            if client is not None:
                self._logger.debug("Searching LDAP, base: %s and filter: %s" % (base, filter))
                result = client.search_s(base, scope, filter)
                client.unbind_s()
                if result:
                    self._logger.debug(result)
                    dn, data = result[0]
                    return dn
        except ldap.LDAPError as e:
            if isinstance(e.message, dict):
                for (k, v) in e.message:
                    self._logger.debug("%s: %s" % (k, v))
            else:
                self._logger.debug(e.message)

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

    USER_PLACEHOLDER = "{user}"
    GROUP_PLACEHOLDER = "{group}"
    GROUP_MEMBER_PLACEHOLDER = "{dn}"

    def get_settings_defaults(self):
        return dict(
            uri=None,
            request_tls_cert=None,
            auth_user=None,
            auth_password=None,
            search_base=None,
            search_filter="uid=%s" % self.USER_PLACEHOLDER,
            groups=None,
            group_filter="ou=%s" % self.GROUP_PLACEHOLDER,
            group_member_filter="uniqueMember=%s" % self.GROUP_MEMBER_PLACEHOLDER
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

# @TODO Command clean LDAP users deleted
