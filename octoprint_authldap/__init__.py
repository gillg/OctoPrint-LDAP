# coding=utf-8
from __future__ import absolute_import

import octoprint.plugin
from octoprint.users import UserManager, FilebasedUserManager, User
from octoprint.settings import settings
import ldap
import uuid


class LDAPUserManager(FilebasedUserManager,
                      octoprint.plugin.SettingsPlugin,
                      octoprint.plugin.TemplatePlugin):
    # Login phase :
    # - findUser called, if it return a user
    # - checkPassword called, if it return True
    # - login_user called with User returned by previous findUser

    def checkPassword(self, username, password):
        try:
            connection = self.getLDAPClient()

            username = self.escapeLDAP(username)
            dn = self.findLDAPUser(username)
            if dn is None:
                return False
            connection.bind_s(dn, password)
            connection.unbind_s()

            user = FilebasedUserManager.findUser(self, username)
            if not user:
                self._logger.debug("Add new user")
                self.addUser(username,
                             str(uuid.uuid4()),
                             active=settings().getBoolean(["plugins", "authldap", "auto_activate"]),
                             roles=self.getRoles())
            return True

        except ldap.INVALID_CREDENTIALS:
            self._logger.error("LDAP : Your username or password is incorrect.")
            return FilebasedUserManager.checkPassword(self, username, password)
        except ldap.LDAPError, e:
            if type(e.message) == dict:
                for (k, v) in e.message.iteritems():
                    self._logger.error("%s: %sn" % (k, v))
            else:
                self._logger.error(e.message)
                return False

    def changeUserPassword(self, username, password):
        # Changing password of LDAP users is not allowed
        if FilebasedUserManager.findUser(self, username) is not None:
            return FilebasedUserManager.changeUserPassword(self, username, password)

    def findUser(self, userid=None, session=None):
        local_user = FilebasedUserManager.findUser(self, userid, session)
        # If user not exists in local database, search it on LDAP
        if userid and not local_user:
            if (self.findLDAPUser(userid)):
                # Return a fake user instance
                return User(userid,
                            str(uuid.uuid4()),
                            settings().getBoolean(["plugins", "authldap", "auto_activate"]),
                            self.getRoles())

            else:
                return None

        else:
            self._logger.debug("Local user found")
            return local_user

    def findLDAPUser(self, userid):
        ldap_search_base = settings().get(["accessControl", "ldap_search_base"])
        groups = settings().get(["accessControl", "groups"])
        userid = self.escapeLDAP(userid)

        if ldap_search_base is None:
            self._logger.error("LDAP conf error")
            return None

        try:
            connection = self.getLDAPClient()

            # verify user)
            result = connection.search_s(ldap_search_base, ldap.SCOPE_SUBTREE, "uid=" + userid)
            if result is None or len(result) == 0:
                return None
            self._logger.error("LDAP-AUTH: User found!")

            # check group(s)
            if groups is not None:
                self._logger.error("LDAP-AUTH: Checking Groups...")
                group_filter = ""
                if "," in groups:
                    group_list = groups.split(",")
                    group_filter = "(|"
                    for g in group_list:
                        group_filter = group_filter + "(cn=%s)" % g
                    group_filter = group_filter + ")"
                else:
                    group_filter = "(cn=%s)" % groups

                query = "(&(objectClass=posixGroup)%s(memberUid=%s))" % (group_filter, userid)
                self._logger.error("LDAP-AUTH QUERY:" + query)
                group_result = connection.search_s(ldap_search_base, ldap.SCOPE_SUBTREE, query)

                if group_result is None or len(group_result) == 0:
                    print("LDAP-AUTH: Group not found")
                    return None

                self._logger.error("LDAP-AUTH: Group matched!")

            # disconnect
            connection.unbind_s()

            # Get the DN of first user found
            dn, data = result[0]
            return dn

        except ldap.NO_SUCH_OBJECT:
            self._logger.error("LDAP-AUTH: NO_SUCH_OBJECT")

        except ldap.SERVER_DOWN:
            self._logger.debug("LDAP-AUTH: Server unreachable!")

        except ldap.LDAPError, e:
            if type(e.message) == dict:
                for (k, v) in e.message.iteritems():
                    self._logger.error("%s: %sn" % (k, v))
            else:
                self._logger.error(e.message)

        return None

    def getLDAPClient(self):
        self._logger.debug("Creating LDAP Client")
        ldap_server = settings().get(["plugins", "authldap", "ldap_uri"])
        self._logger.debug("LDAP URL %s" % ldap_server)
        if not ldap_server:
            self._logger.debug("UserManager: %s" % settings().get(["accessControl", "userManager"]))
            raise Exception("LDAP conf error, server is missing")

        connection = ldap.initialize(ldap_server)
        connection.set_option(ldap.OPT_REFERRALS, 0)
        self._logger.debug("LDAP initialized")

        method = settings().get(["plugins", "authldap", "ldap_method"])
        if (ldap_server.startswith('ldaps://') or method == 'TLS'):
            self._logger.debug("LDAP is using TLS, setting ldap options...")
            ldap_verifypeer = settings().get(
                ["plugins", "authldap", "ldap_tls_reqcert"])

            verifypeer = ldap.OPT_X_TLS_HARD
            if ldap_verifypeer == 'NEVER':
                verifypeer = ldap.OPT_X_TLS_NEVER
            elif ldap_verifypeer == 'ALLOW':
                verifypeer = ldap.OPT_X_TLS_ALLOW
            elif ldap_verifypeer == 'TRY':
                verifypeer = ldap.OPT_X_TLS_TRY
            elif ldap_verifypeer == 'DEMAND':
                verifypeer = ldap.OPT_X_TLS_DEMAND
            connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, verifypeer)
            try:
                connection.start_tls_s()
                self._logger.error("TLS connection established.")
            except:
                self._logger.error("Error initializing tls connection")
                pass

        masterLogin = settings().get(["plugins", "authldap", "ldap_master_user"])
        masterPassword = settings().get(["plugins", "authldap", "ldap_master_password"])
        if (masterLogin and masterPassword):
            connection.simple_bind_s(masterLogin, masterPassword)
            connection.unbind_s()

        return connection

    def escapeLDAP(self, str):
        reservedStrings = ['+', '=', '\\', '\r',
                           '\n', '#', ',', '>', '<', '"', ';']
        for ch in reservedStrings:
            if ch in str:
                str = str.replace(ch, '\\' + ch)
        return str

    def getRoles(self):
        defaultRoles = []
        roles = settings().get(["plugins", "authldap", "roles"])
        if roles is not None:
            defaultRoles = [x.strip() for x in roles.split(',')]
        return defaultRoles

    # Softwareupdate hook

    def get_update_information(self):
        return dict(
            authldap=dict(
                displayName="AuthLDAP",
                displayVersion=self._plugin_version,

                # version check: github repository
                type="github_release",
                user="gillg",
                repo="OctoPrint-LDAP",
                current=self._plugin_version,

                # update method: pip
                pip=("https://github.com"
                     "/gillg/OctoPrint-LDAP/archive/{target_version}.zip")
            )
        )

    # UserManager hook

    def ldap_user_factory(components, settings, *args, **kwargs):
        return LDAPUserManager()

    # SettingsPlugin

    def get_settings_defaults(self):
        return dict(
            ldap_uri=None,
            ldap_search_base=None,
            ldap_method=None,
            auto_activate=True,
            roles="user",
            groups=None,
            ldap_tls_reqcert=None,
            ldap_master_user=None,
            ldap_master_password=None
        )

    def on_settings_save(self, data):
        old_flag = self._settings.get_boolean(["active"])
        octoprint.plugin.SettingsPlugin.on_settings_save(self, data)
        new_flag = self._settings.get_boolean(["active"])
        if new_flag != old_flag:
            if new_flag:
                self._logger.warning("Warning! Activating LDAP Plugin")
                settings().set(["accessControl", "userManager"], 'octoprint_authldap.LDAPUserManager')
                settings().save()
            else:
                if settings().get(["accessControl", "userManager"]) == 'octoprint_authldap.LDAPUserManager':
                    self._logger.warning("Deactivating LDAP Plugin")
                    settings().remove(["accessControl", "userManager"])
                    settings().save()

    # TemplatePlugin

    def get_template_configs(self):
        return [
            dict(type="settings", custom_bindings=False)
        ]


__plugin_name__ = "Auth LDAP"


def __plugin_load__():
    global __plugin_implementation__
    __plugin_implementation__ = LDAPUserManager()

    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.users.factory":
            __plugin_implementation__.ldap_user_factory,
        "octoprint.plugin.softwareupdate.check_config":
            __plugin_implementation__.get_update_information,
    }

# @TODO Command clean LDAP users deleted
