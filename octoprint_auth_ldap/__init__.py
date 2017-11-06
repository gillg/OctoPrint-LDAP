# coding=utf-8
from __future__ import absolute_import

from octoprint.users import FilebasedUserManager
from octoprint.settings import settings
import ldap
import uuid


class LDAPUserManager(FilebasedUserManager):
    def checkPassword(self, username, password):
        ldap_server = settings().get(["accessControl", "ldap_uri"])
        ldap_search_base = settings().get(["accessControl", "ldap_search_base"])
        if ldap_server is None or ldap_search_base is None:
            self._logger.debug("LDAP conf error")
            return False
        dn = "uid=" + username + ",ou=users," + ldap_search_base
        try:
            connection = ldap.initialize(ldap_server)
            connection.start_tls_s()
            connection.bind_s(dn, password)

            user = self.findUser(username)
            if not user:
                self.addUser(username, uuid.uuid4(), True)
            return True
        except ldap.INVALID_CREDENTIALS:
            self._logger.debug("LDAP : Your username or password is incorrect.")
            return FilebasedUserManager.checkPassword(self, username, password)
        except ldap.LDAPError, e:
            if type(e.message) == dict:
                for (k, v) in e.message.iteritems():
                    self._logger.debug("%s: %sn" % (k, v))
            else:
                self._logger.debug(e.message)
                return False

def changeUserPassword(self, username, password):
    pass

def ldap_user_factory(components, settings, *args, **kwargs):
    return LDAPUserManager();

__plugin_name__ = "Auth LDAP"
__plugin_version__ = "1.0.0"
__plugin_description__ = "LDAP authentication"

def __plugin_load__():
    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.users.factory": ldap_user_factory
    }
