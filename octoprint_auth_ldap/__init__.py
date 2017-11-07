# coding=utf-8
from __future__ import absolute_import

from octoprint.users import FilebasedUserManager, User
from octoprint.settings import settings
import ldap
import uuid


class LDAPUserManager(FilebasedUserManager):
    #Login phase :
    #  - findUser called, if it return a user
    #    - chaeckPassword called, if it return True
    #      - login_user called with User returned by previous findUser

    def checkPassword(self, username, password):
        ldap_server = settings().get(["accessControl", "ldap_uri"])
        ldap_search_base = settings().get(["accessControl", "ldap_search_base"])
        ldap_verifypeer = settings().get(["accessControl", "ldap_tls_reqcert"])
        self._logger.debug(ldap_server)
        self._logger.debug(ldap_search_base)
        if ldap_server is None or ldap_search_base is None:
            self._logger.error("LDAP conf error")
            return False

        #@TODO Voir pour sortir le groupe "smile" de là...
        group = "ou=smile,ou=users"
        dn = "uid=" + username + "," + group + "," + ldap_search_base
        try:
            connection = ldap.initialize(ldap_server)
            if (ldap_server.startswith('ldaps://')):
                verifypeer = ldap.OPT_X_TLS_NEVER
                if ldap_verifypeer == 'demand':
                    verifypeer = ldap.OPT_X_TLS_DEMAND
                connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, verifypeer)
                try:
                    connection.start_tls_s()
                except:
                    pass

            connection.bind_s(dn, password)
            connection.unbind_s()

            user = FilebasedUserManager.findUser(self, username)
            if not user:
                self.addUser(username, str(uuid.uuid4()), True)
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
        pass

    def findUser(self, userid=None, session=None):
        local_user = FilebasedUserManager.findUser(self, userid, session)
        #If user not exists in local database, search it on LDAP
        if userid and not local_user:
            ldap_server = settings().get(["accessControl", "ldap_uri"])
            ldap_search_base = settings().get(["accessControl", "ldap_search_base"])
            ldap_verifypeer = settings().get(["accessControl", "ldap_tls_reqcert"])

            try:
                connection = ldap.initialize(ldap_server)
                if (ldap_server.startswith('ldaps://')):
                    verifypeer = ldap.OPT_X_TLS_NEVER
                    if ldap_verifypeer == 'demand':
                        verifypeer = ldap.OPT_X_TLS_DEMAND
                    connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, verifypeer)
                    try:
                        connection.start_tls_s()
                    except:
                        pass

                result = connection.search_s(ldap_search_base, ldap.SCOPE_SUBTREE, "uid="+userid)
                connection.unbind_s()
                if (result is None or len(result) == 0):
                    return None

                #Return a fake user instance
                return User(userid, str(uuid.uuid4()), True, ["user"])

            except ldap.LDAPError, e:
                if type(e.message) == dict:
                    for (k, v) in e.message.iteritems():
                        self._logger.error("%s: %sn" % (k, v))
                else:
                    self._logger.error(e.message)
                    return None
        else :
            return local_user

def ldap_user_factory(components, settings, *args, **kwargs):
    return LDAPUserManager();

__plugin_name__ = "Auth LDAP"
__plugin_version__ = "1.0.0"

def __plugin_load__():
    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.users.factory": ldap_user_factory
    }
