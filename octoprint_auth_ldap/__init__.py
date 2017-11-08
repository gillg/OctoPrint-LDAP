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
        try:
            connection = self.getLDAPClient()

            username = self.escapeLDAP(username)
            dn = self.findLDAPUser(username)
            connection.bind_s(dn, password)
            connection.unbind_s()

            user = FilebasedUserManager.findUser(self, username)
            if not user:
                self._logger.debug("Add new user")
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
        #Changing password of LDAP users is not allowed
        if FilebasedUserManager.findUser(self, username) is not None:
            return FilebasedUserManager.changeUserPassword(self, username, password)

    def findUser(self, userid=None, session=None):
        local_user = FilebasedUserManager.findUser(self, userid, session)
        #If user not exists in local database, search it on LDAP
        if userid and not local_user:
            if(self.findLDAPUser(userid)):
                #Return a fake user instance
                return User(userid, str(uuid.uuid4()), True, ["user"])

            else:
                return None

        else :
            self._logger.debug("Local user found")
            return local_user

    def findLDAPUser(self, userid):
        ldap_search_base = settings().get(["accessControl", "ldap_search_base"])
        userid = self.escapeLDAP(userid)

        if ldap_search_base is None:
            self._logger.error("LDAP conf error")
            return None

        try:
            connection = self.getLDAPClient()

            result = connection.search_s(ldap_search_base, ldap.SCOPE_SUBTREE, "uid=" + userid)
            connection.unbind_s()
            if (result is None or len(result) == 0):
                return None

            #Get the DN of first user found
            dn, data = result[0]
            return dn

        except ldap.LDAPError, e:
            if type(e.message) == dict:
                for (k, v) in e.message.iteritems():
                    self._logger.error("%s: %sn" % (k, v))
            else:
                self._logger.error(e.message)
                return None

    def escapeLDAP(self, str):
        reservedStrings = ['+','=','\\','\r','\n','#',',','>','<','"',';']
        for ch in reservedStrings:
            if ch in str:
                str = str.replace(ch, '\\' + ch)
        return str

    def getLDAPClient(self):
        ldap_server = settings().get(["accessControl", "ldap_uri"])
        ldap_verifypeer = settings().get(["accessControl", "ldap_tls_reqcert"])
        if ldap_server is None:
            self._logger.error("LDAP conf error")
            Exception("LDAP conf error, server is missing")

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

        return connection

def ldap_user_factory(components, settings, *args, **kwargs):
    return LDAPUserManager();

__plugin_name__ = "Auth LDAP"
__plugin_version__ = "1.0.0"

def __plugin_load__():
    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.users.factory": ldap_user_factory
    }
