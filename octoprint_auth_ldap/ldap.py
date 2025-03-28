# coding=utf-8
from __future__ import absolute_import

import json

import ldap
from octoprint_auth_ldap.constants import AUTH_PASSWORD, AUTH_PASSWORD_FILE, AUTH_USER, DISTINGUISHED_NAME, OU, OU_FILTER, OU_MEMBER_FILTER, \
    REQUEST_TLS_CERT, SEARCH_BASE, URI
from octoprint_auth_ldap.tweaks import DependentOnSettingsPlugin
from pathlib import Path


class LDAPConnection(DependentOnSettingsPlugin):
    def __init__(self, plugin):
        DependentOnSettingsPlugin.__init__(self, plugin)

    def get_client(self, user=None, password=None):
        uri = self.settings.get([URI])
        if not uri:
            self.logger.debug("No LDAP URI")
            return None

        if not user:
            user = self.settings.get([AUTH_USER])
            password = self.settings.get([AUTH_PASSWORD]) or \
                Path(self.settings.get([AUTH_PASSWORD_FILE])).read_text()

        try:
            self.logger.debug("Initializing LDAP connection to %s" % uri)
            client = ldap.initialize(uri)
            if self.settings.get([REQUEST_TLS_CERT]):
                self.logger.debug("Requesting TLS certificate")
                client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            else:
                client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            if user is not None:
                self.logger.debug("Binding to LDAP as %s" % user)
                client.bind_s(user, password)
            return client
        except ldap.INVALID_CREDENTIALS:
            self.logger.error("Invalid credentials to bind to LDAP as %s" % user)
        except ldap.SERVER_DOWN as e:
            self.logger.error("the server at %s is down" % uri )
        except ldap.LDAPError as e:
            self.logger.error(json.dumps(e))
        return None

    def search(self, ldap_filter, base=None, scope=ldap.SCOPE_SUBTREE):
        if not base:
            base = self.settings.get([SEARCH_BASE])
        try:
            client = self.get_client()
            if client is not None:
                # self.logger.debug("Searching LDAP, base: %s and filter: %s" % (base, ldap_filter))
                result = client.search_s(base, scope, ldap_filter)
                client.unbind_s()
                if result:
                    dn, data = result[0]
                    """
                    # Dump LDAP search query results to logger
                    self.logger.debug("dn: %s" % dn)
                    for key, value in data.items():
                        self.logger.debug("%s: %s" % (key, value))
                    """
                    return dict(dn=dn, data=data)
        except ldap.LDAPError as e:
            self.logger.error(json.dumps(e))
        return None

    def get_ou_memberships_for(self, dn):
        memberships = []

        ou_common_names = self.settings.get([OU])
        if ou_common_names is None:
            return False

        ou_filter = self.settings.get([OU_FILTER])
        ou_member_filter = self.settings.get([OU_MEMBER_FILTER])
        for ou_common_name in str(ou_common_names).split(","):
            result = self.search("(&" +
                                 "(" + ou_filter % ou_common_name.strip() + ")" +
                                 "(" + (ou_member_filter % dn) + ")" +
                                 ")")
            if result is not None and result[DISTINGUISHED_NAME] is not None:
                self.logger.debug("%s is a member of %s" % (dn, result[DISTINGUISHED_NAME]))
                memberships.append(ou_common_name)
        return memberships


class DependentOnLDAPConnection:
    # noinspection PyShadowingNames
    def __init__(self, ldap):
        self._ldap = ldap

    @property
    def ldap(self):
        return self._ldap
