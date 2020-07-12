# coding=utf-8
from __future__ import absolute_import

import json

import ldap
from octoprint_auth_ldap.tweaks import DependentOnSettingsPlugin, SettingsPlugin


class LDAPConnection(DependentOnSettingsPlugin):
    def __init__(self, plugin: SettingsPlugin):
        DependentOnSettingsPlugin.__init__(self, plugin)

    def get_client(self, user=None, password=None):
        uri = self.settings.get(["uri"])
        if not uri:
            self.logger.debug("No LDAP URI")
            return None

        if not user:
            user = self.settings.get(["auth_user"])
            password = self.settings.get(["auth_password"])

        try:
            self.logger.debug("Initializing LDAP connection to %s" % uri)
            client = ldap.initialize(uri)
            if self.settings.get(["request_tls_cert"]):
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
        except ldap.LDAPError as e:
            self.logger.error(json.dumps(e))
        return None

    def search(self, ldap_filter, base=None, scope=ldap.SCOPE_SUBTREE):
        if not base:
            base = self.settings.get(["search_base"])
        try:
            client = self.get_client()
            if client is not None:
                self.logger.debug("Searching LDAP, base: %s and filter: %s" % (base, ldap_filter))
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


class DependentOnLDAPConnection:
    # noinspection PyShadowingNames
    def __init__(self, ldap: LDAPConnection):
        self._ldap = ldap

    @property
    def ldap(self) -> LDAPConnection:
        return self._ldap
