# coding=utf-8
from __future__ import absolute_import

from octoprint.access.users import User


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
        # TODO validate distinguished name
        self._dn = dn

    @property
    def distinguished_name(self):
        return self._dn
