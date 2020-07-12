# coding=utf-8
from __future__ import absolute_import

from octoprint.access.groups import Group


class LDAPGroup(Group):
    GROUP_TYPE = "LDAP"

    def __init__(
            self,
            key,
            name,
            description="",
            permissions=None,
            subgroups=None,
            default=False,
            removable=True,
            changeable=True,
            toggleable=True,
            dn=None
    ):
        Group.__init__(
            self,
            key=key,
            name=name,
            description=description,
            permissions=permissions,
            subgroups=subgroups,
            default=default,
            removable=removable,
            changeable=changeable,
            toggleable=toggleable
        )
        # TODO validate distinguished name
        self._dn = dn

    @property
    def distinguished_name(self):
        return self._dn
