# coding=utf-8
from __future__ import absolute_import

import io
import os

import yaml
from octoprint.access.groups import FilebasedGroupManager, Group, GroupAlreadyExists
from octoprint.access.permissions import Permissions, OctoPrintPermission
from octoprint.util import atomic_write
from octoprint_auth_ldap.ldap import LDAPConnection, DependentOnLDAPConnection
from octoprint_auth_ldap.tweaks import SettingsPlugin, DependentOnSettingsPlugin


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
        # TODO throw error on missing/invalid dn?
        self.distinguished_name = dn


# TODO map LDAP groups on to OctoPrint groups?
class LDAPGroupManager(FilebasedGroupManager, DependentOnSettingsPlugin, DependentOnLDAPConnection):
    def __init__(self, plugin: SettingsPlugin, ldap: LDAPConnection, path=None):
        DependentOnSettingsPlugin.__init__(self, plugin)
        DependentOnLDAPConnection.__init__(self, ldap)
        FilebasedGroupManager.__init__(self, path)

    def add_group(self, key, name, description, permissions, subgroups, default=False, removable=True,
                  changeable=True, toggleable=True, overwrite=False, notify=True, save=True, dn=None):
        if dn is None:
            return FilebasedGroupManager.add_group(self, key, name, description, permissions, subgroups, default,
                                                   removable, changeable, toggleable, overwrite, notify, save)
        else:
            if key in self._groups and not overwrite:
                raise GroupAlreadyExists(key)

            if not permissions:
                permissions = []

            permissions = self._to_permissions(*permissions)
            assert (all(map(lambda p: isinstance(p, OctoPrintPermission), permissions)))

            subgroups = self._to_groups(*subgroups)
            assert (all(map(lambda g: isinstance(g, Group), subgroups)))

            group = LDAPGroup(
                key,
                name,
                description=description,
                permissions=permissions,
                subgroups=subgroups,
                default=default,
                changeable=True,
                removable=False,
                toggleable=False,
                dn=dn,
            )
            self._groups[key] = group

            if save:
                self._dirty = True
                self._save()

            if notify:
                self._notify_listeners("added", group)

    def sync_with_ldap(self):
        # TODO remove de-configured groups
        # TODO make all LDAP synced groups subgroups of LDAP super-group
        # TODO synced group key-naming scheme "LDAP:dn"?
        ldap_groups_from_settings = [group.strip() for group in str(self.settings.get(["ldap_groups"])).split(",")]
        ldap_type_groups = [group.get_name() for group in self._groups.values() if isinstance(group, LDAPGroup)]
        ldap_group_filter = self.settings.get(["ldap_group_filter"])
        self.logger.debug("settings=%s, groups=%s, diff=%s" % (
        ldap_groups_from_settings, ldap_type_groups, list(set(ldap_groups_from_settings) - set(ldap_type_groups))))
        for ldap_group in list(set(ldap_groups_from_settings) - set(ldap_type_groups)):
            result = self.ldap.search("(" + ldap_group_filter % ldap_group.strip() + ")")
            self.add_group(
                key=result["dn"],
                name=ldap_group,
                dn=result["dn"],
                description="Synced LDAP Group",
                permissions=[],
                subgroups=[],
                toggleable=False,
                removable=False,
                save=self.settings.get(["local_cache"])
            )

    def _load(self):
        if os.path.exists(self._groupfile) and os.path.isfile(self._groupfile):
            try:
                with io.open(self._groupfile, 'rt', encoding='utf-8') as f:
                    data = yaml.safe_load(f)

                if "groups" not in data:
                    groups = data
                    data = dict(groups=groups)

                groups = data.get("groups", dict())
                tracked_permissions = data.get("tracked", list())

                for key, attributes in groups.items():
                    if key in self._groups:
                        # group is already there (from the defaults most likely)
                        if not self._groups[key].is_changeable():
                            # group may not be changed -> bail
                            continue

                        removable = self._groups[key].is_removable()
                        changeable = self._groups[key].is_changeable()
                        toggleable = self._groups[key].is_toggleable()
                    else:
                        removable = True
                        changeable = True
                        toggleable = True

                    permissions = self._to_permissions(*attributes.get("permissions", []))
                    default_permissions = self.default_permissions_for_group(key)
                    for permission in default_permissions:
                        if not permission.key in tracked_permissions and not permission in permissions:
                            permissions.append(permission)

                    subgroups = attributes.get("subgroups", [])

                    group_type = attributes.get("type", False)

                    if group_type == LDAPGroup.GROUP_TYPE:
                        group = LDAPGroup(
                            key,
                            attributes.get("name", ""),
                            description=attributes.get("description", ""),
                            permissions=permissions,
                            subgroups=subgroups,
                            default=attributes.get("default", False),
                            removable=removable,
                            changeable=changeable,
                            toggleable=toggleable,
                            dn=attributes.get("dn", None)
                        )
                    else:
                        group = Group(key, attributes.get("name", ""),
                                      description=attributes.get("description", ""),
                                      permissions=permissions,
                                      subgroups=subgroups,
                                      default=attributes.get("default", False),
                                      removable=removable,
                                      changeable=changeable,
                                      toggleable=toggleable)
                    self._groups[key] = group

                for group in self._groups.values():
                    group._subgroups = self._to_groups(*group._subgroups)

            except Exception:
                self.logger.exception("Error while loading groups from file {}".format(self._groupfile))

    def _save(self, force=False):
        if self._groupfile is None or not self._dirty and not force:
            return

        groups = dict()
        for key, group in self._groups.items():
            if not group or not isinstance(group, Group):
                self.logger.debug('Not saving %s' % key)
                continue

            if isinstance(group, LDAPGroup):
                groups[key] = dict(
                    type=LDAPGroup.GROUP_TYPE,
                    dn=group.distinguished_name,

                    name=group._name,
                    description=group._description,
                    permissions=self._from_permissions(*group._permissions),
                    subgroups=self._from_groups(*group._subgroups),
                    default=group._default
                )
            else:
                groups[key] = dict(
                    name=group._name,
                    description=group._description,
                    permissions=self._from_permissions(*group._permissions),
                    subgroups=self._from_groups(*group._subgroups),
                    default=group._default
                )

        data = dict(groups=groups,
                    tracked=[x.key for x in Permissions.all()])

        with atomic_write(self._groupfile, mode='wt', permissions=0o600, max_permissions=0o666) as f:
            import yaml
            yaml.safe_dump(data, f, default_flow_style=False, indent=4, allow_unicode=True)
            self._dirty = False
        self._load()
