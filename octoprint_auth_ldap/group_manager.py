# coding=utf-8
from __future__ import absolute_import

import io
import os
import re

import yaml
from octoprint.access.groups import FilebasedGroupManager, Group, GroupAlreadyExists
from octoprint.access.permissions import Permissions, OctoPrintPermission
from octoprint.util import atomic_write
from octoprint_auth_ldap.constants import OU, OU_FILTER, DISTINGUISHED_NAME, LDAP_PARENT_GROUP_NAME, \
    LDAP_PARENT_GROUP_DESCRIPTION, LDAP_PARENT_GROUP_KEY, LDAP_GROUP_KEY_PREFIX
from octoprint_auth_ldap.group import LDAPGroup
from octoprint_auth_ldap.ldap import DependentOnLDAPConnection
from octoprint_auth_ldap.tweaks import DependentOnSettingsPlugin
from octoprint_auth_ldap.user import LDAPUser


class LDAPGroupManager(FilebasedGroupManager, DependentOnSettingsPlugin, DependentOnLDAPConnection):

    def __init__(self, plugin, ldap, path=None):
        DependentOnSettingsPlugin.__init__(self, plugin)
        DependentOnLDAPConnection.__init__(self, ldap)
        FilebasedGroupManager.__init__(self, path)

    def add_group(
        self,
        key,
        name,
        description,
        permissions,
        subgroups,
        default=False,
        removable=True,
        changeable=True,
        toggleable=True,
        overwrite=False,
        notify=True,
        save=True,
        dn=None
    ):
        if dn is None:
            FilebasedGroupManager.add_group(
                self,
                key=key,
                name=name,
                description=description,
                permissions=permissions,
                subgroups=subgroups,
                default=default,
                removable=False if key == LDAP_PARENT_GROUP_KEY else removable,
                changeable=True if key == LDAP_PARENT_GROUP_KEY else changeable,
                toggleable=toggleable,
                overwrite=overwrite,
                notify=notify,
                save=save
            )
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
                key=key,
                name=name,
                description=description,
                permissions=permissions,
                subgroups=subgroups,
                default=default,
                changeable=True,
                removable=False,
                dn=dn
            )
            self._groups[key] = group
            self.logger.debug("Added group %s as %s" % (name, LDAPGroup.__name__))

            if save:
                self._dirty = True
                self._save()

            if notify:
                self._notify_listeners("added", group)

    def _to_group_key(self, ou_common_name):
        return "%s%s" % (
            self.settings.get([LDAP_GROUP_KEY_PREFIX]), re.sub(r"\W+", "_", ou_common_name.strip().lower()))

    def _refresh_ldap_groups(self):
        ou = self.settings.get([OU])
        if ou is not None or ou == "":  # FIXME allowing empty string settings is dumb
            self.logger.info("Syncing LDAP groups to local groups based on %s settings" % self.plugin.identifier)

            try:
                self.add_group(key=self.settings.get([LDAP_PARENT_GROUP_KEY]),
                               name=self.settings.get([LDAP_PARENT_GROUP_NAME]),
                               description=self.settings.get([LDAP_PARENT_GROUP_DESCRIPTION]),
                               permissions=[],
                               subgroups=[],
                               overwrite=False
                               )
            except GroupAlreadyExists:
                assert True

            organizational_units = [group.strip() for group in str(self.settings.get([OU])).split(",")]
            ldap_groups = [group.get_name() for group in self._groups.values() if isinstance(group, LDAPGroup)]
            ou_filter = self.settings.get([OU_FILTER])

            for ou_common_name in list(set(organizational_units) - set(ldap_groups)):
                key = self._to_group_key(ou_common_name)
                this_group = self.find_group(key)
                if this_group is None:
                    result = self.ldap.search("(" + ou_filter % ou_common_name.strip() + ")")
                    self.add_group(key=key,
                                   name=ou_common_name,
                                   dn=result[DISTINGUISHED_NAME],
                                   description="Synced LDAP Group",
                                   permissions=[],
                                   subgroups=[],
                                   toggleable=True,
                                   removable=False,
                                   changeable=True,
                                   save=False
                                   )

            self.update_group(
                self.settings.get([LDAP_PARENT_GROUP_KEY]),
                subgroups=[group for group in self._groups.values() if isinstance(group, LDAPGroup)],
                save=True
            )

    def get_ldap_groups_for(self, dn):
        if isinstance(dn, LDAPUser):
            dn = dn.distinguished_name
        self._refresh_ldap_groups()
        memberships = self.ldap.get_ou_memberships_for(dn)
        if memberships is False:
            return []
        return list(map(lambda g: self._to_group_key(g), memberships))

    def _load(self):
        if os.path.exists(self._groupfile) and os.path.isfile(self._groupfile):
            try:
                with io.open(self._groupfile, 'rt', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    version = data.pop("_version", 1)

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
                        if permission.key not in tracked_permissions and permission not in permissions:
                            permissions.append(permission)

                    subgroups = attributes.get("subgroups", [])

                    group_type = attributes.get("type", False)

                    if group_type == LDAPGroup.GROUP_TYPE:
                        self.logger.debug("Loading group %s as %s" % (attributes.get("name", key), LDAPGroup.__name__))
                        group = LDAPGroup(
                            key,
                            attributes.get("name", key),
                            description=attributes.get("description", ""),
                            permissions=permissions,
                            subgroups=subgroups,
                            default=attributes.get("default", False),
                            removable=False,
                            changeable=changeable,
                            toggleable=toggleable,
                            dn=attributes.get(DISTINGUISHED_NAME, None)
                        )
                    else:
                        self.logger.debug("Loading group %s as %s" % (attributes.get("name", key), Group.__name__))
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
                self.logger.debug("Saving group %s as %s" % (group.get_name(), LDAPGroup.__name__))
                groups[key] = dict(
                    type=LDAPGroup.GROUP_TYPE,
                    dn=group.distinguished_name,

                    name=group.get_name(),
                    description=group.get_description(),
                    permissions=self._from_permissions(*group.permissions),
                    subgroups=self._from_groups(*group.subgroups),
                    default=group.is_default()
                )
            else:
                self.logger.debug("Saving group %s as %s" % (group.get_name(), Group.__name__))
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
