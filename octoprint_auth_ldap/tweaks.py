# coding=utf-8
from __future__ import absolute_import

import logging

from octoprint.plugin import SettingsPlugin as OctoPrintSettingPlugin


class SettingsPlugin(OctoPrintSettingPlugin):
    @property
    def settings(self):
        return self._settings

    @property
    def identifier(self):
        return self._identifier

    @property
    def logger(self):
        if "_logger" in self.__dict__:
            return self._logger
        else:
            # FIXME vexingly, sometimes we want to log things before the logger is injected
            return logging.getLogger("octoprint.plugins.auth_ldap")


class DependentOnSettingsPlugin:
    def __init__(self, plugin):
        self._plugin = plugin

    @property
    def plugin(self):
        return self._plugin

    @property
    def logger(self):
        return self._plugin.logger

    @property
    def settings(self):
        return self._plugin.settings
