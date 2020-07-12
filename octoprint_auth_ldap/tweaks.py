# coding=utf-8
from __future__ import absolute_import

import logging
from logging import Logger

from octoprint.plugin import SettingsPlugin as OctoPrintSettingPlugin, PluginSettings


class SettingsPlugin(OctoPrintSettingPlugin):
    @property
    def settings(self) -> PluginSettings:
        return self._settings

    @property
    def identifier(self) -> str:
        return self._identifier

    @property
    def logger(self) -> Logger:
        if "_logger" in self.__dict__:
            return self._logger
        else:
            # FIXME vexingly, sometimes we want to log things before the logger is injected
            return logging.getLogger("octoprint.plugins.auth_ldap")


class DependentOnSettingsPlugin:
    def __init__(self, plugin: SettingsPlugin):
        self._plugin = plugin

    @property
    def plugin(self):
        return self._plugin

    @property
    def logger(self) -> Logger:
        return self._plugin.logger

    @property
    def settings(self) -> PluginSettings:
        return self._plugin.settings
