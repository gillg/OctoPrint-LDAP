# coding=utf-8
from __future__ import absolute_import

from octoprint_auth_ldap.plugin import AuthLDAPPlugin

__plugin_name__ = "Auth LDAP"
__plugin_pythoncompat__ = ">=3,<4"


def __plugin_load__():
    # noinspection PyGlobalUndefined
    global __plugin_implementation__
    __plugin_implementation__ = AuthLDAPPlugin()

    # noinspection PyGlobalUndefined
    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.access.users.factory": __plugin_implementation__.ldap_user_factory,
        "octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information
    }
