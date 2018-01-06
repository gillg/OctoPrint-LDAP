# coding=utf-8
from __future__ import absolute_import

import octoprint.plugin
from octoprint.users import UserManager, FilebasedUserManager, User
from octoprint.settings import settings
import ldap
import random
import string
import os


class LDAPUserManager(FilebasedUserManager, octoprint.plugin.SettingsPlugin, octoprint.plugin.TemplatePlugin):

	# Login phase :
	# - findUser called, if it return a user
	# - checkPassword called, if it return True
	# - login_user called with User returned by previous findUser

	_localUserManager = FilebasedUserManager()

	def __init__(self):
		if settings().get(["accessControl", "userManager"]) == 'octoprint_authldap.LDAPUserManager':
			if settings().get(["plugins", "authldap", "ldap_uri"]) is not None\
					and settings().get(["plugins", "authldap", "ldap_bind_user"]) is not None \
					and settings().get(["plugins", "authldap", "ldap_bind_password"]) is not None \
					and settings().get(["plugins", "authldap", "ldap_search_base"]) is not None \
					and settings().get(["plugins", "authldap", "ldap_query"]) is not None:
				connection = ldap.initialize(settings().get(["plugins", "authldap", "ldap_uri"]))
				connection.set_option(ldap.OPT_REFERRALS, 0)
				if settings().get(["plugins", "authldap", "ldap_method"]) == 'TLS':
					ldap_verifypeer = settings().get(
						["plugins", "authldap", "ldap_tls_reqcert"])
					verifypeer = ldap.OPT_X_TLS_HARD
					if ldap_verifypeer == 'NEVER':
						verifypeer = ldap.OPT_X_TLS_NEVER
					elif ldap_verifypeer == 'ALLOW':
						verifypeer = ldap.OPT_X_TLS_ALLOW
					elif ldap_verifypeer == 'TRY':
						verifypeer = ldap.OPT_X_TLS_TRY
					elif ldap_verifypeer == 'DEMAND':
						verifypeer = ldap.OPT_X_TLS_DEMAND
					# elif ldap_verifypeer == 'HARD':
					#   verifypeer = ldap.OPT_X_TLS_HARD
					connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, verifypeer)
					try:
						connection.start_tls_s()
					except:
						pass
				try:
					connection.simple_bind_s(settings().get(["plugins", "authldap", "ldap_bind_user"]), settings().get(["plugins", "authldap", "ldap_bind_password"]))
					connection.unbind_s()

					FilebasedUserManager.__init__(self)
					return
				except:
					pass
			settings().remove(["accessControl", "userManager"])
			settings().remove(["plugins", "authldap", "active"])
			settings().save()
			os.system('kill $PPID')

	def findUser(self, userid=None, apikey=None, session=None):
		user = UserManager.findUser(self, userid=userid, session=session)

		if user is not None:
			self._logger.debug("User already logged in.")
			return user

		elif apikey is not None:
			self._logger.debug("User logs in via API Key.")
			return self._localUserManager.findUser(apikey=apikey, session=session)

		elif userid is not None:
			self._logger.debug("User not yet logged in: %s" % userid)
			local_user = self._localUserManager.findUser(userid=userid, session=session)
			if local_user is not None:
				self._logger.debug("User found locally")
				return local_user
			elif self.findLDAPUser(userid):
				self._logger.debug("User found in LDAP")
				password = ''.join([random.choice(string.lowercase) for i in range(10)])
				if settings().get(["plugins", "authldap", "roles"]) is not None:
					roles = [x.strip() for x in settings().get(["plugins", "authldap", "roles"]).split(',')]
				self._localUserManager.addUser(userid, password, active=settings().getBoolean(["plugins", "authldap", "auto_activate"]), roles=roles)
				return self._localUserManager.findUser(userid=userid, session=session)
			else:
				return None
		else:
			return None

	def findLDAPUser(self, userid):
		userid = self.escapeLDAP(userid)
		self._logger.debug("Searching User in ldap: %s" % userid)

		connection = self.getLDAPClient()
		try:
			self._logger.debug("Binding LDAP with User: %s" % settings().get(["plugins", "authldap", "ldap_bind_user"]))
			connection.simple_bind_s(
				settings().get(["plugins", "authldap", "ldap_bind_user"]),
				settings().get(["plugins", "authldap", "ldap_bind_password"])
			)
			query = settings().get(["plugins", "authldap", "ldap_query"]).format(uid=userid)
			self._logger.debug("Searching for \"uid=%s\" under \"%s\" " % (query, settings().get(["plugins", "authldap", "ldap_search_base"])))
			result = connection.search_s(
				settings().get(["plugins", "authldap", "ldap_search_base"]),
				ldap.SCOPE_SUBTREE,
				query
			)
			connection.unbind_s()
			self._logger.debug("Search finished.")
			if result is None or len(result) == 0:
				self._logger.debug("No User Found in LDAP")
				return None
			# Get the DN of first user found
			dn, data = result[0]
			self._logger.debug("User Found %s" % dn)
			return dn
		except ldap.SERVER_DOWN:
			self._logger.debug("LDAP Server unreachable!")
		return None

	def checkPassword(self, username, password):
		self._logger.debug("Checking Password")
		if self.findLDAPUser(username) is not None:
			self._logger.debug("User is a LDAP User")
			try:
				connection = self.getLDAPClient()
				username = self.escapeLDAP(username)
				dn = self.findLDAPUser(username)
				connection.simple_bind_s(dn, password)
				connection.unbind_s()
				return True

			except ldap.INVALID_CREDENTIALS:
				self._logger.error("Username or password is incorrect.")
		else:
			self._logger.debug("User is a local user")
			return self._localUserManager.checkPassword(username, password)

	def changeUserPassword(self, username, password):
		# Changing password of LDAP users is not allowed
		if self.findLDAPUser(username) is None:
			return self._localUserManager.changeUserPassword(username, password)
		else:
			self._logger.error("User is not allowed to change the Password.")

	def getLDAPClient(self):
		self._logger.debug("Creating LDAP Client")
		ldap_server=settings().get(["plugins", "authldap", "ldap_uri"])
		self._logger.debug("LDAP URL %s" % ldap_server)
		if not ldap_server:
			settings().remove(["accessControl", "userManager"])
			self._logger.debug("UserManager: %s" % settings().get(["accessControl", "userManager"]))
			raise Exception("LDAP conf error, server is missing")

		connection = ldap.initialize(ldap_server)
		connection.set_option(ldap.OPT_REFERRALS,0)
		self._logger.debug("LDAP initialized")

		if settings().get(["plugins", "authldap", "ldap_method"]) == 'TLS':
			self._logger.debug("LDAP is using TLS, setting ldap options...")
			ldap_verifypeer = settings().get(
				["plugins", "authldap", "ldap_tls_reqcert"])
			verifypeer = ldap.OPT_X_TLS_HARD
			if ldap_verifypeer == 'NEVER':
				verifypeer = ldap.OPT_X_TLS_NEVER
			elif ldap_verifypeer == 'ALLOW':
				verifypeer = ldap.OPT_X_TLS_ALLOW
			elif ldap_verifypeer == 'TRY':
				verifypeer = ldap.OPT_X_TLS_TRY
			elif ldap_verifypeer == 'DEMAND':
				verifypeer = ldap.OPT_X_TLS_DEMAND
			# elif ldap_verifypeer == 'HARD':
			#   verifypeer = ldap.OPT_X_TLS_HARD
			connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, verifypeer)
			try:
				connection.start_tls_s()
				self._logger.error("TLS connection established.")
			except:
				self._logger.error("Error initializing tls connection")
				pass
		self._logger.error("Finished creating connection")
		return connection

	def escapeLDAP(self, str):
		reservedStrings = ['+', '=', '\\', '\r',
						   '\n', '#', ',', '>', '<', '"', ';']
		for ch in reservedStrings:
			if ch in str:
				str = str.replace(ch, '\\' + ch)
		return str

	# Softwareupdate hook

	def get_update_information(self):
		return dict(
			authldap=dict(
				displayName="AuthLDAP",
				displayVersion=self._plugin_version,

				# version check: github repository
				type="github_release",
				user="gillg",
				repo="OctoPrint-LDAP",
				current=self._plugin_version,

				# update method: pip
				pip=("https://github.com"
					 "/gillg/OctoPrint-LDAP/archive/{target_version}.zip")
			)
		)

	# UserManager hook

	def ldap_user_factory(components, settings, *args, **kwargs):
		return LDAPUserManager()

	# SettingsPlugin

	def get_settings_defaults(self):
		return dict(
			active=False,
			ldap_uri=None,
			ldap_search_base=None,
			ldap_query=None,
			ldap_method=None,
			auto_activate=False,
			roles=None,
			ldap_tls_reqcert=None,
			ldap_bind_user=None,
			ldap_bind_password = None
		)

	def on_settings_save(self, data):
		old_flag = self._settings.get_boolean(["active"])
		octoprint.plugin.SettingsPlugin.on_settings_save(self, data)
		new_flag = self._settings.get_boolean(["active"])
		if new_flag != old_flag:
			if new_flag:
				self._logger.warning("Warning! Activating LDAP Plugin")
				settings().set(["accessControl", "userManager"],'octoprint_authldap.LDAPUserManager')
				settings().save()
			else:
				if settings().get(["accessControl", "userManager"]) == 'octoprint_authldap.LDAPUserManager':
					self._logger.warning("Deactivating LDAP Plugin")
					settings().remove(["accessControl", "userManager"])
					settings().save()

	# TemplatePlugin

	def get_template_configs(self):
		return [
			dict(type="settings", custom_bindings=False)
		]


__plugin_name__ = "Auth LDAP"


def __plugin_load__():
	global __plugin_implementation__
	__plugin_implementation__ = LDAPUserManager()

	global __plugin_hooks__
	__plugin_hooks__ = {
		"octoprint.plugin.softwareupdate.check_config":
			__plugin_implementation__.get_update_information,
	}

# @TODO Command clean LDAP users deleted
