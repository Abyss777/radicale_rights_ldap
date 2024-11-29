# This file is part of Radicale - CalDAV and CardDAV server
# Copyright © 2024 Andrey Kunitsyn
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Radicale.  If not, see <http://www.gnu.org/licenses/>.
"""
Rights backend that allows authenticated users to read and write their own
calendars and address books, allows authenticated users to read GAL and GCAL,
allows members of editors group to write GCAL

"""
import ssl
import radicale.rights.authenticated as authenticated
from radicale import pathutils, config
from radicale.log import logger


class Rights(authenticated.Rights):

    _ldap_uri: str
    _ldap_base: str
    _ldap_reader_dn: str
    _ldap_secret: str
    _ldap_filter: str
    _ldap_version: int = 3
    _ldap_use_ssl: bool = False
    _ldap_ssl_verify_mode: int = ssl.CERT_REQUIRED
    _ldap_ssl_ca_file: str = ""

    _gal_path: str
    _gcal_path: str
    _gcal_group_dn: str


    def __init__(self, configuration: config.Configuration) -> None:
        super().__init__(configuration)
        try:
            import ldap3
            self.ldap3 = ldap3
        except ImportError:
            try:
                import ldap
                self._ldap_version = 2
                self.ldap = ldap
            except ImportError as e:
                raise RuntimeError("LDAP authentication requires the ldap3 module") from e
        self._ldap_uri = configuration.get("auth", "ldap_uri")
        self._ldap_base = configuration.get("auth", "ldap_base")
        self._ldap_reader_dn = configuration.get("auth", "ldap_reader_dn")
        self._ldap_secret = configuration.get("auth", "ldap_secret")
        ldap_secret_file_path = configuration.get("auth", "ldap_secret_file")
        if ldap_secret_file_path:
            with open(ldap_secret_file_path, 'r') as file:
                self._ldap_secret = file.read().rstrip('\n')
        if self._ldap_version == 3:
            self._ldap_use_ssl = configuration.get("auth", "ldap_use_ssl")
            if self._ldap_use_ssl:
                self._ldap_ssl_ca_file = configuration.get("auth", "ldap_ssl_ca_file")
                tmp = configuration.get("auth", "ldap_ssl_verify_mode")
                if tmp == "NONE":
                    self._ldap_ssl_verify_mode = ssl.CERT_NONE
                elif tmp == "OPTIONAL":
                    self._ldap_ssl_verify_mode = ssl.CERT_OPTIONAL
        self._gal_path = configuration.get("rights", "gal_path")
        self._gcal_path = configuration.get("rights", "gcal_path")
        self._gcal_group_dn = configuration.get("rights", "gcal_group_dn")
        self._ldap_filter = configuration.get("rights", "ldap_filter")

    def _check_group_membership2(self, user: str, group: str) -> bool:
        try:
            """Bind as reader dn"""
            logger.debug(f"_check_group_membership2 {self._ldap_uri}, {self._ldap_reader_dn}")
            conn = self.ldap.initialize(self._ldap_uri)
            conn.protocol_version = 3
            conn.set_option(self.ldap.OPT_REFERRALS, 0)
            conn.set_option(self.ldap.OPT_PROTOCOL_VERSION, 3)
            conn.simple_bind_s(self._ldap_reader_dn, self._ldap_secret)
            """Search for the user in group"""
            res = conn.search_s(self._ldap_base, self.ldap.SCOPE_SUBTREE, filterstr=self._ldap_filter.format(user, group), attrlist=['sAMAccountName'])
            if len(res) == 0:
                logger.debug(f"_check_group_membership2 user '{user}' is not a member of {group}")
                return False
            else:
                logger.debug(f"_check_group_membership2 user '{user}' is a memeber of {group}")
                return True
        except Exception as e:
            raise RuntimeError(f"Invalid ldap configuration:{e}")

    def _check_group_membership3(self, user: str, group: str) -> bool:
        """Connect the server"""
        try:
            logger.debug(f"_check_group_membership3 {self._ldap_uri}, {self._ldap_reader_dn}")
            if self._ldap_use_ssl:
                tls = self.ldap3.Tls(validate=self._ldap_ssl_verify_mode)
                if self._ldap_ssl_ca_file != "":
                    tls = self.ldap3.Tls(
                        validate=self._ldap_ssl_verify_mode,
                        ca_certs_file=self._ldap_ssl_ca_file
                        )
                server = self.ldap3.Server(self._ldap_uri, use_ssl=True, tls=tls)
            else:
                server = self.ldap3.Server(self._ldap_uri)
            conn = self.ldap3.Connection(server, self._ldap_reader_dn, password=self._ldap_secret)
        except self.ldap3.core.exceptions.LDAPSocketOpenError:
            raise RuntimeError("Unable to reach ldap server")
        except Exception as e:
            logger.debug(f"_check_group_membership3 error 1 {e}")
            pass

        if not conn.bind():
            logger.debug("_check_group_membership3 can not bind")
            raise RuntimeError("Unable to read from ldap server")

        logger.debug(f"_check_group_membership3 bind as {self._ldap_reader_dn}")
        """Search the user dn"""
        conn.search(
            search_base=self._ldap_base,
            search_filter=self._ldap_filter.format(user, group),
            search_scope=self.ldap3.SUBTREE,
            attributes=['sAMAccountName']
        )
        if len(conn.entries) == 0:
            logger.debug(f"_check_group_membership3 user '{user}' is not a member of {group}")
            return False
        else:
            logger.debug(f"_check_group_membership3 user '{user}' is a memeber of {group}")
            return True

    def check_group_membership(self, user: str, group: str) -> bool:
        """
        Check if user is a memeber of the group
        """
        if self._ldap_version == 2:
            return self._check_group_membership2(user, group)
        return self._check_group_membership3(user, group)


    def authorization(self, user: str, path: str) -> str:
        if self._verify_user and not user:
            return ""
        sane_path = pathutils.strip_path(path)
        if not sane_path:
            return "R"
        if sane_path == self._gal_path:
            return "r"
        if sane_path == self._gcal_path:
            if self.check_group_membership(user, self._gcal_group_dn):
                return "rw"
            return "r"
        if self._verify_user and user != sane_path.split("/", maxsplit=1)[0]:
            return ""
        if "/" not in sane_path:
            return "RW"
        if sane_path.count("/") == 1:
            return "rw"
        return ""
