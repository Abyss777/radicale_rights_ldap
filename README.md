# radicale_rights_ldap

Config example

```ini
[auth]
type = http_x_remote_user
ldap_uri = ldaps://dc1.domain.local ldaps://dc2.domain.local
ldap_base = DC=domain,DC=local
ldap_reader_dn = ldapradicale
ldap_secret = ldap_radicale_password
ldap_use_ssl = True
[storage]
filesystem_folder = /var/lib/radicale
[rights]
type = radicale_rights_ldap
# Shared collection root path
shared_collection = shared
# Pattern for shared calendar group with readers
shared_calendar_group_r = CN=Mail_Calendar_{0}_R,OU=Shared,OU=Radicale,OU=Security,DC=domain,DC=local
# Pattern for shared calendar group with writers
shared_calendar_group_rw = CN=Mail_Calendar_{0}_RW,OU=Shared,OU=Radicale,OU=Security,DC=domain,DC=local
# Pattern for shared address book with readers
shared_abook_group_r = CN=Mail_Abook_{0}_R,OU=Shared,OU=Radicale,OU=Security,DC=domain,DC=local
# Pattern for shared address book with writers
shared_abook_group_rw = CN=Mail_Abook_{0}_RW,OU=Shared,OU=Radicale,OU=Security,DC=domain,DC=local
# Subpath to Global Address List
gal_path = gal
# Subpath to Global Clients Address List
gcal_path = clients
# Group of Global Clients Address List editors
gcal_group_dn = CN=Mail_GCAL_Editors,OU=Radicale,OU=Security,DC=domain,DC=local
# ldap filter to check group membership (with nested)
ldap_filter = (&(objectClass=person)(sAMAccountName={0})(memberof:1.2.840.113556.1.4.1941:={1})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
#[logging]
#level = debug

```
