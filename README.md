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
# Path to Global Address List
gal_path = shared/gal
# Path to Global Clients Address List
gcal_path = shared/clients
# Group of Global Clients Address List editors
gcal_group_dn = CN=Mail_GCAL_Editors,OU=Radicale,OU=Security,DC=domain,DC=local
# ldap filter to check group membership (with nested)
ldap_filter = (&(objectClass=person)(sAMAccountName={0})(memberof:1.2.840.113556.1.4.1941:={1})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
#[logging]
#level = debug

```
