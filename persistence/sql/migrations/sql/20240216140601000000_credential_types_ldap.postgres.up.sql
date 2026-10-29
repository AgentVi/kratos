INSERT INTO identity_credential_types (id, name) SELECT '6e82770e-f534-435a-a1bd-3815412aa03e', 'ldap' WHERE NOT EXISTS ( SELECT * FROM identity_credential_types WHERE name = 'ldap');
