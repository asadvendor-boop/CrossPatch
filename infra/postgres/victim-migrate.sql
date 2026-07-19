SET ROLE crosspatch_victim_owner;
\i /bootstrap/victim-init.sql
RESET ROLE;
\i /bootstrap/victim-roles.sql
