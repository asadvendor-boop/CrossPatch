REVOKE ALL ON DATABASE crosspatch_victim FROM PUBLIC;

CREATE ROLE crosspatch_victim_owner NOLOGIN
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;

ALTER DATABASE crosspatch_victim OWNER TO crosspatch_victim_owner;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO crosspatch_victim_owner;

SET ROLE crosspatch_victim_owner;
\i /bootstrap/victim-init.sql
RESET ROLE;
\i /bootstrap/victim-roles.sql
