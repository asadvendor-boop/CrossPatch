\getenv candidate_password CROSSPATCH_VICTIM_CANDIDATE_PASSWORD
\getenv app_password CROSSPATCH_VICTIM_APP_PASSWORD
\getenv worker_password CROSSPATCH_VICTIM_WORKER_PASSWORD
\getenv oracle_password CROSSPATCH_VICTIM_ORACLE_PASSWORD
\getenv scope_password CROSSPATCH_VICTIM_SCOPE_PASSWORD

SELECT 'CREATE ROLE crosspatch_victim NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'crosspatch_victim') \gexec
ALTER ROLE crosspatch_victim NOLOGIN;

SELECT 'CREATE ROLE crosspatch_victim_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'crosspatch_victim_app') \gexec
SELECT format('ALTER ROLE crosspatch_victim_app WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', :'app_password') \gexec

SELECT 'CREATE ROLE crosspatch_victim_candidate NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'crosspatch_victim_candidate') \gexec
SELECT format('ALTER ROLE crosspatch_victim_candidate WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', :'candidate_password') \gexec

SELECT 'CREATE ROLE crosspatch_victim_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'crosspatch_victim_worker') \gexec
SELECT format('ALTER ROLE crosspatch_victim_worker WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', :'worker_password') \gexec

SELECT 'CREATE ROLE crosspatch_victim_oracle NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'crosspatch_victim_oracle') \gexec
SELECT format('ALTER ROLE crosspatch_victim_oracle WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', :'oracle_password') \gexec

SELECT 'CREATE ROLE crosspatch_victim_scope NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'crosspatch_victim_scope') \gexec
SELECT format('ALTER ROLE crosspatch_victim_scope WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', :'scope_password') \gexec

REVOKE ALL ON DATABASE crosspatch_victim FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM crosspatch_victim, crosspatch_victim_app, crosspatch_victim_candidate, crosspatch_victim_worker, crosspatch_victim_oracle, crosspatch_victim_scope;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM crosspatch_victim, crosspatch_victim_app, crosspatch_victim_candidate, crosspatch_victim_worker, crosspatch_victim_oracle, crosspatch_victim_scope;

GRANT CONNECT ON DATABASE crosspatch_victim TO crosspatch_victim_app, crosspatch_victim_candidate, crosspatch_victim_worker, crosspatch_victim_oracle, crosspatch_victim_scope;
GRANT USAGE ON SCHEMA public TO crosspatch_victim_app, crosspatch_victim_candidate, crosspatch_victim_worker, crosspatch_victim_oracle, crosspatch_victim_scope;

-- The long-lived sample victim is trusted application code, not model-authored code.
GRANT SELECT, INSERT ON webhook_receipts, outbox_jobs TO crosspatch_victim_app;
GRANT USAGE, SELECT ON SEQUENCE outbox_jobs_id_seq TO crosspatch_victim_app;

-- Candidate grants are additionally restricted to one server-bound event by RLS.
GRANT SELECT ON webhook_receipts TO crosspatch_victim_candidate;
GRANT INSERT ON webhook_receipts, outbox_jobs TO crosspatch_victim_candidate;
GRANT USAGE, SELECT ON SEQUENCE outbox_jobs_id_seq TO crosspatch_victim_candidate;

-- Worker grants: delivery mutation stays outside candidate code.
GRANT SELECT ON webhook_receipts, outbox_jobs, deliveries TO crosspatch_victim_worker;
GRANT UPDATE ON outbox_jobs TO crosspatch_victim_worker;
GRANT INSERT ON deliveries TO crosspatch_victim_worker;
GRANT USAGE, SELECT ON SEQUENCE deliveries_id_seq TO crosspatch_victim_worker;

-- Oracle grants: trusted cleanup and observations cannot manufacture rows.
GRANT SELECT, DELETE ON webhook_receipts, outbox_jobs, deliveries
    TO crosspatch_victim_oracle;

-- Scope control can only bind/clear the one active candidate row capability.
GRANT EXECUTE ON FUNCTION crosspatch_bind_candidate_scope(TEXT, TEXT, TEXT, TIMESTAMPTZ)
    TO crosspatch_victim_scope;
GRANT EXECUTE ON FUNCTION crosspatch_clear_candidate_scope(TEXT)
    TO crosspatch_victim_scope;
GRANT EXECUTE ON FUNCTION crosspatch_candidate_scope_allows(TEXT, TEXT)
    TO crosspatch_victim_candidate;

ALTER TABLE webhook_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE outbox_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE deliveries FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS webhook_receipts_app ON webhook_receipts;
DROP POLICY IF EXISTS webhook_receipts_candidate ON webhook_receipts;
DROP POLICY IF EXISTS webhook_receipts_oracle ON webhook_receipts;
CREATE POLICY webhook_receipts_app ON webhook_receipts
    FOR ALL TO crosspatch_victim_app USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY webhook_receipts_candidate ON webhook_receipts
    FOR ALL TO crosspatch_victim_candidate
    USING (crosspatch_candidate_scope_allows(provider, event_id))
    WITH CHECK (crosspatch_candidate_scope_allows(provider, event_id));
CREATE POLICY webhook_receipts_oracle ON webhook_receipts
    FOR ALL TO crosspatch_victim_oracle USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS outbox_jobs_app ON outbox_jobs;
DROP POLICY IF EXISTS outbox_jobs_candidate ON outbox_jobs;
DROP POLICY IF EXISTS outbox_jobs_worker ON outbox_jobs;
DROP POLICY IF EXISTS outbox_jobs_oracle ON outbox_jobs;
CREATE POLICY outbox_jobs_app ON outbox_jobs
    FOR ALL TO crosspatch_victim_app USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY outbox_jobs_candidate ON outbox_jobs
    FOR ALL TO crosspatch_victim_candidate
    USING (crosspatch_candidate_scope_allows(provider, event_id))
    WITH CHECK (crosspatch_candidate_scope_allows(provider, event_id));
CREATE POLICY outbox_jobs_worker ON outbox_jobs
    FOR ALL TO crosspatch_victim_worker USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY outbox_jobs_oracle ON outbox_jobs
    FOR ALL TO crosspatch_victim_oracle USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS deliveries_worker ON deliveries;
DROP POLICY IF EXISTS deliveries_oracle ON deliveries;
CREATE POLICY deliveries_worker ON deliveries
    FOR ALL TO crosspatch_victim_worker USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY deliveries_oracle ON deliveries
    FOR ALL TO crosspatch_victim_oracle USING (TRUE) WITH CHECK (TRUE);
