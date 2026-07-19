CREATE TABLE IF NOT EXISTS webhook_receipts (
    provider TEXT NOT NULL,
    event_id TEXT NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (provider, event_id)
);

CREATE TABLE IF NOT EXISTS outbox_jobs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provider TEXT NOT NULL,
    event_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    state TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (state IN ('PENDING', 'PROCESSING', 'COMPLETED', 'DEAD')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS deliveries (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id BIGINT NOT NULL REFERENCES outbox_jobs(id),
    provider TEXT NOT NULL,
    event_id TEXT NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS outbox_jobs_pending_idx
    ON outbox_jobs (created_at, id)
    WHERE state = 'PENDING';

CREATE INDEX IF NOT EXISTS deliveries_event_idx
    ON deliveries (provider, event_id);

CREATE TABLE IF NOT EXISTS candidate_scope_bindings (
    candidate_role NAME PRIMARY KEY,
    provider TEXT NOT NULL,
    event_id TEXT NOT NULL,
    runtime_id TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (candidate_role = 'crosspatch_victim_candidate'),
    CHECK (provider ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    CHECK (event_id ~ '^cpv-[0-9a-f]{32}$'),
    CHECK (runtime_id ~ '^cp-[0-9a-f]{32}$')
);

CREATE OR REPLACE FUNCTION crosspatch_candidate_scope_allows(
    row_provider TEXT,
    row_event_id TEXT
) RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
          FROM public.candidate_scope_bindings
         WHERE candidate_role = session_user::name
           AND provider = row_provider
           AND event_id = row_event_id
           AND expires_at > clock_timestamp()
    )
$$;

CREATE OR REPLACE FUNCTION crosspatch_bind_candidate_scope(
    bound_provider TEXT,
    bound_event_id TEXT,
    bound_runtime_id TEXT,
    bound_expires_at TIMESTAMPTZ
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF session_user <> 'crosspatch_victim_scope' THEN
        RAISE EXCEPTION 'candidate scope binding authority is required';
    END IF;
    IF bound_provider !~ '^[a-z0-9][a-z0-9._-]{0,63}$'
        OR bound_event_id !~ '^cpv-[0-9a-f]{32}$'
        OR bound_runtime_id !~ '^cp-[0-9a-f]{32}$'
        OR bound_expires_at <= clock_timestamp()
        OR bound_expires_at > clock_timestamp() + interval '5 minutes' THEN
        RAISE EXCEPTION 'candidate scope binding is invalid';
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.candidate_scope_bindings
         WHERE expires_at > clock_timestamp()
           AND runtime_id <> bound_runtime_id
    ) THEN
        RAISE EXCEPTION 'another candidate scope is active';
    END IF;
    INSERT INTO public.candidate_scope_bindings (
        candidate_role, provider, event_id, runtime_id, expires_at
    ) VALUES (
        'crosspatch_victim_candidate', bound_provider, bound_event_id,
        bound_runtime_id, bound_expires_at
    )
    ON CONFLICT (candidate_role) DO UPDATE
       SET provider = EXCLUDED.provider,
           event_id = EXCLUDED.event_id,
           runtime_id = EXCLUDED.runtime_id,
           expires_at = EXCLUDED.expires_at;
END
$$;

CREATE OR REPLACE FUNCTION crosspatch_clear_candidate_scope(
    bound_runtime_id TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF session_user <> 'crosspatch_victim_scope' THEN
        RAISE EXCEPTION 'candidate scope clearing authority is required';
    END IF;
    DELETE FROM public.candidate_scope_bindings
     WHERE runtime_id = bound_runtime_id;
END
$$;

REVOKE ALL ON candidate_scope_bindings FROM PUBLIC;
REVOKE ALL ON FUNCTION crosspatch_candidate_scope_allows(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION crosspatch_bind_candidate_scope(TEXT, TEXT, TEXT, TIMESTAMPTZ)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION crosspatch_clear_candidate_scope(TEXT) FROM PUBLIC;
