-- GRE schema, version gre-schema-3 (build step 7; evaluation-plan.md section 5).
-- Lives in its own schema (gre, owned by role gre_exec; see pg-up.sh). Times
-- are Unix nanoseconds (bigint). The GRE reads the TGS only through the
-- tgs_reader role, on a separate connection.

CREATE TABLE IF NOT EXISTS gre_schema_version (version text PRIMARY KEY);

-- One row per consumed nonce. The primary key makes consumption atomic
-- across GRE instances: exactly one INSERT wins. A row is kept until the
-- request's exp plus the maximum clock skew, so no GRE whose clock lags by
-- up to that skew can accept a replay after the row is purged.
CREATE TABLE IF NOT EXISTS gre_nonces (
  nonce text PRIMARY KEY,
  rid text NOT NULL,
  keep_until bigint NOT NULL,
  consumed_at bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS gre_nonces_keep ON gre_nonces (keep_until);

-- A_resp (paper eq. response-audit): one row per attempt, rejected ones
-- included, never updated in place; a later state is a new row.
CREATE TABLE IF NOT EXISTS gre_attempts (
  attempt_id bigserial PRIMARY KEY,
  rid text NOT NULL,
  gid text NOT NULL,
  act text NOT NULL,
  uid text NOT NULL,
  ts bigint NOT NULL,
  status text NOT NULL CHECK (status IN ('Rejected', 'Submitted', 'Verified', 'Failed', 'Unresolved')),
  reason text NOT NULL,
  ref_audit text NOT NULL DEFAULT '',
  ref_verify text NOT NULL DEFAULT '',
  request jsonb
);
CREATE INDEX IF NOT EXISTS gre_attempts_rid ON gre_attempts (rid, attempt_id);

-- 7.3: what was accepted, kept with the nonce, so a request whose GRE died
-- before writing anything can still be closed by reconciliation.
ALTER TABLE gre_nonces ADD COLUMN IF NOT EXISTS request jsonb;
-- The executor's own outcome row for this accepted request (a replay's
-- rejection under the same rid does not close it).
ALTER TABLE gre_nonces ADD COLUMN IF NOT EXISTS closed_attempt_id bigint;

-- 7.3: the intent journal. One row is stored durably before a write is
-- sent; its user_agent tags that write in the API server's audit log.
-- resolved_attempt_id points at the A_resp row that closed it (Submitted,
-- Failed or Rejected); an Unresolved one is closed again by reconciliation.
CREATE TABLE IF NOT EXISTS gre_intents (
  intent_id bigserial PRIMARY KEY,
  rid text NOT NULL,
  nonce text NOT NULL,
  act text NOT NULL,
  service_account text NOT NULL,
  path text NOT NULL,
  user_agent text NOT NULL,
  planned_at bigint NOT NULL,
  request jsonb NOT NULL,
  resolved_attempt_id bigint
);
CREATE INDEX IF NOT EXISTS gre_intents_open ON gre_intents (resolved_attempt_id, intent_id);

-- 7.4: postcondition verification. What the check needs that the write may
-- remove (a revoked binding's subjects, a workload's selector), planned
-- before the write; and the A_resp row of the latest verification of the
-- write this intent submitted (Verified or Failed closes it; Unresolved is
-- checked again by reconciliation).
ALTER TABLE gre_intents ADD COLUMN IF NOT EXISTS postcondition jsonb;
ALTER TABLE gre_intents ADD COLUMN IF NOT EXISTS verified_attempt_id bigint;
