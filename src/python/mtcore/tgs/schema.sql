-- TGS schema, version tgs-schema-5 (spec/graph/tgs-contract.md).
-- Times are Unix nanoseconds (bigint). Every row carries seq, the apply
-- transaction that wrote it: the TGS's knowledge time. Full envelopes are
-- kept as the exact bytes read from Kafka.

CREATE TABLE IF NOT EXISTS schema_version (version text PRIMARY KEY);

CREATE TABLE IF NOT EXISTS apply_log (
  seq bigint PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now(),
  records integer NOT NULL
);

CREATE TABLE IF NOT EXISTS applied_offsets (
  topic text NOT NULL,
  kafka_partition integer NOT NULL,
  last_offset bigint NOT NULL,
  seq bigint NOT NULL,
  PRIMARY KEY (topic, kafka_partition)
);

CREATE TABLE IF NOT EXISTS nodes (
  node_id text PRIMARY KEY,
  node_type text NOT NULL,
  uid text NOT NULL,
  namespace text NOT NULL,
  name text NOT NULL,
  identity_status text NOT NULL,
  first_seq bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  event_id text PRIMARY KEY,
  source text NOT NULL,
  event_time bigint,
  ingest_time bigint,
  node_id text NOT NULL,
  boot_id text NOT NULL,
  topic text NOT NULL,
  kafka_partition integer NOT NULL,
  kafka_offset bigint NOT NULL,
  seq bigint NOT NULL,
  envelope bytea NOT NULL
);
CREATE INDEX IF NOT EXISTS events_time ON events (event_time);

CREATE TABLE IF NOT EXISTS findings (
  finding_id text PRIMARY KEY,
  finding_type text NOT NULL,
  event_start bigint,
  topic text NOT NULL,
  kafka_partition integer NOT NULL,
  kafka_offset bigint NOT NULL,
  seq bigint NOT NULL,
  envelope bytea NOT NULL
);

CREATE TABLE IF NOT EXISTS witnesses (
  witness_id text NOT NULL,
  record_sha256 text NOT NULL,
  status text NOT NULL,
  topic text NOT NULL,
  kafka_partition integer NOT NULL,
  kafka_offset bigint NOT NULL,
  seq bigint NOT NULL,
  envelope bytea NOT NULL,
  PRIMARY KEY (witness_id, record_sha256)
);

CREATE TABLE IF NOT EXISTS incident_records (
  incident_id text NOT NULL,
  record_sha256 text NOT NULL,
  version integer NOT NULL,
  status text NOT NULL,
  input_frontier jsonb NOT NULL,
  topic text NOT NULL,
  kafka_partition integer NOT NULL,
  kafka_offset bigint NOT NULL,
  seq bigint NOT NULL,
  envelope bytea NOT NULL,
  PRIMARY KEY (incident_id, record_sha256)
);

CREATE TABLE IF NOT EXISTS node_epochs (
  node_id text NOT NULL,
  boot_id text NOT NULL,
  tau_n bigint NOT NULL,
  trigger_finding_id text NOT NULL,
  kind text NOT NULL,
  seq bigint NOT NULL,
  PRIMARY KEY (node_id, boot_id)
);

CREATE TABLE IF NOT EXISTS completeness (
  record_sha256 text PRIMARY KEY,
  source text NOT NULL,
  scope text NOT NULL,
  interval_start bigint,
  interval_end bigint,
  topic text NOT NULL,
  kafka_partition integer NOT NULL,
  kafka_offset bigint NOT NULL,
  seq bigint NOT NULL,
  envelope bytea NOT NULL
);

CREATE TABLE IF NOT EXISTS edges (
  edge_id text PRIMARY KEY,
  edge_type text NOT NULL,
  src text NOT NULL,
  dst text NOT NULL,
  label text NOT NULL,
  identity_status text NOT NULL,
  trust text NOT NULL,
  count bigint NOT NULL,
  first_t bigint,
  last_t bigint,
  witness_id text,
  finding_id text,
  extractor_version text NOT NULL,
  attributes jsonb NOT NULL,
  created_seq bigint NOT NULL,
  closed_seq bigint
);
CREATE INDEX IF NOT EXISTS edges_src ON edges (src, first_t);
CREATE INDEX IF NOT EXISTS edges_dst ON edges (dst, first_t);

CREATE TABLE IF NOT EXISTS edge_events (
  event_id text NOT NULL,
  edge_id text NOT NULL,
  event_time bigint,
  ingest_time bigint,
  node_id text NOT NULL,
  boot_id text NOT NULL,
  topic text NOT NULL,
  kafka_partition integer NOT NULL,
  kafka_offset bigint NOT NULL,
  seq bigint NOT NULL,
  attributes jsonb NOT NULL,
  PRIMARY KEY (event_id, edge_id)
);
CREATE INDEX IF NOT EXISTS edge_events_edge ON edge_events (edge_id, event_time);
CREATE INDEX IF NOT EXISTS edge_events_node ON edge_events (node_id, boot_id, ingest_time);

-- 6b: snapshots and incident aliases.
CREATE TABLE IF NOT EXISTS snapshots (
  sid text PRIMARY KEY,
  incident_id text NOT NULL,
  version integer NOT NULL,
  record_sha256 text NOT NULL,
  offsets jsonb NOT NULL,
  status text NOT NULL,
  seq bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS snapshots_incident ON snapshots (incident_id, seq);

CREATE TABLE IF NOT EXISTS incident_aliases (
  alias_id text PRIMARY KEY,
  incident_id text NOT NULL,
  seq bigint NOT NULL
);

-- 6c: hypotheses (never links, scores, membership or metrics). Written only
-- by ingest (GO speculative paths) and the hypothesis generator.
CREATE TABLE IF NOT EXISTS hypotheses (
  hyp_id text PRIMARY KEY,
  incident_id text NOT NULL,
  record_sha256 text NOT NULL,
  origin text NOT NULL,
  template_id text NOT NULL,
  template_sha256 text NOT NULL,
  stage_id text NOT NULL,
  detail jsonb NOT NULL,
  seq bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS hypotheses_incident ON hypotheses (incident_id, record_sha256);

CREATE TABLE IF NOT EXISTS hypothesis_edges (
  hyp_id text NOT NULL,
  src text NOT NULL,
  dst text NOT NULL,
  label text NOT NULL,
  origin text NOT NULL,
  seq bigint NOT NULL,
  PRIMARY KEY (hyp_id, src, dst, label)
);

-- The hypothesis generator's role may add hypotheses and read everything,
-- nothing else (created by pg-up.sh; absent in test schemas).
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tgs_hyp') THEN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO tgs_hyp', current_schema());
    EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA %I TO tgs_hyp', current_schema());
    EXECUTE format('GRANT INSERT ON %I.hypotheses, %I.hypothesis_edges TO tgs_hyp',
                   current_schema(), current_schema());
  END IF;
END $$;

-- The investigator role (Exp. 5 interfaces, the GRE) reads, nothing else
-- (created by pg-up.sh; absent in test schemas unless the role exists).
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tgs_reader') THEN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO tgs_reader', current_schema());
    EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA %I TO tgs_reader', current_schema());
  END IF;
END $$;

-- 6d: columns the Exp. 5 interfaces filter on.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS agent_id text NOT NULL DEFAULT '';
ALTER TABLE witnesses ADD COLUMN IF NOT EXISTS source_finding_id text NOT NULL DEFAULT '';
ALTER TABLE witnesses ADD COLUMN IF NOT EXISTS target_finding_id text NOT NULL DEFAULT '';
ALTER TABLE witnesses ADD COLUMN IF NOT EXISTS source_event_time bigint;
CREATE INDEX IF NOT EXISTS findings_time ON findings (event_start, finding_id);
CREATE INDEX IF NOT EXISTS witnesses_findings ON witnesses (source_finding_id, target_finding_id);
CREATE INDEX IF NOT EXISTS completeness_time ON completeness (interval_start);
