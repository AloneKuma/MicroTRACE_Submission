# MicroTRACE

MicroTRACE traces attacks in Kubernetes microservices. It joins three kinds of
evidence: Kubernetes API audit events, cluster context, and node-level eBPF
events. From them it builds time-ordered findings and links, and maps each one
to an ATT&CK tactic. This repository holds the source code for the final
report.

## Repository layout

| Folder | Contents |
|---|---|
| `src/go/` | Node side (Go): `shipper` and `receiver` (TLS link into Kafka), `faultinject`, `devcerts`, `trace-check` |
| `src/python/mtcore/` | Analysis side (Python): agents A-H (rules + Isolation Forest), Global Orchestrator, Time-Aware Graph Store, Guarded Response Executor, scoring harness, baseline adapters |
| `src/python/mtgen/` | Synthetic dataset generator (builds every dataset used in the report) |
| `src/python/tests/` | Python tests |
| `src/params/` | Parameter sets; `frozen/` holds the frozen parameters and models used for the results |
| `src/scripts/` | Dev-host setup, code generation, Kafka/Postgres start and stop, pilot tools |
| `src/k8s/` | Kubernetes manifests for the response executor (kind cluster) |
| `spec/` | Message schemas (`proto/`), Kafka topics, audit policy, rulebook, fault contract, scenario catalogue |
| `proofs/` | Reference correlator and its property tests |
| `experiments/` | Run scripts and configs for Exp. 1-5, cluster probes and the AWS (Terraform) testbed |

`src/README.md` documents every component and its command-line options in detail.

## Requirements

- Linux (tested on Ubuntu 24.04, kernel 6.8), with `bash`, `gcc`, `make`, `curl`
- Python 3.12+ and Go 1.27 (the setup script installs both)
- Docker and [kind](https://kind.sigs.k8s.io/) only for the cluster experiments
  and the response executor
- An AWS account only to repeat the full-scale experiment runs (optional)

## Install

The setup script installs everything under one folder (default
`~/microtrace-dev`): Python and a virtualenv with `src/python/requirements.txt`,
Go, JDK 21, Kafka and Postgres. It changes nothing system-wide and checks every
download against its published checksum.

```sh
git clone <this repository> MicroTRACE && cd MicroTRACE
bash src/scripts/setup-dev-host.sh
source ~/microtrace-dev/env.sh
bash src/scripts/gen-proto.sh          # generates Python and Go code from spec/proto
```

Build the executables (they are built from source, not shipped as binaries):

```sh
(cd src/go && for c in receiver shipper devcerts trace-check faultinject; do
   go build -o "$MT_DEV/bin/$c" ./cmd/$c; done)
```

## Run

Start the local services, create the Kafka topics, and run the pipeline:

```sh
bash src/scripts/kafka-up.sh           # single-node Kafka on 127.0.0.1
bash src/scripts/pg-up.sh              # graph store Postgres on 127.0.0.1:55432
source ~/microtrace-dev/pg.env
(cd src/python && python -m mtcore.kafka_topics)

# Agents A-H and the Global Orchestrator
(cd src/python && python -m mtcore.restream &)
(cd src/python && python -m mtcore.agents.run --agent A,B,C,D,E,F,G,H &)
(cd src/python && python -m mtcore.orchestrator.run &)
```

To run the detectors without Kafka, replay a record file offline:

```sh
(cd src/python && python -m mtcore.agents.run --offline records.jsonl > findings.jsonl)
```

Stop the services with `bash src/scripts/kafka-down.sh` and
`bash src/scripts/pg-down.sh`.

## Dataset

No dataset files are included. All data are synthetic and come from the
generator `mtgen`, which is deterministic for a given seed. To build one run:

```sh
cd src/python
python -m mtgen build --world Small --split PILOT --seed 42 --out ../../data/pilot-run
```

`--split` takes `PILOT`, `RESEARCH` or `HELD_OUT`; `--scenarios` selects attack
scenarios from `spec/` (default: all). The run lists behind the reported
results are in `experiments/heldout/splits/` and `experiments/heldout/configs/`.
`python -m mtgen --help` lists the other subcommands (`assemble`, `seal`,
`package`, `verify-seal`).

## Test

```sh
source ~/microtrace-dev/env.sh
bash src/scripts/check-all.sh          # vet, Go race tests, build, Python tests, clean-up check
```

Or run the parts on their own:

```sh
(cd src/go && go test -race ./...)
(cd src/python && python -m pytest -q tests)
python proofs/test_props.py --cases 2000 --seed 1
```

The Kafka and Postgres tests skip when those services are not running.

## Experiments

| Experiment | Scripts |
|---|---|
| Exp. 1-2: detection and attack-path accuracy against KAIROS, ORTHRUS, SAGE | `experiments/heldout/`, `experiments/baselines/` |
| Exp. 3: telemetry faults | `experiments/exp3/` (fault plans in `plans/`) |
| Exp. 4: scaling and timing | `experiments/exp4/` |
| Exp. 5: crash recovery and guarded response | `experiments/exp5/`, `src/k8s/gre/` |
| AWS testbed (Terraform) | `experiments/aws/` |

The full runs used one AWS m7i.8xlarge machine. Bucket names and the account ID
are written as placeholders (`<WORK_BUCKET>`, `<SEALED_BUCKET>`,
`<AWS_ACCOUNT_ID>`); set your own values before running them.
