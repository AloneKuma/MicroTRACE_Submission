"""Create the Kafka topics named in spec/kafka/topics.yaml.

    python -m mtcore.kafka_topics --bootstrap 127.0.0.1:9092

Partition count, replication, retention and timestamp type come from
src/kafka/dev-topics.yaml (or --config). Missing topics are created. On
existing topics, retention and timestamp type are brought in line with the
config; a partition count that differs is an error, because the contract
freezes partition counts per topic generation.
"""
import argparse
import os
import sys

import yaml
from confluent_kafka.admin import (AdminClient, AlterConfigOpType, ConfigEntry, ConfigResource,
                                   NewTopic, ResourceType)

from mtcore import REPO

SPEC_TOPICS = os.path.join(REPO, "spec", "kafka", "topics.yaml")
DEV_CONFIG = os.path.join(REPO, "src", "kafka", "dev-topics.yaml")


def planned_topics(config_path):
    spec = yaml.safe_load(open(SPEC_TOPICS, encoding="utf-8"))
    cfg = yaml.safe_load(open(config_path, encoding="utf-8"))
    base = cfg["defaults"]
    overrides = cfg.get("overrides") or {}
    unknown = set(overrides) - {t["name"] for t in spec["topics"]}
    if unknown:
        raise ValueError(f"overrides for topics not in topics.yaml: {sorted(unknown)}")
    return {t["name"]: {**base, **overrides.get(t["name"], {})} for t in spec["topics"]}


def topic_configs(s):
    """Kafka topic configs managed by this tool."""
    return {"retention.ms": str(s["retention_ms"]),
            "message.timestamp.type": s.get("timestamp_type", "CreateTime")}


def ensure_topics(bootstrap, config_path=DEV_CONFIG, timeout=30):
    """Returns (plan, created, altered, problems)."""
    admin = AdminClient({"bootstrap.servers": bootstrap})
    plan = planned_topics(config_path)
    existing = admin.list_topics(timeout=timeout).topics
    problems, created, altered = [], [], []
    for name, s in plan.items():
        if name in existing and len(existing[name].partitions) != s["partitions"]:
            problems.append(f"{name}: has {len(existing[name].partitions)} partitions, config says {s['partitions']}")
    new = [NewTopic(name, num_partitions=s["partitions"], replication_factor=s["replication_factor"],
                    config=topic_configs(s))
           for name, s in plan.items() if name not in existing]
    if new:
        for name, fut in admin.create_topics(new, request_timeout=timeout).items():
            fut.result()
            created.append(name)
    present = [n for n in plan if n in existing]
    if present:
        res = [ConfigResource(ResourceType.TOPIC, n) for n in present]
        current = {r.name: f.result() for r, f in admin.describe_configs(res, request_timeout=timeout).items()}
        changes = []
        for n in present:
            want = topic_configs(plan[n])
            diff = [ConfigEntry(k, v, incremental_operation=AlterConfigOpType.SET)
                    for k, v in want.items() if current[n][k].value != v]
            if diff:
                changes.append(ConfigResource(ResourceType.TOPIC, n, incremental_configs=diff))
        if changes:
            for r, fut in admin.incremental_alter_configs(changes, request_timeout=timeout).items():
                fut.result()
                altered.append(r.name)
    return plan, created, altered, problems


def check_configs(bootstrap, config_path=DEV_CONFIG, timeout=30):
    """Topics whose managed configs differ from the config file."""
    admin = AdminClient({"bootstrap.servers": bootstrap})
    plan = planned_topics(config_path)
    res = [ConfigResource(ResourceType.TOPIC, n) for n in plan]
    current = {r.name: f.result() for r, f in admin.describe_configs(res, request_timeout=timeout).items()}
    return [f"{n}: {k}={current[n][k].value}, want {v}"
            for n in plan for k, v in topic_configs(plan[n]).items() if current[n][k].value != v]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bootstrap", default="127.0.0.1:9092")
    ap.add_argument("--config", default=DEV_CONFIG)
    args = ap.parse_args(argv)
    plan, created, altered, problems = ensure_topics(args.bootstrap, args.config)
    print(f"{len(plan)} topics planned, {len(created)} created, {len(altered)} reconfigured, "
          f"{len(plan) - len(created)} already present")
    for p in problems:
        print("ERROR", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
