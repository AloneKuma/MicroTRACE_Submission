"""SAGE (Nadeem et al., IEEE TDSC 2022) as the alert-level baseline of Exp. 2 and 3.

SAGE receives the agents' findings as alerts (alerts.py, through the frozen
mapping in spec/baselines/sage-mapping.v2.yaml), runs unchanged except for the
patch in src/baselines/sage/patches (alert IDs carried to its outputs), and its
attack-graph paths become CONFIRMED witnesses and incidents (project.py) that
mtcore.harness.score scores exactly as it scores the GO. run.py drives it.
"""
