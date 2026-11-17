"""Guarded Response Executor (build step 7; design-spec section 4; paper
Phase 4, Steps 3 and 4).

MicroTRACE performs no automated enforcement. A containment action runs only
on a signed analyst approval R_resp that is bound to a reviewed TGS snapshot,
names one target and one action, expires, and carries a nonce used once.

7.1 (this package so far): the request format and its Ed25519 signature
(request.py), the scripted approver that issues requests from real TGS
snapshots (approver.py), the durable nonce store and attempt records
(store.py), and the fail-closed validation (validate.py). Kubernetes
execution, reconciliation and postconditions follow in 7.2-7.4.
"""
