# Runtime for the audit-to-incident slice components (dependencies only; the
# code is mounted read-only at run time and hashed in the run facts).
FROM docker.io/library/python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
RUN pip install --no-cache-dir confluent-kafka==2.15.1 grpcio-tools==1.84.0 PyYAML==6.0.3 \
 && pip freeze > /pip-freeze.txt
