# © 2026 aiaiaiai · aiaiaiai.org
# SPDX-License-Identifier: Apache-2.0
FROM python:3.13-alpine
WORKDIR /app
COPY server.py /app/server.py
COPY static /app/static
USER 65532:65532
EXPOSE 1927
CMD ["python", "-B", "/app/server.py"]
