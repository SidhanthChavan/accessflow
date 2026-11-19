FROM python:3.12-slim

RUN useradd --create-home accessflow
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .
COPY config ./config
COPY data ./data
COPY scripts ./scripts
RUN chown -R accessflow /app
USER accessflow

ENTRYPOINT ["accessflow"]
CMD ["plan", "--hr", "data/hr_feed.csv", "--policy", "config/policy.yaml", "--today", "2026-11-19"]
