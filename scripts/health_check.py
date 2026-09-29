"""Infrastructure health check script for PECFF services.

Validates Redis, PostgreSQL, MinIO, and Celery workers with a deadline.
Exits with code 0 on all healthy, or code 1 on timeout/failure.
"""

from __future__ import annotations

import argparse
import sys
import time
import urllib.request
from typing import Any

from pecff.config import settings


def check_redis() -> tuple[bool, str]:
    try:
        import redis

        client = redis.from_url(settings.redis_url, socket_timeout=2)
        if client.ping():
            return True, "PONG"
        return False, "ping returned false"
    except Exception as exc:
        return False, str(exc)


def check_postgres() -> tuple[bool, str]:
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(settings.sync_database_url, connect_args={"connect_timeout": 3})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "accepting connections"
    except Exception as exc:
        return False, str(exc)


def check_minio() -> tuple[bool, str]:
    endpoint = settings.minio_endpoint.rstrip("/")
    proto = "https" if settings.minio_secure else "http"
    url = f"{proto}://{endpoint}/minio/health/live"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                return True, "200 OK"
            return False, f"HTTP {resp.status}"
    except Exception as exc:
        return False, str(exc)


def check_celery(expected_queues: list[str] | None = None) -> tuple[bool, str]:
    try:
        from pecff.tasks.celery_app import celery_app

        inspect = celery_app.control.inspect(timeout=3.0)
        active_queues = inspect.active_queues()
        if not active_queues:
            return False, "No active workers detected"
        registered_q_names: set[str] = set()
        for worker, q_list in active_queues.items():
            for q in q_list:
                registered_q_names.add(q.get("name", ""))

        if expected_queues:
            missing = [q for q in expected_queues if q not in registered_q_names]
            if missing:
                return False, f"Missing workers for queues: {missing}"

        return True, f"Workers active for {sorted(registered_q_names)}"
    except Exception as exc:
        return False, str(exc)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check health of PECFF infrastructure")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")
    parser.add_argument("--check-celery", action="store_true", help="Check Celery worker status")
    args = parser.parse_args()

    required_queues = ["pecff.ingest", "pecff.score", "pecff.ml", "pecff.report"]
    start_time = time.time()
    deadline = start_time + args.timeout

    print(f"Waiting for dependencies to be healthy (timeout: {args.timeout}s)...")

    while time.time() < deadline:
        redis_ok, redis_msg = check_redis()
        pg_ok, pg_msg = check_postgres()
        minio_ok, minio_msg = check_minio()

        if args.check_celery:
            celery_ok, celery_msg = check_celery(required_queues)
        else:
            celery_ok, celery_msg = True, "skipped"

        if redis_ok and pg_ok and minio_ok and celery_ok:
            print("[SUCCESS] All required dependencies are healthy:")
            print(f"  Redis:      {redis_msg}")
            print(f"  Postgres:   {pg_msg}")
            print(f"  MinIO:      {minio_msg}")
            if args.check_celery:
                print(f"  Celery:     {celery_msg}")
            return 0

        time.sleep(2)

    # Failed within timeout
    print("\n[ERROR] Health check TIMEOUT! Diagnostics:")
    print(f"  Redis:      {'UP' if redis_ok else 'DOWN'} ({redis_msg})")
    print(f"  Postgres:   {'UP' if pg_ok else 'DOWN'} ({pg_msg})")
    print(f"  MinIO:      {'UP' if minio_ok else 'DOWN'} ({minio_msg})")
    if args.check_celery:
        print(f"  Celery:     {'UP' if celery_ok else 'DOWN'} ({celery_msg})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
