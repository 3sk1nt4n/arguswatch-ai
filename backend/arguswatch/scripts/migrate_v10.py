"""
Migration runner - executes V10 and V11 migration SQL against the live database.
Called at backend startup before uvicorn. Safe to run multiple times.
"""
import os, sys, time, logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("migrate")

MIGRATIONS = ["02_migrate_v10.sql", "03_migrate_v11.sql"]


def get_dsn() -> str:
    user = os.environ.get("POSTGRES_USER", "arguswatch")
    pw   = os.environ.get("POSTGRES_PASSWORD", "arguswatch_dev_2026")
    host = os.environ.get("POSTGRES_HOST", "postgres")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db   = os.environ.get("POSTGRES_DB", "arguswatch")
    return f"postgresql://{user}:{pw}@{host}:{port}/{db}"


def run():
    try:
        import psycopg2
    except ImportError:
        log.warning("psycopg2 not available - skipping migrations (dev mode)")
        return

    base = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../../../initdb")
    )

    dsn = get_dsn()
    for attempt in range(20):
        try:
            conn = psycopg2.connect(dsn)
            break
        except Exception as e:
            log.info(f"Waiting for postgres ({attempt+1}/20)… {e}")
            time.sleep(2)
    else:
        log.error("Postgres not ready after 40s - aborting")
        sys.exit(1)

    conn.autocommit = True
    cur = conn.cursor()

    for fname in MIGRATIONS:
        path = os.path.join(base, fname)
        if not os.path.exists(path):
            log.warning(f"Migration file not found: {path} - skipping")
            continue
        sql = open(path).read()
        try:
            cur.execute(sql)
            log.info(f"✓ {fname} applied")
        except Exception as e:
            log.warning(f"{fname} warning (may already be applied): {e}")

    conn.close()
    log.info("All migrations complete")


if __name__ == "__main__":
    run()
