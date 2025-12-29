from app.db import init_db, close_db
from app.db import log_event
from app.db import query_recent_logs
from app.utils import now_iso
import asyncio
from app.startup import start_ssh_honeypot


async def test_db():
    try:
        print("Initializing database and logging a test event...")
        await init_db()
        ts = now_iso()
        await log_event(ts, src_ip="127.0.0.1", src_port=55555, dst_port=2222,
                        protocol="ssh", event_type="auth_attempt",
                        raw="root:password123", parsed='{"user":"root"}',
                        classification="brute_force", confidence=0.9,
                        details='{"failed_attempts": 12}', headers="{}")

        rows = await query_recent_logs(20)
        print("\nRecent logs:")
        for r in rows:
            print(r["id"], r["timestamp"], r["protocol"], r["event_type"], r["classification"])

    except Exception as e:
        print("An error occurred:", e)

    finally:
        print("\nDone. Closing DB...")
        await close_db()


async def main():
    await init_db()

    ssh_server = await start_ssh_honeypot(port=2222)

    print("Honeypot running. Press Ctrl+C to stop.")
    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        ssh_server.close()
        await ssh_server.wait_closed()
        await close_db()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted by user")
