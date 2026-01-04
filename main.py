import sys

from app.db import init_db, close_db, set_stats_manager
from app.db import log_event
from app.db import query_recent_logs
from app.ssh.ssh_server import HoneySSHServer
from app.stats import StatsManager
from app.utils import now_iso, log, SupportedProtocols, EventType, Classification
import asyncio
from app.startup import start_ssh_honeypot, start_telnet_honeypot
import signal
from prometheus_client import start_http_server

shutdown_event = asyncio.Event()


async def test_db():
    try:
        print("Initializing database and logging a test event...")
        await init_db()
        ts = now_iso()
        await log_event(ts, src_ip="127.0.0.1", src_port=55555, dst_port=2222,
                        protocol=SupportedProtocols.SSH, event_type=EventType.AUTH_ATTEMPT,
                        raw="root:password123", parsed='{"user":"root"}',
                        classification=Classification.PASSWORD_GUESS, confidence=0.9,
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
    try:
        start_http_server(8000)
        log.info("[MONITORING] Prometheus metrics server started on port 8000")
    except Exception as e:
        log.error(f"[MONITORING] Failed to start metrics server: {e}")

    await init_db()
    stats = StatsManager()
    await stats.load_today_stats()
    set_stats_manager(stats)
    asyncio.create_task(stats.run_background_saver(interval=30))

    ssh_server = await start_ssh_honeypot(port=2222)
    telnet_server = await start_telnet_honeypot(port=2223)
    log.info("Honeypot running. SSH on 2222, Telnet on 2223. Ctrl+C to stop.")

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
            loop.add_signal_handler(sig, lambda: stop_event.set())
        except NotImplementedError:
            pass

    try:
        await stop_event.wait()
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        log.info("\n[SHUTDOWN] Stopping servers...")
        try:
            await asyncio.wait_for(telnet_server.stop(), timeout=3.0)
        except Exception as e:
            log.error(f"Telnet stop error: {e}")

        try:
            await HoneySSHServer.close_all_sessions()
            ssh_server.close()
            await asyncio.wait_for(ssh_server.wait_closed(), timeout=3.0)
        except Exception as e:
            log.error(f"SSH stop error: {e}")

        log.info("[SHUTDOWN] Flushing final stats to database...")
        try:
            await stats.flush()
        except Exception as e:
            log.error(f"Final stats flush error: {e}")

        await close_db()
        print("[SHUTDOWN] Cleanup complete. Exit.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)

