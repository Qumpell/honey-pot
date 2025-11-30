from app.db import init_db, close_db
from app.db import log_event
from app.db import query_recent_logs
import datetime
import asyncio

async def main():
   try:
        print("Initializing database and logging a test event...")
        await init_db()
        ts = datetime.datetime.now().isoformat()
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
    
if __name__ == "__main__":
    asyncio.run(main())