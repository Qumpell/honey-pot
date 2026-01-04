## SSH & TELNET HONEYPOT

This project is a honeypot system designed to simulate SSH and Telnet servers to detect and log unauthorized access attempts, such as password guessing, public key authentication attempts, and command executions. It captures attacker activities, stores them in a SQLite database, and provides daily summaries for analysis. The honeypot grants access after a random number of failed attempts to lure attackers into executing commands in a fake shell environment.

## Technologies Used

- **Python 3.12**: Core language for the application.
- **AsyncIO**: For asynchronous operations and handling concurrent connections.
- **AsyncSSH**: Library for implementing the SSH honeypot server.
- **AIO SQLite**: For database operations.
- **Cryptography**: For secure key generation and handling.
- **Docker**: For containerized deployment.
- **SQLite**: Database for storing logs and daily summaries.

## Setup Instructions

### Prerequisites

- Docker and Docker Compose installed on your system.
- Python 3.12 if running locally (though Docker is recommended).

### Using Docker (Recommended)

1. Clone or download the project files to your local machine.
2. Navigate to the project root directory.
3. Run the following command to build and start the honeypot:

   ```bash
   docker-compose up --build
   ```

   This will start the honeypot services with SSH on port 2222 and Telnet on port 2223, mapped to host ports 22 and 23 respectively.

4. The application will automatically initialize the database and start logging.

### Local Setup (Alternative)

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Ensure the data and logs directories exist (they will be created automatically if needed).
3. Run the main script:

   ```bash
   python main.py
   ```

4. The honeypot will start SSH on port 2222 and Telnet on port 2223.

### Environment Variables

You can configure the honeypot using environment variables defined in .env or via Docker Compose:

- `HP_SSH_HOST_KEY`: Path to SSH host key (default: ssh_host_key).
- `HP_MAX_CONNS`: Maximum concurrent connections (default: 50).
- `HP_MAX_CMDS`: Maximum commands per session (default: 50).
- `HP_MAX_CMD_LEN`: Maximum command length (default: 256).
- `HP_SESSION_TIMEOUT`: Session idle timeout in seconds (default: 300).
- `HP_BRUTE_MIN/MAX`: Minimum/maximum attempts before granting access (default: 3/7).
- `HP_DB_PATH`: Database file path (default: honeypot.db).

## Database Location

The SQLite database is stored at honeypot.db (relative to the project root or container's `/app/data`). It contains two main tables:

- logs: Stores individual events (e.g., auth attempts, commands).
- `daily_summary`: Aggregates events by day, including totals and classifications.

Use tools like SQLite Browser or command-line `sqlite3` to inspect the database.

## Reading Logs

Logs are stored in two formats:

1. **File-based Logs**: Written to the logs directory. These are text files with timestamps and messages from the application.

2. **Database Logs**: Query the logs table in honeypot.db for structured data. Example query to fetch recent logs:

   ```sql
   SELECT * FROM logs ORDER BY id DESC LIMIT 20;
   ```

   Use the `query_recent_logs` function in db.py for programmatic access.

Daily summaries can be queried from the `daily_summary` table.

## Testing and Verification of Attacks

To test the honeypot and verify attack detection:

1. **Run the Honeypot**: Start the services as described in setup.

2. **Simulate Attacks**:
   - SSH: Use `ssh user@host -p 2222` and attempt logins with fake credentials.
   - Telnet: Use `telnet host 23` and attempt logins.

3. **Verify Logs**: 
   Check the database for logged events directly from your terminal. Run this command to see the 10 most recent interactions:

   ```bash
   docker exec -it honeypot_app sqlite3 /app/data/honeypot.db "SELECT timestamp, protocol, event_type, src_ip, raw FROM logs ORDER BY id DESC LIMIT 10
    ```
   This allows you to see real-time data without leaving the host shell.

4. **Check Daily Summaries**: After attacks, inspect the `daily_summary` table for aggregated data.

5. **Monitor Output**: Watch the console or Docker logs for real-time activity.

The honeypot grants access after 3-7 failed attempts (configurable), allowing command execution in a fake shell. All activities are logged for analysis.