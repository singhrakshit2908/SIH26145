import sqlite3
from pathlib import Path


DB_PATH = Path("data/cyberdhristi.db")


def get_connection():
    """Create a SQLite connection with safe concurrent-access settings."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,
    )

    # Wait for another SQLite operation instead of immediately failing.
    conn.execute("PRAGMA busy_timeout = 30000")

    return conn


def clear_analysis_data():
    """Clear alerts and correlated incidents before a new analysis run."""

    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("DELETE FROM alerts")
        cursor.execute("DELETE FROM correlated_alerts")

        conn.commit()

    finally:
        conn.close()


def initialize_database():
    """Create the CYBERDHRISTI database tables."""

    conn = get_connection()

    try:
        cursor = conn.cursor()

        # WAL allows readers and writers to work concurrently.

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                duration REAL,
                packet_count INTEGER,
                byte_count INTEGER
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                threat_type TEXT,
                confidence REAL,
                severity TEXT,
                evidence TEXT,
                detection_source TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS correlated_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                threat_type TEXT,
                correlation_score REAL,
                severity TEXT,
                time_window INTEGER,
                evidence TEXT
            )
        """)

        conn.commit()

    finally:
        conn.close()


def insert_alert(alert):
    """Store a standardized alert in SQLite."""

    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO alerts (
                timestamp,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
                threat_type,
                confidence,
                severity,
                evidence,
                detection_source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get("timestamp"),
            alert.get("source_ip"),
            alert.get("destination_ip"),
            alert.get("source_port"),
            alert.get("destination_port"),
            alert.get("protocol"),
            alert.get("threat_type"),
            alert.get("confidence"),
            alert.get("severity"),
            str(alert.get("evidence", {})),
            alert.get("detection_source"),
        ))

        conn.commit()

    finally:
        conn.close()