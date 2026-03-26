import sqlite3
from config import DEFAULT_SETTINGS

DB_FILE = "users.db"

def db_connect():
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)")
    cur.execute("INSERT OR IGNORE INTO users VALUES (?, ?)", ("admin", "password"))

    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            ip TEXT,
            port TEXT,
            type TEXT,
            severity TEXT,
            status TEXT,
            details TEXT
        )
    """)

    for key, value in DEFAULT_SETTINGS.items():
        cur.execute(
            "INSERT OR IGNORE INTO app_settings(key, value) VALUES (?, ?)",
            (key, str(value))
        )

    conn.commit()
    conn.close()

def authenticate_user(username: str, password: str) -> bool:
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username=? AND password=?", (username, password))
    result = cur.fetchone()
    conn.close()
    return result is not None

def load_settings():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT key, value FROM app_settings")
    rows = cur.fetchall()
    conn.close()
    return {k: v for k, v in rows}

def save_setting(key: str, value: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO app_settings(key, value)
        VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
    """, (key, str(value)))
    conn.commit()
    conn.close()

def insert_alert(alert: dict):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO alerts_log(time, ip, port, type, severity, status, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["time"], alert["ip"], alert["port"],
        alert["type"], alert["severity"], alert["status"], alert["details"]
    ))
    conn.commit()
    conn.close()

def load_alerts():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT time, ip, port, type, severity, status, details FROM alerts_log ORDER BY id ASC")
    rows = cur.fetchall()
    conn.close()

    alerts = []
    for row in rows:
        alerts.append({
            "time": row[0],
            "ip": row[1],
            "port": row[2],
            "type": row[3],
            "severity": row[4],
            "status": row[5],
            "details": row[6],
        })
    return alerts
