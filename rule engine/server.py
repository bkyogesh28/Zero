from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor

from sigma_engine import run_sigma


app = FastAPI()


DB_CONFIG = {
    "dbname": "logs",
    "user": "postgres",
    "password": "PostGres",
    "host": "localhost",
    "port": "5432",
}


class TelemetryEvent(BaseModel):
    hostname: str
    pid: int
    process_name: Optional[str] = None
    exe: Optional[str] = None
    file_name: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    cmdline: Optional[str] = None
    username: Optional[str] = None
    sha256: Optional[str] = None
    path_type: Optional[str] = None
    is_lolbin: Optional[bool] = None
    timestamp: str


def get_db_connection():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)


def create_tables():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS telemetry_events (
            id SERIAL PRIMARY KEY,
            hostname TEXT NOT NULL,
            pid INTEGER NOT NULL,
            process_name TEXT,
            exe TEXT,
            file_name TEXT,
            parent_pid INTEGER,
            parent_name TEXT,
            cmdline TEXT,
            username TEXT,
            sha256 TEXT,
            path_type TEXT,
            is_lolbin BOOLEAN,
            timestamp TIMESTAMP
        );
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            telemetry_event_id INTEGER REFERENCES telemetry_events(id) ON DELETE CASCADE,
            rule_id TEXT,
            title TEXT,
            severity TEXT,
            description TEXT,
            tags TEXT,
            hostname TEXT,
            process_name TEXT,
            parent_name TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );
        """
    )

    conn.commit()
    cur.close()
    conn.close()


@app.on_event("startup")
def startup():
    create_tables()


def to_sigma_event(event: TelemetryEvent) -> dict:
    return {
        "Image": (event.process_name or "").lower(),
        "ParentImage": (event.parent_name or "").lower(),
        "CommandLine": event.cmdline or "",
        "CurrentDirectory": event.exe or "",
        "User": event.username or "",
        "HostName": event.hostname or "",
        "SHA256": event.sha256 or "",
        "PathType": event.path_type or "",
        "IsLOLBin": event.is_lolbin,
    }


@app.post("/telemetry")
def receive_telemetry(event: TelemetryEvent):
    conn = None
    cur = None

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 1. Store telemetry
        cur.execute(
            """
            INSERT INTO telemetry_events (
                hostname,
                pid,
                process_name,
                exe,
                file_name,
                parent_pid,
                parent_name,
                cmdline,
                username,
                sha256,
                path_type,
                is_lolbin,
                timestamp
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (
                event.hostname,
                event.pid,
                event.process_name,
                event.exe,
                event.file_name,
                event.parent_pid,
                event.parent_name,
                event.cmdline,
                event.username,
                event.sha256,
                event.path_type,
                event.is_lolbin,
                event.timestamp,
            ),
        )

        inserted_id = cur.fetchone()["id"]

        # 2. Run Sigma on the incoming event in real time
        sigma_event = to_sigma_event(event)
        alerts = run_sigma(sigma_event)

        # 3. Store alerts separately
        for alert in alerts:
            cur.execute(
                """
                INSERT INTO alerts (
                    telemetry_event_id,
                    rule_id,
                    title,
                    severity,
                    description,
                    tags,
                    hostname,
                    process_name,
                    parent_name
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                """,
                (
                    inserted_id,
                    alert.get("rule_id"),
                    alert.get("title"),
                    alert.get("severity"),
                    alert.get("description"),
                    ",".join(alert.get("tags", [])),
                    event.hostname,
                    event.process_name,
                    event.parent_name,
                ),
            )

        conn.commit()

        return {
            "status": "ok",
            "event_id": inserted_id,
            "alerts_generated": len(alerts),
        }

    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.get("/telemetry")
def get_telemetry(limit: int = 50):
    conn = None
    cur = None

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT *
            FROM telemetry_events
            ORDER BY timestamp DESC
            LIMIT %s;
            """,
            (limit,),
        )

        rows = cur.fetchall()

        return {
            "count": len(rows),
            "data": rows,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.get("/alerts")
def get_alerts(limit: int = 50):
    conn = None
    cur = None

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT *
            FROM alerts
            ORDER BY created_at DESC
            LIMIT %s;
            """,
            (limit,),
        )

        rows = cur.fetchall()

        return {
            "count": len(rows),
            "data": rows,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
