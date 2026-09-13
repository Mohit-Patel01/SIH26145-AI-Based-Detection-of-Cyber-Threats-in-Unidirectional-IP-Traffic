import sqlite3
import os


# Find the main project folder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Database will be stored inside Database/
DB_PATH = os.path.join(BASE_DIR, "Database", "cyber_threats.db")


def create_database():

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,

            source_port INTEGER,
            destination_port INTEGER,
            protocol INTEGER,

            packet_count INTEGER,
            total_bytes REAL,
            duration REAL,

            prediction TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_detection(
    timestamp,
    source_port,
    destination_port,
    protocol,
    packet_count,
    total_bytes,
    duration,
    prediction
):

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO detections (
            timestamp,
            source_port,
            destination_port,
            protocol,
            packet_count,
            total_bytes,
            duration,
            prediction
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        source_port,
        destination_port,
        protocol,
        packet_count,
        total_bytes,
        duration,
        prediction
    ))

    conn.commit()
    conn.close()


# Create the database and table first
create_database()
