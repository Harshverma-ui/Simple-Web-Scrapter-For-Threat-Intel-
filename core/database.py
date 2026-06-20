import sqlite3
import os


class Database:

    def __init__(self, db_path="data/threats.db"):

        os.makedirs("data", exist_ok=True)

        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)

        self.create_tables()

    def create_tables(self):

        cursor = self.conn.cursor()

        # Threats Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve TEXT UNIQUE,
            severity TEXT,
            cvss REAL,
            description TEXT
        )
        """)

        # IOC Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id INTEGER,
            type TEXT,
            value TEXT,
            FOREIGN KEY(threat_id)
            REFERENCES threats(id)
        )
        """)

        self.conn.commit()

    # -------------------------
    # Insert Threat
    # -------------------------

    def insert_threat(
        self,
        cve,
        severity,
        cvss,
        description
    ):

        cursor = self.conn.cursor()

        cursor.execute("""
        INSERT OR IGNORE INTO threats(
            cve,
            severity,
            cvss,
            description
        )
        VALUES (?, ?, ?, ?)
        """, (
            cve,
            severity,
            cvss,
            description
        ))

        self.conn.commit()

        cursor.execute(
            "SELECT id FROM threats WHERE cve=?",
            (cve,)
        )

        row = cursor.fetchone()

        if row:
            return row[0]

        return None

    # -------------------------
    # Insert IOC
    # -------------------------

    def insert_ioc(
        self,
        threat_id,
        ioc_type,
        value
    ):

        cursor = self.conn.cursor()

        cursor.execute("""
        INSERT INTO iocs(
            threat_id,
            type,
            value
        )
        VALUES (?, ?, ?)
        """, (
            threat_id,
            ioc_type,
            value
        ))

        self.conn.commit()

    # -------------------------
    # Get All Threats
    # -------------------------

    def get_all_threats(self):

        cursor = self.conn.cursor()

        cursor.execute("""
        SELECT
            id,
            cve,
            severity,
            cvss,
            description
        FROM threats
        ORDER BY id DESC
        """)

        return cursor.fetchall()

    # -------------------------
    # Get All IOCs
    # -------------------------

    def get_all_iocs(self):

        cursor = self.conn.cursor()

        cursor.execute("""
        SELECT
            type,
            value
        FROM iocs
        ORDER BY id DESC
        """)

        return cursor.fetchall()

    # -------------------------
    # Search CVE
    # -------------------------

    def search_cve(self, keyword):

        cursor = self.conn.cursor()

        cursor.execute("""
        SELECT
            id,
            cve,
            severity,
            cvss,
            description
        FROM threats
        WHERE cve LIKE ?
        """, (
            f"%{keyword}%",
        ))

        return cursor.fetchall()

    # -------------------------
    # Filter Severity
    # -------------------------

    def filter_severity(self, severity):

        cursor = self.conn.cursor()

        cursor.execute("""
        SELECT
            id,
            cve,
            severity,
            cvss,
            description
        FROM threats
        WHERE severity=?
        """, (
            severity,
        ))

        return cursor.fetchall()

    # -------------------------
    # Statistics
    # -------------------------

    def get_statistics(self):

        cursor = self.conn.cursor()

        stats = {}

        cursor.execute(
            "SELECT COUNT(*) FROM threats"
        )
        stats["total"] = cursor.fetchone()[0]

        cursor.execute("""
        SELECT COUNT(*)
        FROM threats
        WHERE severity='Critical'
        """)
        stats["critical"] = cursor.fetchone()[0]

        cursor.execute("""
        SELECT COUNT(*)
        FROM threats
        WHERE severity='High'
        """)
        stats["high"] = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM iocs"
        )
        stats["iocs"] = cursor.fetchone()[0]

        return stats

    # -------------------------
    # Clear Database
    # -------------------------

    def clear_database(self):

        cursor = self.conn.cursor()

        cursor.execute("DELETE FROM threats")
        cursor.execute("DELETE FROM iocs")

        self.conn.commit()

    # -------------------------
    # Close Connection
    # -------------------------

    def close(self):

        self.conn.close()