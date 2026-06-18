"""
Self-Learning Attack Memory
"""

import json
import hashlib
import sqlite3
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict


@dataclass
class AttackRecord:
    """سجل هجوم كامل مع جميع التفاصيل"""
    id: str
    prompt: str
    tool_used: str
    target: str
    was_blocked: bool
    risk_score: float
    decision: str
    response: str
    timestamp: str
    context: Dict[str, Any] = field(default_factory=dict)
    success: bool = False
    adaptation_count: int = 0
    variants: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "prompt": self.prompt,
            "tool_used": self.tool_used,
            "target": self.target,
            "was_blocked": self.was_blocked,
            "risk_score": self.risk_score,
            "decision": self.decision,
            "response": self.response,
            "timestamp": self.timestamp,
            "context": self.context,
            "success": self.success,
            "adaptation_count": self.adaptation_count,
            "variants": self.variants,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "AttackRecord":
        return cls(
            id=data["id"],
            prompt=data["prompt"],
            tool_used=data.get("tool_used", ""),
            target=data.get("target", ""),
            was_blocked=data.get("was_blocked", False),
            risk_score=data.get("risk_score", 0.0),
            decision=data.get("decision", ""),
            response=data.get("response", ""),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            context=data.get("context", {}),
            success=data.get("success", False),
            adaptation_count=data.get("adaptation_count", 0),
            variants=data.get("variants", []),
        )


class AttackMemory:
    """
    ذاكرة هجمات ذاتية التعلم
    """

    def __init__(self, db_path: str = ":memory:"):
        self._original_db_path = db_path
        self._keepalive_conn = None
        self._uri = False
        if db_path == ":memory:":
            import uuid as _uuid
            mem_name = f"hestia_mem_{_uuid.uuid4().hex[:12]}"
            self.db_path = f"file:{mem_name}?mode=memory&cache=shared"
            self._uri = True
            self._keepalive_conn = sqlite3.connect(self.db_path, uri=True)
        else:
            self.db_path = db_path
            self._uri = False
        self._init_db()
        self.cache = {}
        self.pattern_cache = {}

    def _connect(self):
        if self._uri:
            return sqlite3.connect(self.db_path, uri=True)
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """تهيئة قاعدة البيانات"""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id TEXT PRIMARY KEY,
                prompt TEXT NOT NULL,
                tool_used TEXT,
                target TEXT,
                was_blocked INTEGER,
                risk_score REAL,
                decision TEXT,
                response TEXT,
                timestamp TEXT,
                context_json TEXT,
                success INTEGER,
                adaptation_count INTEGER,
                variants_json TEXT
            )
        """)

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON attacks(timestamp)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_tool ON attacks(tool_used)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_success ON attacks(success)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_blocked ON attacks(was_blocked)"
        )

        conn.commit()
        conn.close()

    def store(self, record: AttackRecord) -> str:
        """تخزين سجل هجوم جديد"""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO attacks
            (id, prompt, tool_used, target, was_blocked, risk_score,
             decision, response, timestamp, context_json, success,
             adaptation_count, variants_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.id,
                record.prompt,
                record.tool_used,
                record.target,
                1 if record.was_blocked else 0,
                record.risk_score,
                record.decision,
                record.response,
                record.timestamp,
                json.dumps(record.context),
                1 if record.success else 0,
                record.adaptation_count,
                json.dumps(record.variants),
            ),
        )

        conn.commit()
        conn.close()

        self.cache[record.id] = record
        return record.id

    def get(self, attack_id: str) -> Optional[AttackRecord]:
        """الحصول على سجل هجوم"""
        if attack_id in self.cache:
            return self.cache[attack_id]

        conn = self._connect()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM attacks WHERE id = ?", (attack_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            record = AttackRecord(
                id=row["id"],
                prompt=row["prompt"],
                tool_used=row["tool_used"],
                target=row["target"],
                was_blocked=bool(row["was_blocked"]),
                risk_score=row["risk_score"],
                decision=row["decision"],
                response=row["response"],
                timestamp=row["timestamp"],
                context=json.loads(row["context_json"])
                if row["context_json"]
                else {},
                success=bool(row["success"]),
                adaptation_count=row["adaptation_count"],
                variants=json.loads(row["variants_json"])
                if row["variants_json"]
                else [],
            )
            self.cache[record.id] = record
            return record

        return None

    def get_similar(
        self, prompt: str, tool: str = None, limit: int = 5
    ) -> List[AttackRecord]:
        """البحث عن هجمات مشابهة"""
        conn = self._connect()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM attacks WHERE 1=1"
        params = []

        if tool:
            query += " AND tool_used = ?"
            params.append(tool)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit * 2)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        similar = []
        for row in rows:
            record = AttackRecord(
                id=row["id"],
                prompt=row["prompt"],
                tool_used=row["tool_used"],
                target=row["target"],
                was_blocked=bool(row["was_blocked"]),
                risk_score=row["risk_score"],
                decision=row["decision"],
                response=row["response"],
                timestamp=row["timestamp"],
                context=json.loads(row["context_json"])
                if row["context_json"]
                else {},
                success=bool(row["success"]),
                adaptation_count=row["adaptation_count"],
                variants=json.loads(row["variants_json"])
                if row["variants_json"]
                else [],
            )

            prompt_words = set(prompt.lower().split())
            record_words = set(record.prompt.lower().split())
            overlap = len(prompt_words & record_words)
            similarity = overlap / max(len(prompt_words), len(record_words), 1)

            similar.append((similarity, record))

        similar.sort(key=lambda x: x[0], reverse=True)
        return [record for _, record in similar[:limit]]

    def get_recent(self, limit: int = 100) -> List[str]:
        """الحصول على أحدث IDs"""
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM attacks ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        ids = [row[0] for row in cursor.fetchall()]
        conn.close()
        return ids

    def get_stats(self) -> Dict:
        """إحصائيات الذاكرة"""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM attacks")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM attacks WHERE success = 1")
        successful = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM attacks WHERE was_blocked = 1")
        blocked = cursor.fetchone()[0]

        cursor.execute("SELECT AVG(risk_score) FROM attacks")
        avg_risk = cursor.fetchone()[0] or 0.0

        cursor.execute(
            """
            SELECT tool_used, COUNT(*) as count
            FROM attacks
            GROUP BY tool_used
            ORDER BY count DESC
            LIMIT 5
            """
        )
        top_tools = [
            {"tool": row[0], "count": row[1]} for row in cursor.fetchall()
        ]

        conn.close()

        return {
            "total_attacks": total,
            "successful": successful,
            "blocked": blocked,
            "success_rate": successful / total if total > 0 else 0,
            "avg_risk_score": round(avg_risk, 3),
            "top_tools": top_tools,
        }
