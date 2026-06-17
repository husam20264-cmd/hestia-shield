"""
Utils for Hestia Shield v1.0.0
"""

import uuid
from datetime import datetime
from typing import Dict, Any


def generate_id(prefix: str = "") -> str:
    unique_id = uuid.uuid4().hex[:12]
    return f"{prefix}_{unique_id}" if prefix else unique_id


def get_timestamp() -> str:
    return datetime.now().isoformat()


def sanitize_input(text: str) -> str:
    Dangerous sequences
    dangerous = ["<script>", "javascript:", "onclick=", "onerror="]
    for seq in dangerous:
        text = text.replace(seq, "")
    return text.strip()