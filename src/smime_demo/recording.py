"""Record every SWS request and response to numbered JSON files.

Used to produce the real examples in docs/API_GUIDE.md (`smime-demo --record DIR
...`). Credentials are replaced with placeholders, activation-link tokens are
redacted, and any address listed in `replace` is substituted (for example a
personal test mailbox), so recordings are safe to publish.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from smime_demo.redaction import redact

PLACEHOLDERS = {"account_key": "YOUR_ACCOUNT_KEY", "secret_key": "YOUR_SECRET_KEY"}


class Recorder:
    def __init__(self, directory: str | Path, replace: dict[str, str] | None = None) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.replace = {k.lower(): v for k, v in (replace or {}).items() if k}
        self.count = len(list(self.directory.glob("*.json")))

    def __call__(
        self,
        method: str,
        path: str,
        query: dict[str, Any],
        body: Any,
        status: int,
        response: Any,
        elapsed: float,
    ) -> Path:
        self.count += 1
        record = {
            "method": method,
            "path": path,
            "query": {k: PLACEHOLDERS.get(k, v) for k, v in query.items()},
            "json": self._clean(body),
            "status": status,
            "elapsed_seconds": round(elapsed, 2),
            "response": self._clean(response),
        }
        slug = re.sub(r"[^a-z0-9]+", "_", f"{method} {path}".lower()).strip("_")
        out = self.directory / f"{self.count:03d}_{slug}.json"
        out.write_text(json.dumps(record, indent=2) + "\n")
        return out

    def _clean(self, value: Any) -> Any:
        value = redact(value)
        if not self.replace:
            return value
        text = json.dumps(value)
        for old, new in self.replace.items():
            text = re.sub(re.escape(old), new, text, flags=re.IGNORECASE)
        return json.loads(text)
