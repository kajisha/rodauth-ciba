#!/usr/bin/env python3
"""Send the saved decision questions; never print or save the API credential."""
import json
import argparse
import os
import re
import shlex
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parent.parent
directory = root / "docs/research"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--review", choices=("decision", "alternatives", "cache", "cache-options", "cache-rfc"), default="decision")
args = parser.parse_args()
prefix = "jev-alignment-" + args.review
key = os.environ.get("TYPESAFE_API_KEY")
if not key:
    for line in (Path.home() / ".config/typesafe/env").read_text().splitlines():
        match = re.match(r"\s*(?:export\s+)?TYPESAFE_API_KEY\s*=\s*(.*)$", line)
        if match:
            values = shlex.split(match.group(1), comments=True)
            key = values[0] if len(values) == 1 else None
if not key:
    raise SystemExit("TYPESAFE_API_KEY is unavailable or not a literal value")

request = urllib.request.Request(
    "https://api.typesafe.ai/v1/systemone",
    data=(directory / (prefix + "-request.json")).read_bytes(),
    headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(request, timeout=45) as response:
        result = json.load(response)
except (urllib.error.URLError, TimeoutError) as error:
    result = {"status": "failed", "time": datetime.now(timezone.utc).isoformat(),
              "failure": type(error).__name__, "received_model_answers": False}
    if isinstance(error, urllib.error.HTTPError):
        result["http_status"] = error.code
    (directory / (prefix + "-attempt.json")).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    raise SystemExit(1)

(directory / (prefix + "-response.json")).write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + "\n"
)
print(json.dumps({k: result.get(k) for k in ("model", "answers", "usage")}, ensure_ascii=False, indent=2))
