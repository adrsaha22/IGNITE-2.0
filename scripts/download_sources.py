"""Download the public detection sources IGNITE's knowledge base is built from.

  - splunk/security_content  (Splunk ESCU detections, Apache 2.0)
  - SigmaHQ/sigma            (community Sigma rules, Detection Rule License)

Both are shallow-cloned into data/knowledge/raw/. Requires git on your PATH.
The ATT&CK bundle is already shipped at data/mitre.json.

Run from the project root:
    ./venv/bin/python scripts/download_sources.py
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api.settings import KNOWLEDGE_RAW_DIR  # noqa: E402

# Some SigmaHQ paths exceed Windows' 260-character limit when the project sits
# in a deep folder; without this, git clones but cannot check those files out.
LONG_PATHS = ["-c", "core.longpaths=true"]

REPOS = {
    "security_content": "https://github.com/splunk/security_content.git",
    "sigma": "https://github.com/SigmaHQ/sigma.git",
}


def clone_or_update(name: str, url: str) -> Path:
    target = KNOWLEDGE_RAW_DIR / name
    if (target / ".git").exists():
        print(f"Updating {name}...")
        subprocess.run(["git", *LONG_PATHS, "-C", str(target), "pull", "--depth", "1"], check=True)
    else:
        print(f"Cloning {name} (shallow)...")
        subprocess.run(["git", *LONG_PATHS, "clone", "--depth", "1", url, str(target)], check=True)
        # Keep long-path support for later pulls in this clone.
        subprocess.run(["git", "-C", str(target), "config", "core.longpaths", "true"], check=True)
    return target


if __name__ == "__main__":
    KNOWLEDGE_RAW_DIR.mkdir(parents=True, exist_ok=True)
    for repo_name, repo_url in REPOS.items():
        clone_or_update(repo_name, repo_url)
    print(f"Sources are in {KNOWLEDGE_RAW_DIR}. Next: scripts/build_dataset.py --product windows")
