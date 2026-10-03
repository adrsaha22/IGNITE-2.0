import os
import yaml

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

# Where the Sigma rule corpus lives, in order of preference:
#   1. IGNITE_SIGMA_PATH, if set
#   2. the SigmaHQ clone made by scripts/download_sources.py
#   3. data/sigma/rules (legacy location, empty by default)
_KNOWLEDGE_SIGMA = os.path.join(DATA_DIR, "knowledge", "raw", "sigma", "rules")
_LEGACY_SIGMA = os.path.join(DATA_DIR, "sigma", "rules")


def sigma_path():
    """Resolve the corpus location on every call, so a download is picked up."""
    override = os.environ.get("IGNITE_SIGMA_PATH", "").strip()
    if override:
        return override
    if os.path.isdir(_KNOWLEDGE_SIGMA):
        return _KNOWLEDGE_SIGMA
    return _LEGACY_SIGMA


# Kept for callers that read the constant; prefer sigma_path().
SIGMA_PATH = sigma_path()

# Parsing thousands of YAML files per request would take seconds, so the
# corpus is indexed once and re-indexed only when its files change.
_index = {"key": None, "rules": []}


def _rule_files(root):
    for directory, _dirs, files in os.walk(root):
        for name in files:
            if name.endswith(".yml"):
                yield os.path.join(directory, name)


def _corpus_key(root, paths):
    latest = 0.0
    for path in paths:
        try:
            latest = max(latest, os.path.getmtime(path))
        except OSError:
            pass
    return (root, len(paths), latest)


def _load_index():
    root = sigma_path()
    paths = list(_rule_files(root))
    key = _corpus_key(root, paths)
    if _index["key"] == key:
        return _index["rules"]

    rules = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
        except Exception:
            continue
        if not isinstance(rule, dict):
            continue
        tags = [str(tag).lower() for tag in rule.get("tags", []) or []]
        rules.append((str(rule.get("title", "Unknown")), path, tags))

    _index.update(key=key, rules=rules)
    return rules


def corpus_size():
    """Number of readable Sigma rules in the corpus."""
    return len(_load_index())


def search_sigma_by_attack(attack_id):
    """Rules whose tags mention the technique (T1059 also matches T1059.001)."""
    needle = str(attack_id).lower()
    matches = []
    for title, path, tags in _load_index():
        if any(needle in tag for tag in tags):
            matches.append({"title": title, "path": path})
    return matches
