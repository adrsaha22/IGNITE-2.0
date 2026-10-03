"""Reference-detection knowledge base: loading, retrieval and dataset building.

Generation is grounded in real detections: before the model is asked for a
rule, the most similar known detections (Splunk ESCU, SigmaHQ, and rules your
team has approved) are retrieved and supplied as reference examples. Approved
library rules get a ranking boost, so new rules converge on your house style.

The dataset is built offline from public sources by
``scripts/download_sources.py`` and ``scripts/build_dataset.py``. Until then a
small bundled sample is used, and the UI says so.

Each example has the shape::

    {"id", "split_key", "input", "output": {title, description, mitre,
     data_source, sigma_rule, spl_query, false_positives, severity,
     how_to_implement}, "meta": {source, ...}}

Splits are made BY TECHNIQUE, so the test split only contains techniques the
retriever has never seen — the evaluation harness relies on that.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from api import settings
from api.services import attack
from api.services.sigma_tools import sigma_to_spl

logger = logging.getLogger(__name__)

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    HAVE_SKLEARN = True
except ImportError:  # pragma: no cover - depends on the environment
    HAVE_SKLEARN = False

_TOKEN = re.compile(r"[a-z0-9_.]+")
_TID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def normalize_tid(value: Any) -> str | None:
    tid = str(value).strip().upper()
    if tid.startswith("ATTACK."):
        tid = tid[7:]
    return tid if _TID.match(tid) else None


# ------------------------------------------------------------------- loading


def active_dataset_dir() -> Path:
    if (settings.KNOWLEDGE_PROCESSED_DIR / "train.jsonl").exists():
        return settings.KNOWLEDGE_PROCESSED_DIR
    return settings.KNOWLEDGE_SAMPLE_DIR


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    logger.warning("Skipping unreadable line in %s", path)
    return out


def load_split(split: str = "train") -> list[dict]:
    return load_jsonl(active_dataset_dir() / f"{split}.jsonl")


def dataset_stats() -> dict[str, Any]:
    d = active_dataset_dir()
    stats_file = d / "stats.json"
    stats: dict[str, Any] = {}
    if stats_file.exists():
        try:
            stats = json.loads(stats_file.read_text(encoding="utf-8"))
        except ValueError:
            stats = {}
    stats.setdefault(
        "counts", {s: len(load_jsonl(d / f"{s}.jsonl")) for s in ("train", "val", "test")}
    )
    stats["location"] = "built" if d == settings.KNOWLEDGE_PROCESSED_DIR else "bundled_sample"
    stats["path"] = str(d)
    return stats


# ----------------------------------------------------------------- retrieval


def _doc_text(example: dict) -> str:
    out = example.get("output", {})
    mitre = out.get("mitre", {})
    return " ".join(
        [
            example.get("input", ""),
            str(out.get("title", "")),
            " ".join(mitre.get("technique_ids", [])),
            str(mitre.get("technique_name", "")),
            " ".join(map(str, out.get("data_source", []) or [])),
        ]
    ).lower()


class ExampleRetriever:
    """TF-IDF retrieval (token overlap if scikit-learn is unavailable)."""

    def __init__(self, examples: Iterable[dict]):
        self.examples = [e for e in examples if e.get("output")]
        self.texts = [_doc_text(e) for e in self.examples]
        self._vec = self._matrix = None
        if HAVE_SKLEARN and self.examples:
            self._vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1)
            self._matrix = self._vec.fit_transform(self.texts)

    def __len__(self) -> int:
        return len(self.examples)

    def _base_scores(self, query: str) -> list[float]:
        if self._vec is not None:
            return cosine_similarity(self._vec.transform([query.lower()]), self._matrix)[0].tolist()
        q = set(_TOKEN.findall(query.lower()))
        return [len(q & set(_TOKEN.findall(t))) / (len(q) or 1) for t in self.texts]

    def search(
        self,
        query: str,
        technique_ids: Iterable[str] | None = None,
        k: int = 3,
        exclude_ids: Iterable[str] | None = None,
    ) -> list[dict]:
        if not self.examples:
            return []
        wanted = {normalize_tid(t) for t in technique_ids or []} - {None}
        wanted_parents = {t.split(".")[0] for t in wanted}
        excluded = set(exclude_ids or [])
        scored = []
        for i, score in enumerate(self._base_scores(query)):
            ex = self.examples[i]
            if ex.get("id") in excluded:
                continue
            tids = set(ex["output"].get("mitre", {}).get("technique_ids", []))
            if wanted & tids:
                score += 0.5
            elif wanted_parents & {t.split(".")[0] for t in tids}:
                score += 0.25
            if ex["output"].get("sigma_rule"):
                score += 0.05  # prefer complete examples
            if ex.get("meta", {}).get("source") == "approved":
                score += 0.1  # your team's approved rules set the house style
            if score > 0:
                scored.append((score, i))
        scored.sort(reverse=True)
        return [dict(self.examples[i], _score=round(s, 3)) for s, i in scored[:k]]


_lock = threading.Lock()
_cache: dict[str, Any] = {"key": None, "retriever": None}


def get_retriever(extra_examples: list[dict] | None = None) -> ExampleRetriever:
    """Retriever over the training split plus approved library rules.

    Rebuilt only when the dataset directory or the approved set changes.
    """
    extra = extra_examples or []
    key = (str(active_dataset_dir()), tuple(sorted(e.get("id", "") for e in extra)))
    with _lock:
        if _cache["key"] != key:
            examples = load_split("train") + load_split("val") + extra
            _cache["retriever"] = ExampleRetriever(examples)
            _cache["key"] = key
        return _cache["retriever"]


def reset_cache() -> None:
    with _lock:
        _cache.update(key=None, retriever=None)


def _trim(value: str | None, limit: int) -> str:
    value = value or ""
    return value if len(value) <= limit else value[:limit] + "\n...[truncated]"


def format_references(examples: list[dict]) -> str:
    """Render retrieved references for the prompt, bounded in size."""
    blocks = []
    for i, ex in enumerate(examples, 1):
        out = ex.get("output", {})
        mitre = out.get("mitre", {})
        blocks.append(
            "\n".join(
                [
                    f"### Reference {i}: {out.get('title', '')} ({ex.get('meta', {}).get('source', 'unknown')})",
                    f"ATT&CK: {', '.join(mitre.get('technique_ids', []))}",
                    f"Data source: {', '.join(map(str, out.get('data_source', []) or []))}",
                    f"SPL:\n{_trim(out.get('spl_query'), 1500)}",
                    f"Sigma:\n{_trim(out.get('sigma_rule'), 1500)}" if out.get("sigma_rule") else "",
                ]
            ).strip()
        )
    return "\n\n".join(blocks)


def reference_summary(examples: list[dict]) -> list[dict[str, Any]]:
    """What the UI shows about the references a rule was grounded in."""
    return [
        {
            "id": ex.get("id", ""),
            "title": ex.get("output", {}).get("title", ""),
            "source": ex.get("meta", {}).get("source", ""),
            "technique_ids": ex.get("output", {}).get("mitre", {}).get("technique_ids", []),
            "score": ex.get("_score"),
        }
        for ex in examples
    ]


# ------------------------------------------------------------ dataset build


def _scores(node: Any) -> list[float]:
    """Every numeric `score` value nested anywhere under a node."""
    found: list[float] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "score" and isinstance(value, (int, float)):
                found.append(value)
            else:
                found += _scores(value)
    elif isinstance(node, list):
        for item in node:
            found += _scores(item)
    return found


def _escu_severity(tags: dict, doc: dict) -> str:
    """Severity from the detection's risk score.

    Current ESCU keeps scores under `finding` / `intermediate_findings`; older
    releases used `rba` or `tags.risk_score`.
    """
    scores = _scores([doc.get("finding"), doc.get("intermediate_findings"), doc.get("rba")])
    score = max(scores) if scores else tags.get("risk_score")
    if not isinstance(score, (int, float)):
        return "medium"
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"


def load_escu(root: Path, product: str | None = None) -> list[dict]:
    records = []
    for f in Path(root, "detections").rglob("*.yml"):
        if "deprecated" in f.parts:
            continue
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict) or not doc.get("search"):
            continue
        if doc.get("status") not in (None, "production"):
            continue
        tags = doc.get("tags") or {}
        # Current ESCU puts mitre_attack_id at the top level; older releases under tags.
        raw_ids = doc.get("mitre_attack_id") or tags.get("mitre_attack_id") or []
        tids = [t for t in (normalize_tid(x) for x in raw_ids) if t]
        if not tids:
            continue
        data_sources = doc.get("data_source", []) or []
        if product:
            ds_text = " ".join(map(str, data_sources)).lower()
            keywords = [product] + (["sysmon"] if product == "windows" else [])
            if not any(k in ds_text for k in keywords):
                continue
        fps = doc.get("known_false_positives")
        records.append(
            {
                "source": "escu",
                "source_id": doc.get("id"),
                "title": doc.get("name"),
                "description": doc.get("description", ""),
                "technique_ids": tids,
                "data_sources": data_sources,
                "sigma_rule": None,
                "spl_query": doc["search"].strip(),
                "false_positives": [fps] if isinstance(fps, str) else (fps or []),
                "severity": _escu_severity(tags, doc),
                "how_to_implement": doc.get("how_to_implement", ""),
            }
        )
    return records


def load_sigma(root: Path, product: str | None = None, convert: bool = True) -> list[dict]:
    records = []
    for f in Path(root, "rules").rglob("*.yml"):
        try:
            text = f.read_text(encoding="utf-8")
            docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        except Exception:
            continue
        if len(docs) != 1:
            continue
        doc = docs[0]
        if doc.get("status") in ("deprecated", "unsupported"):
            continue
        logsource = doc.get("logsource") or {}
        if product and logsource.get("product") != product:
            continue
        tids = [t for t in (normalize_tid(x) for x in doc.get("tags", []) or []) if t]
        if not tids:
            continue
        fps = doc.get("falsepositives", []) or []
        records.append(
            {
                "source": "sigma",
                "source_id": doc.get("id"),
                "title": doc.get("title"),
                "description": doc.get("description", ""),
                "technique_ids": tids,
                "data_sources": [" / ".join(str(v) for v in logsource.values())],
                "sigma_rule": text.strip(),
                "spl_query": sigma_to_spl(text)[0] if convert else None,
                "false_positives": [fps] if isinstance(fps, str) else fps,
                "severity": doc.get("level") or "medium",
                "how_to_implement": "",
            }
        )
    return records


def build_example(rec: dict) -> dict | None:
    primary = rec["technique_ids"][0]
    dataset = attack.load_dataset()
    technique = dataset.get(primary) or dataset.get(primary.split(".")[0])
    if not technique:
        return None
    prompt = (
        f"Create a Splunk detection rule for MITRE ATT&CK {primary} ({technique.name}).\n"
        f"Behavior to detect: {str(rec['description']).strip()}\n"
        f"Available data source: {', '.join(map(str, rec['data_sources'])) or 'unspecified'}"
    )
    return {
        "id": f"{rec['source']}:{rec['source_id']}",
        "split_key": primary.split(".")[0],
        "input": prompt,
        "output": {
            "title": rec["title"],
            "description": rec["description"],
            "mitre": {
                "technique_ids": rec["technique_ids"],
                "technique_name": technique.name,
                "tactics": list(technique.tactics),
            },
            "data_source": rec["data_sources"],
            "sigma_rule": rec["sigma_rule"],
            "spl_query": rec["spl_query"],
            "false_positives": rec["false_positives"],
            "severity": rec["severity"],
            "response_actions": [],
            "how_to_implement": rec["how_to_implement"],
        },
        "meta": {"source": rec["source"]},
    }


def split_for(key: str, val_pct: int = 10, test_pct: int = 10) -> str:
    bucket = int(hashlib.sha256(key.encode()).hexdigest(), 16) % 100
    return "test" if bucket < test_pct else "val" if bucket < test_pct + val_pct else "train"


def build_dataset(
    escu_dir: Path | None,
    sigma_dir: Path | None,
    out_dir: Path | None = None,
    product: str | None = None,
    log: Callable[[str], None] = print,
) -> dict[str, Any]:
    out = Path(out_dir or settings.KNOWLEDGE_PROCESSED_DIR)
    log(f"ATT&CK techniques available: {len(attack.load_dataset().techniques)}")
    escu = load_escu(escu_dir, product) if escu_dir and Path(escu_dir).exists() else []
    log(f"ESCU detections: {len(escu)}")
    sigma = load_sigma(sigma_dir, product) if sigma_dir and Path(sigma_dir).exists() else []
    log(f"Sigma rules: {len(sigma)} ({sum(1 for r in sigma if r['spl_query'])} converted to SPL)")

    out.mkdir(parents=True, exist_ok=True)
    files = {s: open(out / f"{s}.jsonl", "w", encoding="utf-8") for s in ("train", "val", "test")}
    counts: Counter = Counter()
    skipped, seen = 0, set()
    per_technique: dict[str, int] = defaultdict(int)
    try:
        for rec in escu + sigma:
            ex = build_example(rec)
            if not ex or ex["id"] in seen:
                skipped += 1
                continue
            seen.add(ex["id"])
            split = split_for(ex["split_key"])
            files[split].write(json.dumps(ex, ensure_ascii=False) + "\n")
            counts[split] += 1
            per_technique[ex["split_key"]] += 1
    finally:
        for fh in files.values():
            fh.close()

    stats = {
        "counts": dict(counts),
        "skipped": skipped,
        "sources": {"escu": len(escu), "sigma": len(sigma)},
        "techniques_covered": len(per_technique),
        "top_techniques": Counter(per_technique).most_common(15),
        "product_filter": product,
    }
    (out / "stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    reset_cache()
    log(f"Written to {out}: {dict(counts)} (skipped {skipped})")
    return stats


def last_evaluation() -> dict[str, Any] | None:
    """The most recent evaluation summary written by scripts/evaluate.py."""
    path = settings.KNOWLEDGE_DIR / "evaluation.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("summary")
    except ValueError:
        return None
