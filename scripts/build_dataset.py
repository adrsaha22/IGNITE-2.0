"""Build IGNITE's reference-detection knowledge base from data/knowledge/raw/.

    ./venv/bin/python scripts/build_dataset.py                    # everything
    ./venv/bin/python scripts/build_dataset.py --product windows  # recommended start

Output: data/knowledge/processed/{train,val,test}.jsonl and stats.json, split
by technique so the test split only contains techniques retrieval never sees.
Restart the API (or wait for the next generation) to pick it up.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api.services.knowledge import build_dataset  # noqa: E402
from api.settings import KNOWLEDGE_PROCESSED_DIR, KNOWLEDGE_RAW_DIR  # noqa: E402

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--escu", default=str(KNOWLEDGE_RAW_DIR / "security_content"))
    parser.add_argument("--sigma", default=str(KNOWLEDGE_RAW_DIR / "sigma"))
    parser.add_argument("--out", default=str(KNOWLEDGE_PROCESSED_DIR))
    parser.add_argument("--product", default=None, help="e.g. windows, linux")
    args = parser.parse_args()

    if not Path(args.escu).exists() and not Path(args.sigma).exists():
        sys.exit("No sources found. Run scripts/download_sources.py first.")
    build_dataset(Path(args.escu), Path(args.sigma), Path(args.out), args.product)
