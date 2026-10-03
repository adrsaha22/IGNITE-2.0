# legacy/

Archived files kept for reference. Nothing in the application imports them.

| Path | What it was |
| --- | --- |
| `manual_checks/` | Ad-hoc scripts that print the output of individual `modules/` functions. They were never part of the automated suite (`tests/`). To run one, from the project root: `./venv/bin/python -c "import runpy; runpy.run_path('legacy/manual_checks/test_engine.py')"` |
| `app_old.py`, `app_backup.py` | Earlier copies of the Streamlit front end, superseded by `app.py`. |
| `llm_rule_generator.py` | Was at `modules/modules/llm_rule_generator.py`, an accidental nested copy. |

Safe to delete once the team agrees.
