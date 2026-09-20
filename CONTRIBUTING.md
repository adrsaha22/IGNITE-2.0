# Team Guide — IGNITE 2.0

A complete beginner's guide to running the project and contributing code.
**No prior GitHub experience needed.** Follow the sections in order.

Repo: https://github.com/adrsaha22/IGNITE-2.0

---

## Table of Contents

1. [One-time setup](#1-one-time-setup)
2. [Running the website](#2-running-the-website)
3. [Understanding branches](#3-understanding-branches)
4. [The daily workflow](#4-the-daily-workflow)
5. [Making small commits (important!)](#5-making-small-commits-important)
6. [Pushing your work](#6-pushing-your-work)
7. [Opening a Pull Request](#7-opening-a-pull-request)
8. [Staying up to date](#8-staying-up-to-date)
9. [Troubleshooting](#9-troubleshooting)
10. [Command cheat sheet](#10-command-cheat-sheet)

---

## 1. One-time setup

You only do this **once** per computer.

### Step 1.1 — Install Git

Check if you already have it:

```bash
git --version
```

If it says "command not found":

- **Ubuntu/Debian Linux:** `sudo apt install git`
- **Mac:** `brew install git` (or just run `git --version` and macOS will offer to install it)
- **Windows:** download from https://git-scm.com/download/win and use **Git Bash** as your terminal for everything in this guide

### Step 1.2 — Tell Git who you are

This name and email show up on every commit you make. Use your real name and your GitHub email.

```bash
git config --global user.name "Your Name"
git config --global user.email "your-github-email@example.com"
```

### Step 1.3 — Get a GitHub account and access

1. Create an account at https://github.com if you don't have one
2. Send your GitHub username to the project owner so they can add you as a collaborator
3. Accept the invite email — **you can't push without this**

### Step 1.4 — Set up a Personal Access Token (PAT)

GitHub no longer accepts your password in the terminal. You need a token instead.

1. Go to https://github.com/settings/tokens
2. Click **Generate new token** → **Generate new token (classic)**
3. Give it a name like `ignite-laptop`
4. Set **Expiration** to 90 days (or whatever you prefer)
5. Tick the **`repo`** checkbox (this ticks all the sub-boxes automatically)
6. Click **Generate token** at the bottom
7. **Copy the token immediately** — it's shown only once. Save it in a notes app.

When Git later asks for a **password**, paste this token, *not* your GitHub password.

**Optional but recommended** — make Git remember it so you only paste once:

```bash
git config --global credential.helper store
```

### Step 1.5 — Download the project

Pick a folder where you keep your code, then:

```bash
cd ~/projects
git clone https://github.com/adrsaha22/IGNITE-2.0.git
cd IGNITE-2.0
```

You now have the whole project on your computer.

### Step 1.6 — Install Python dependencies

First check you have Python 3:

```bash
python3 --version
```

You need 3.10 or newer. Now create a **virtual environment** — an isolated folder that holds this project's libraries so they don't clash with other projects.

Try the standard way first:

```bash
python3 -m venv venv
```

> **If that fails** with *"ensurepip is not available"* (common on Ubuntu), you have two options:
>
> **Option A** — install the missing package:
> ```bash
> sudo apt install python3-venv
> python3 -m venv venv
> ```
>
> **Option B** — use `uv`, which needs no sudo:
> ```bash
> curl -LsSf https://astral.sh/uv/install.sh | sh
> uv venv venv
> ```

Now install the libraries. **Use the command that matches how you created the venv above:**

```bash
# If you used  python3 -m venv  (Option A):
./venv/bin/pip install -r requirements.txt

# If you used  uv venv  (Option B):
uv pip install --python venv/bin/python -r requirements.txt
```

> ⚠️ Don't mix these up. A venv created by `uv` has **no `pip` inside it**, so
> `./venv/bin/pip` will fail with "No such file or directory". Use the `uv pip`
> command instead — it does the same job.

Check it worked:

```bash
./venv/bin/python -c "import streamlit, yaml, requests, pandas; print('all good')"
```

**Setup is done.** You never repeat section 1.

---

## 2. Running the website

Every time you want to see the site:

```bash
cd ~/projects/IGNITE-2.0
./venv/bin/streamlit run app.py
```

> **Windows (Git Bash)** uses a different path:
> ```bash
> ./venv/Scripts/streamlit run app.py
> ```

Your browser should open automatically. If not, go to **http://localhost:8501**

**To stop the server:** press `Ctrl + C` in the terminal.

### First run only

Streamlit may ask for your email. **Just press Enter** to skip it.

To silence it permanently:

```bash
mkdir -p ~/.streamlit
printf '[general]\nemail = ""\n' > ~/.streamlit/credentials.toml
```

### What you'll see

Paste this into the text box to test it:

```
Attacker used PowerShell to download a payload from GitHub via
DownloadString and created a scheduled task with schtasks for persistence
```

Then click **🛡️ Generate Detection Rules**.

### Known gaps (not bugs — don't report these)

| What you see | Why |
|---|---|
| `Sigma Rules: 0` and empty Sigma section | The `data/sigma/` folder has no rule files yet |
| "AI analysis unavailable" | Ollama isn't installed — that's a separate optional setup |

Everything else works: MITRE mapping, entity extraction, rule scoring, the autonomous engine, validation, and JSON export.

### Shortcut: activating the venv

Typing `./venv/bin/` every time is annoying. You can "activate" the venv instead:

```bash
source venv/bin/activate      # Mac/Linux
source venv/Scripts/activate  # Windows Git Bash
```

Your prompt now shows `(venv)` and you can type plain commands:

```bash
streamlit run app.py
```

Type `deactivate` to exit. **Note:** you must re-activate in every new terminal window.

---

## 3. Understanding branches

A **branch** is your own private copy of the code. You make changes there without affecting anyone else, then ask for them to be merged in.

This project has two permanent branches:

| Branch | What it's for | Can you push to it directly? |
|---|---|---|
| `main` | Stable, working code only | ❌ **Never** |
| `develop` | Where everyone's finished work is combined | ❌ **No** — go through a PR |

**Your work always goes on a new branch made from `develop`.**

```
develop  ──●──────●──────●──────────────▶
            \            ↑
             \           │ (merged via Pull Request)
              ●───●───●──┘
              your-feature-branch
```

### Naming your branch

Use a prefix so everyone knows what it is:

| Prefix | Use it for | Example |
|---|---|---|
| `feature/` | Something new | `feature/export-to-csv` |
| `fix/` | Fixing a bug | `fix/empty-sigma-crash` |
| `docs/` | Documentation only | `docs/setup-instructions` |
| `refactor/` | Cleaning code, no behaviour change | `refactor/merge-scorers` |

Rules: all lowercase, dashes instead of spaces, short and descriptive.

✅ `feature/dark-mode`
❌ `my branch`, `Nithish_work`, `new stuff`, `test123`

---

## 4. The daily workflow

This is the loop you repeat for every piece of work.

### Step 4.1 — Start from the latest `develop`

**Always do this before starting something new.** It prevents most merge conflicts.

```bash
git checkout develop
git pull origin develop
```

`checkout` switches branches. `pull` downloads everyone else's latest work.

### Step 4.2 — Create your branch

```bash
git checkout -b feature/your-thing-here
```

The `-b` flag means "create it, then switch to it."

Confirm where you are:

```bash
git branch --show-current
```

### Step 4.3 — Write your code

Edit files in your editor as normal. Run the app (section 2) to test your changes.

### Step 4.4 — See what you changed

```bash
git status
```

- **Red files** = changed but not staged yet
- **Green files** = staged, ready to commit

To see the actual line-by-line changes:

```bash
git diff
```

(Press `q` to exit if it opens a scrolling view.)

### Step 4.5 — Commit (see section 5 — this is the important part)

### Step 4.6 — Push and open a PR (sections 6 and 7)

---

## 5. Making small commits (important!)

> **The #1 rule of this project: never dump all your work into one giant commit.**

### Why this matters

| One huge commit | Several small commits |
|---|---|
| Reviewer sees 600 changed lines and gives up | Reviewer checks 30 lines at a time and actually catches bugs |
| A bug means undoing *everything* | Undo just the one bad commit |
| Constant merge conflicts | Conflicts are small and rare |
| "Fixed stuff" tells nobody anything | History explains itself |

### The rule of thumb

**One commit = one complete idea.**

If you can't describe your commit in one short sentence without using the word "and", it should be more than one commit.

### Staging specific files

This is the key skill. `git add` decides *what goes in this commit* — you don't have to include everything you changed.

```bash
# Stage ONE file
git add app.py

# Stage a few specific files
git add modules/rule_scorer.py modules/rule_quality.py

# Stage everything in one folder
git add modules/

# Stage everything (⚠️ use sparingly — this is the "dump it all" trap)
git add .
```

Check what's staged before committing:

```bash
git status
```

### Splitting one file into multiple commits

If you changed several unrelated things in the *same* file, Git can walk you through it chunk by chunk:

```bash
git add -p app.py
```

For each chunk it asks `Stage this hunk?`:

- `y` — yes, include it
- `n` — no, skip it for now
- `s` — split into smaller chunks
- `q` — quit

### Writing a good commit message

```bash
git commit -m "Add CSV export button to results panel"
```

**Format:** start with a verb, describe *what it does*, keep it under ~70 characters.

✅ Good:
```
Add CSV export button to results panel
Fix crash when Sigma folder is empty
Remove unused telemetry_context module
Update README with venv setup steps
```

❌ Bad:
```
update
fixed stuff
asdfgh
final version FINAL v2
changes and fixes and new feature
```

### A realistic example

You spent the morning adding a CSV export, fixing a crash, and updating the README. That's **three** commits, not one:

```bash
git add modules/csv_exporter.py app.py
git commit -m "Add CSV export for generated detection rules"

git add modules/sigma_search.py
git commit -m "Fix crash when data/sigma folder is missing"

git add README.md
git commit -m "Document CSV export feature in README"
```

### How often should I commit?

Whenever one small thing **works**. A good target is every 20–60 minutes of coding. Committing is local and free — it costs you nothing and it's your safety net.

### Checking your history

```bash
git log --oneline -10
```

Shows your last 10 commits, one per line.

---

## 6. Pushing your work

**Committing saves locally. Pushing uploads to GitHub.** Both are needed.

### First push on a new branch

```bash
git push -u origin feature/your-thing-here
```

`-u origin <branch>` links your local branch to GitHub. You only need the full form **once per branch**.

When prompted:
- **Username:** your GitHub username
- **Password:** paste your **Personal Access Token** from step 1.4 (not your real password — it will look like nothing is typing, that's normal, just paste and press Enter)

### Every push after that

```bash
git push
```

### How often to push?

**At least once at the end of every work session.** Code that only exists on your laptop is code that can be lost. Pushing an unfinished branch is completely fine — it's not merged into anything until the PR is approved.

---

## 7. Opening a Pull Request

A **Pull Request (PR)** asks the team to review your branch and merge it into `develop`.

### Step 7.1 — Make sure everything is pushed

```bash
git status
```

Should say `nothing to commit, working tree clean`.

### Step 7.2 — Go to GitHub

Open https://github.com/adrsaha22/IGNITE-2.0

You'll see a yellow banner: **"your-branch had recent pushes"** with a green **Compare & pull request** button. Click it.

*(No banner? Click the **Pull requests** tab → **New pull request**.)*

### Step 7.3 — Set the branches correctly ⚠️

This is the step people get wrong:

```
base: develop   ←   compare: feature/your-thing-here
```

- **base** = where your code is going → must be **`develop`**, NOT `main`
- **compare** = your branch

GitHub often defaults `base` to `main`. **Change it to `develop`.**

### Step 7.4 — Describe your work

**Title:** one clear line
```
Add CSV export for detection rules
```

**Description:** use this template
```markdown
## What this does
Adds a "Download CSV" button next to the existing JSON export
so analysts can open results in Excel.

## Why
Requested by the team — JSON is hard to read for non-technical users.

## How to test
1. Run the app
2. Enter any attack description and click Generate Detection Rules
3. Scroll to the bottom and click "Download CSV"
4. Open the file in Excel — should show one row per rule

## Notes
Sigma section still shows 0 rules — unrelated, existing issue.
```

### Step 7.5 — Create and wait for review

Click **Create pull request**, then share the link with the team.

**If reviewers request changes:** don't open a new PR. Just commit and push to the *same branch* — the PR updates automatically:

```bash
# make the requested edits, then:
git add <files>
git commit -m "Address review: rename CSV column headers"
git push
```

### Step 7.6 — After it's merged

```bash
git checkout develop
git pull origin develop
git branch -d feature/your-thing-here
```

That switches back, gets the merged code, and deletes your finished branch locally.

---

## 8. Staying up to date

If teammates merged work while you were coding, pull their changes into your branch:

```bash
git checkout develop
git pull origin develop
git checkout feature/your-thing-here
git merge develop
```

Do this every day or two on a long-running branch. Small, frequent merges are painless; one big merge after two weeks is misery.

### If you get a merge conflict

Don't panic — it just means you and someone else edited the same lines.

1. `git status` lists the conflicted files
2. Open each one. You'll see:

```
<<<<<<< HEAD
your version of the line
=======
their version of the line
>>>>>>> develop
```

3. Delete the `<<<<<<<`, `=======`, and `>>>>>>>` markers, and keep whichever code is correct (sometimes both, combined)
4. Then:

```bash
git add <the-file-you-fixed>
git commit -m "Merge develop into feature branch"
```

**Unsure which version to keep?** Ask in the team chat before guessing. To abandon the merge and go back to how things were:

```bash
git merge --abort
```

---

## 9. Troubleshooting

### `zsh: command not found: streamlit`

The venv isn't active. Use the full path:
```bash
./venv/bin/streamlit run app.py
```

### `zsh: number expected` / weird shell errors

You pasted the terminal prompt (`➜ IGNITE-2.0 git:(develop)`) along with the command. Copy only the command itself.

### `ensurepip is not available`

See the note in step 1.6 — install `python3-venv` with sudo, or use `uv`.

### `Port 8501 is already in use`

The app is already running somewhere. Either use that tab, or:
```bash
pkill -f streamlit
```
Or run on a different port:
```bash
./venv/bin/streamlit run app.py --server.port 8502
```

### `Authentication failed` when pushing

Your Personal Access Token is wrong or expired. Generate a new one (step 1.4). To clear a bad saved credential:
```bash
git config --global --unset credential.helper
```
Then push again and paste the new token.

### `Updates were rejected because the remote contains work that you do not have`

Someone pushed to your branch. Pull first:
```bash
git pull origin feature/your-thing-here
git push
```

### `Permission denied` / `403` when pushing

You haven't been added as a collaborator, or you didn't accept the invite. Check your email and ask the project owner.

### I committed to `develop` by accident

Nothing is broken as long as you haven't pushed. Move your work to a proper branch:
```bash
git branch feature/my-work     # save current state to a new branch
git reset --hard origin/develop # reset develop back to normal
git checkout feature/my-work    # continue on the right branch
```

> ⚠️ `git reset --hard` **deletes uncommitted changes permanently.** Only run it when your work is already committed (which the first line above ensures).

### I want to undo my last commit but keep the code

```bash
git reset --soft HEAD~1
```
Your changes return to "staged" and you can re-commit them properly.

### I'm lost / everything is broken

Your work is almost always recoverable. Before trying random commands, run these and paste the output in the team chat:
```bash
git status
git log --oneline -5
git branch --show-current
```

### Never commit these

The `.gitignore` already blocks them, but as a rule: never commit `venv/`, `__pycache__/`, `*.pyc`, or any file with passwords, API keys, or tokens.

---

## 10. Command cheat sheet

### Running the app
```bash
cd ~/projects/IGNITE-2.0
./venv/bin/streamlit run app.py          # start (Ctrl+C to stop)
```

### Starting new work
```bash
git checkout develop                      # go to develop
git pull origin develop                   # get latest
git checkout -b feature/my-thing          # create your branch
```

### While working
```bash
git status                                # what changed?
git diff                                  # show the changes
git add path/to/file.py                   # stage one file
git add -p path/to/file.py                # stage part of a file
git commit -m "Clear message here"        # save a small commit
git log --oneline -10                     # recent history
```

### Sharing
```bash
git push -u origin feature/my-thing       # first push on a branch
git push                                  # every push after
```

### Then open the PR on GitHub with base = `develop`

### Keeping current
```bash
git checkout develop && git pull origin develop
git checkout feature/my-thing && git merge develop
```

### After your PR is merged
```bash
git checkout develop
git pull origin develop
git branch -d feature/my-thing
```

---

## The golden rules

1. **Never push directly to `main` or `develop`** — always branch, always PR
2. **Always `git pull origin develop` before starting** something new
3. **Small commits, one idea each** — if the message needs "and", split it
4. **Push before you finish for the day** — don't leave work only on your laptop
5. **PR base is `develop`**, not `main`
6. **Ask in the team chat** before running anything with `--force` or `--hard`
