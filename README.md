# AI Code Security Auditor

An evidence-first repository security auditor designed to combine deterministic
security findings with grounded AI explanations and actionable reports.

## Portfolio links

- **Live Demo:** Planned - the project is not publicly deployed yet.
- **Source Code:** https://github.com/Yosshmi/ai-code-security-auditor
- **Demo Video:** Planned after the public workflow is complete.
- **Technical Documentation:** This README and the future `docs/` directory.
- **Architecture:** The current architecture is documented below.
- **Evaluation Results:** Not measured yet; results will be added after fixtures exist.

## Current status

The current release validates a local repository path, produces a deterministic
file inventory, detects possible hardcoded secrets, and identifies selected
dynamic SQL, command injection, path traversal, and XSS patterns in Python.
Findings include file and line locations with safe evidence and are persisted in
a versioned SQLite database.

## Current architecture

```text
Terminal argument
      |
      v
Argument parser
      |
      v
Path conversion and validation
      |
      +---- invalid ----> helpful error + nonzero exit code
      |
      +---- valid ------> recursive repository inventory
                                |
                                v
                    files, sizes, and extensions
                                |
                                v
                    hardcoded-secret detector
                                |
                                v
                 redacted evidence with file + line
                                |
                                v
                  Python SQL syntax-tree analysis
                                |
                                v
             direct command, path, and XSS flow rules
                                |
                                v
              SQLite repositories, scans, rules, findings
```

## Requirements

- Python 3.12 or newer
- No third-party runtime dependencies

## Run the CLI

From this repository directory:

```powershell
python -m security_auditor C:\path\to\repository
```

Choose a different local database file when needed:

```powershell
python -m security_auditor C:\path\to\repository --database .\audit-results.db
```

Expected successful output:

```text
Repository accepted: C:\path\to\repository
```

## Run the tests

```powershell
python -m unittest discover -s tests -v
```

The tests cover path validation, repository traversal and filtering, extension
and size totals, secret matching and redaction, safe file loading, dynamic SQL
construction, parameterized queries, direct request-to-path and request-to-HTML
flows, shell execution, malformed Python, and safe CLI errors.
Database tests verify schema versioning, rule records, relationships, repeated
scans, and that complete secret candidates are never persisted.

## Security boundary

Repository input must be treated as untrusted. The inventory never executes
repository code and does not follow symbolic links. Future releases must also
apply file, size, time, resource, and network limits before public deployment.
Possible secret values are redacted before they enter findings or terminal
output. Findings require human review because pattern matching can produce
false positives and false negatives.

The SQL rule currently analyzes direct Python calls to `execute()` and
`executemany()`. It detects f-strings, concatenation, percent formatting, and
`str.format()`. It does not yet follow a dynamically constructed query through
variables or analyze non-Python languages, so its findings and omissions require
human review.

The command, path, and XSS rules currently identify selected direct Python
source-to-sink patterns. They do not perform full data-flow analysis across
assignments, functions, modules, or frameworks. Safe validation may therefore
create a false positive, and indirect unsafe flows may produce a false negative.

## Data storage

SQLite stores repository paths, scan metadata, deterministic rule definitions,
and findings. Development database files are ignored by Git. The schema uses
primary keys, foreign keys, indexes, a transaction for each completed scan, and
SQLite `user_version` as the migration baseline. Production database selection,
retention, backup, and migration execution will be defined before deployment.
By default, local scan history is stored in `.security-auditor/auditor.db`; the
generated state directory is excluded from both Git and repository inventory.

## Production status

This is not a finished or deployed application. The final project must provide
a public end-to-end workflow that another person can use while the developer's
laptop is off.
