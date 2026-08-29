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

The current release provides the repository-input boundary: it validates and
normalizes a local repository directory through the command line. Security
scanning rules are under active development.

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
      +---- valid ------> normalized repository path
```

## Requirements

- Python 3.12 or newer
- No third-party runtime dependencies

## Run the CLI

From this repository directory:

```powershell
python -m security_auditor C:\path\to\repository
```

Expected successful output:

```text
Repository accepted: C:\path\to\repository
```

## Run the tests

```powershell
python -m unittest discover -s tests -v
```

The tests cover an existing directory, a missing path, a file passed instead
of a directory, a successful CLI result, and a safe CLI error without a
traceback.

## Security boundary

Repository input must be treated as untrusted. The current release only
validates a local path. Future releases must not execute repository code and
must apply file, size, time, resource, and network limits before public
deployment.

## Production status

This is not a finished or deployed application. The final project must provide
a public end-to-end workflow that another person can use while the developer's
laptop is off.
