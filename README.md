# AI Code Security Auditor

An evidence-first repository security auditor built as a learning-focused,
production-ready portfolio project.

## Portfolio links

- **Live Demo:** Planned - the project is not publicly deployed yet.
- **Source Code:** Add the GitHub URL after the remote repository is created.
- **Demo Video:** Planned after the public workflow is complete.
- **Technical Documentation:** This README and the future `docs/` directory.
- **Architecture:** Current milestone architecture is documented below.
- **Evaluation Results:** Not measured yet; results will be added after fixtures exist.

The project is currently at **Milestone 1**. It validates a local repository
directory but does not scan files yet.

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
- No third-party runtime dependencies for Milestone 1

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

Repository input must be treated as untrusted. This milestone only validates a
local path. Future milestones must not execute repository code and must apply
file, size, time, resource, and network limits before public deployment.

## Production status

This is not a finished or deployed application. The final project must provide
a public end-to-end workflow that another person can use while the developer's
laptop is off.

