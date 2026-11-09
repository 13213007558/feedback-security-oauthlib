# Feedback task starting environment

Upstream: https://github.com/oauthlib/oauthlib
Upstream commit: `179287a5f9067aac7b1c0d71c4c5e083ccbf58f2`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/oauth2/rfc6749
```

Observed baseline (2026-11-09): `273 passed, 10 warnings, 33 subtests passed in 1.44s`
Whole-command wall time: 2.027 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
