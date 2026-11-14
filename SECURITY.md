# Security policy

`rls_check.py` reads files in the folder you point it at. It makes no network calls, needs no credentials, and never prints secret values (keys it finds are reported by file and line with the value redacted). The test suite checks this (`tests/test_security.py`).

Found a bug that could leak data or a false "no findings" on a dangerous pattern? Email hello@proofmerge.com with a minimal SQL example. Please do not include real keys or customer data.
