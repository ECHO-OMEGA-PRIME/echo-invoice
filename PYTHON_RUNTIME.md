# Python runtime

This repository is the authoritative source for the Echo Invoice Python runtime. The similarly named `C:\\ECHO_OMEGA_PRIME\\SYSTEMS` directory is a compatibility mirror; production changes originate here, pass review and tests here, and only then synchronize to that mirror.

## Local verification

~~~powershell
python -m venv .venv
. .venv/Scripts/Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest -q
~~~

Start the API only after the required environment has been supplied by the deployment secret provider:

~~~powershell
python -m uvicorn app:app --host 127.0.0.1 --port 8000
~~~

## Required configuration

Credential-bearing variables have no built-in production values. Missing or blank required values fail closed.

- `PGPASSWORD`
- `MINIO_ACCESS_KEY`
- `MINIO_SECRET_KEY`
- `ECHO_API_KEY`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`

Never place values in source, examples, service files, or command history. Inject them through the approved runtime secret mechanism.

## Deployment gate

The FORGE unit is `echo-invoice.service`. Deploy an exact reviewed commit to an isolated staging port, exercise `/health`, unauthenticated and invalid-auth rejection, and authenticated access, then promote. If any check fails, leave the current unit untouched or restore its pre-deploy backup.
