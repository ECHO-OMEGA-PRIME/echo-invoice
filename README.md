# Echo Invoice

Invoice, payment-link, and billing API for ECHO OMEGA PRIME, with a Cloudflare Worker edge surface and a production Python service.

See [PYTHON_RUNTIME.md](PYTHON_RUNTIME.md) for Python installation, required credentials, and the staging-first deployment gate.

## Verify

~~~powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
npm install
npm exec tsc -- --noEmit
~~~
