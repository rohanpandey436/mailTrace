Deployment assets.

- `../render.yaml` must stay at the repository root: Render only reads a
  Blueprint from there. It points `rootDir` at `backend/`.
- `.env.example` is the template for local configuration; copy it to
  `../.env` (project root) or `../backend/.env`, both are read.
- `Dockerfile` builds the same service for any container host. Build it from
  the **repository root**, because the image needs `backend/`, `frontend/` and
  `samples/` together:

      docker build -f deploy/Dockerfile -t mailtrace .
      docker run --rm -p 8000:8000 -v mailtrace-data:/app/backend/data mailtrace

  UNVERIFIED: no Docker daemon was available where it was written, so it has
  never been built or run. `../.dockerignore` keeps the build context small and
  keeps `data/` (real cases) and any `.env` out of the image.
  `../.dockerignore` also excludes `backend/tests/`, `engine/`, `docs/` and
  `deploy/` itself, so `docker run ... pytest` will not work as shipped.
- `../.github/workflows/ci.yml` runs the same suite on every push and pull
  request: Python 3.12, `backend/requirements-dev.txt` installed from
  `working-directory: backend`, an import check that walks every module in the
  `app` package plus `run`, then `python -m pytest -q`. The optional extras
  (`requirements-ml.txt`, `requirements-pg.txt`) are deliberately not installed
  there - CI's job is to prove the service works without them. Locally, that
  suite reports **133 passed, 6 skipped** (measured 2026-09-05); the six skips
  are the C++ parity tests, which need the never-built extension in `../engine/`.
- `../backend/requirements-pg.txt` is the optional PostgreSQL driver. See
  `MAILTRACE_DATABASE_URL` in `.env.example`, and `../docs/scaling.md` for why
  a shared store is the prerequisite for everything else.
