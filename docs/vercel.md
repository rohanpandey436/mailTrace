# Deploying the dashboard on Vercel

The MailTrace dashboard is a directory of static files: HTML, one Tailwind-built
stylesheet, and ES modules the browser runs as written. There is no build step
and no Node, so Vercel has nothing to compile. It serves `frontend/` as-is.

The API stays on Render. `vercel.json` rewrites `/api/*` to it, so the frontend
keeps calling same-origin paths and needs no change; the browser never sees the
Render hostname, and there is no CORS preflight on every request.

## One-time setup

1. Sign in at [vercel.com](https://vercel.com) with the GitHub account that owns
   the repository.
2. **Add New… → Project**, and import `rohanpandey436/mailTrace`.
3. Leave every build setting alone. `vercel.json` already sets the output
   directory to `frontend` and disables the build command; Vercel's framework
   detection finds nothing to override.
4. **Deploy.**

Every push to `main` redeploys. Pull requests get their own preview URL, which
also proxies to the same Render API.

## If the API moves

The Render URL appears once, in the `rewrites` block of `vercel.json`. Change it
there and redeploy; nothing in `frontend/` refers to it.

## What still runs on Render

Everything that is not a static file: analysis, the database, the chain of
custody, report generation, the alert stream and the task queue. Vercel serves
the dashboard and forwards API calls. It does not run any Python.

Two consequences:

- **Cold starts still apply.** The Render free tier sleeps an idle service, so
  the first request after a quiet period waits for it to wake, whether it
  arrives through Vercel or directly.
- **The alert stream is a proxied `text/event-stream`.** It works, but a
  platform proxy may buffer more than a direct connection does, so a live alert
  can arrive a moment later than it would against Render directly.

Neither affects the Render deployment, which continues to serve the dashboard
itself at `/` exactly as before. Vercel is an additional front door, not a
replacement.
