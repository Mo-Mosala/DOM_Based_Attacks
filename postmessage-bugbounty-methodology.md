# postMessage Vulnerability Hunting — Methodology

A reference workflow for finding and exploiting `window.postMessage` / DOM XSS
vulnerabilities during authorized testing (bug bounty, pentest, CTF). Target
placeholder throughout: `example.com`. Replace with the in-scope host you're
actually testing, and confirm program scope before sending any payload
cross-origin to a live target.

---

## 1. Why postMessage matters as an attack surface

`postMessage` is the browser's sanctioned way around the Same-Origin Policy —
it lets two different origins (a page and a popup, a page and an embedded
iframe) exchange data safely, *if and only if* both sides implement their half
of the contract correctly. The API enforces nothing on its own; all of the
security is opt-in application logic. That's exactly why it's fertile ground:

- Automated scanners don't understand it — there's no request/response to
  fuzz, it's pure client-side JS logic.
- It requires reading and reasoning about JavaScript, not just throwing
  payloads at parameters — most hunters skip it in favor of reflected XSS/SQLi
  that tooling already covers.
- It shows up in high-value flows precisely because it exists to bridge origin
  boundaries: **payment/checkout iframes** (PCI segmentation), **OAuth
  popups** (token handback to the opener), **customer-support chat widgets**,
  **embedded ad/analytics iframes**, and **cross-subdomain SSO**.
- Impact scales with what's reachable from the sink — DOM XSS via postMessage
  is functionally identical to any other DOM XSS once you're executing script
  in the target's origin (session/localStorage token theft, CSRF-token theft,
  full account takeover), just reached via a different source.

---

## 2. The postMessage triangle

Every postMessage vulnerability decomposes into three parts. Identify all
three before you write a single payload.

```
   SENDER                    RECEIVER                    SINK
(who sends it)      →    (who listens, and how       →  (what happens to
                          it validates the sender)        the data)
```

### 2.1 Sender

```js
otherWindow.postMessage(data, targetOrigin);
```

- `data` — the payload (string, or a structured-clone-able object).
- `targetOrigin` — a constraint on the **sender**: "only deliver this if the
  recipient window's current origin matches this value." `'*'` disables that
  constraint entirely. This is frequently confused with receiver-side origin
  validation — **it is not the same thing and does nothing to protect the
  receiver.** A wildcard `targetOrigin` on the sender side is only a bug in
  its own right if the *data* being sent is sensitive (see §2.3, sink type
  E) — otherwise it just means "this message can reach anyone," which is
  normal for public broadcast-style messages.

### 2.2 Receiver

```js
window.addEventListener('message', function(e) { ... });
```

The event object `e` carries three properties worth checking every time:

| Property | Meaning | What to check |
|---|---|---|
| `e.data` | the payload | is it used raw, or passed through `JSON.parse`, `innerHTML`, `eval`, a URL sink, etc.? |
| `e.origin` | the **sender's** origin (`protocol://host[:port]`) | is it validated at all, and validated *correctly*? (§3) |
| `e.source` | window reference to the sender | rarely checked in practice; if relied on for trust decisions, verify it's actually compared against something |

A quick refresher on what "origin" means, since receiver bugs are almost
always origin-comparison bugs:

```
https://example.com                → origin A
https://sub.example.com            → different origin (subdomain differs)
http://example.com                 → different origin (scheme differs)
https://example.com:8443           → different origin (port differs)
https://example.com.evil.tld       → different origin, but a NAIVE substring
                                      or prefix check may treat it as trusted
```

### 2.3 Sink

Where `e.data` (or a field extracted from it) ends up determines the exploit
primitive. Catalog:

| Sink type | Example code | Primitive |
|---|---|---|
| **A. `eval`/`Function`** | `eval(e.data)` | Direct arbitrary JS execution — highest severity, simplest exploit. |
| **B. HTML injection** | `el.innerHTML = e.data` / `document.write(e.data)` | Classic markup-based XSS — `<img src=1 onerror=...>`, `<svg onload=...>`. |
| **C. Navigation / URL** | `location.href = e.data` / `location.assign(e.data)` / `iframe.src = e.data` / `window.open(e.data)` | `javascript:` URI → script execution (if the browser still honors it in that sink — see §5 notes); `https:` URI → open redirect / phishing / reverse tabnabbing. |
| **D. `JSON.parse` + dispatcher** | `var d = JSON.parse(e.data); switch(d.type) { ... }` | `JSON.parse` is a *format* check, not a *security* check — trace every `case` branch to its own sink independently; this pattern is extremely common in real apps (RPC-style `{action, ...}` or `{type, ...}` messages) and each branch is a separate bug to test. |
| **E. Sensitive-data handback** | receiver replies with `e.source.postMessage(secretToken, e.origin)` after insufficient validation of the *request* | information disclosure — attacker page requests data it shouldn't be able to get and receives it because the request wasn't authenticated. |
| **F. CSS/attribute injection** | message content flows into a `style`/attribute value that's later reflected | lower-severity but chainable (see §7 case study 3 — CSS exfiltration). |

---

## 3. Origin-check bypass patterns

This is where most real bugs live — not "no check at all" (though that
happens), but a check that *looks* correct and isn't. Grep for these patterns
specifically; each has a concrete bypass.

### 3.1 Missing check entirely
```js
window.addEventListener('message', function(e) {
  document.getElementById('ads').innerHTML = e.data; // no origin check anywhere
});
```
Bypass: none needed. Any origin works.

### 3.2 `startsWith()` — bypassed via subdomain-shaped attacker domain
```js
if (!e.origin.startsWith('https://example.com')) return;
```
Bypass: register/host on `https://example.com.attacker.tld` — the string
literally starts with `https://example.com`.

### 3.3 `endsWith()` — bypassed via a "junk-prefixed" attacker domain
```js
if (!e.origin.endsWith('example.com')) return;
```
Bypass: `https://evilexample.com` or `https://notexample.com` both satisfy
this — there's no delimiter check for the subdomain boundary.

### 3.4 `.includes()` / `.indexOf(x) > -1` — bypassed via substring anywhere
```js
if (e.origin.includes('example.com')) { /* trusted */ }
// or
if (e.origin.indexOf('example.com') > -1) { /* trusted */ }
```
Bypass: `https://example.com.attacker.tld`, `https://attacker-example.com.tld`,
literally any origin string that contains the substring `example.com`
*anywhere*. This is the single most common real-world variant — it "reads"
like a safe check to a developer and passes casual QA.

### 3.5 Unescaped `.` in a regex
```js
if (/^https:\/\/example\.com$/.test(e.origin)) { /* correct: escaped dot, anchored */ }
if (/^https:\/\/example.com$/.test(e.origin))  { /* BUG: unescaped dot = wildcard char */ }
```
Bypass: the unescaped `.` matches *any single character*, so
`https://examplexcom`, `https://example-com`, `https://exampleAcom` all pass.
Also check for **missing anchors** (`^`/`$`) independent of the dot issue —
an unanchored regex is bypassable the same way as `.includes()`.

### 3.6 Same-string-check applied to the wrong value
Occasionally the check validates `e.source` loosely, or checks
`document.referrer` / `location.ancestorOrigins` instead of `e.origin` — worth
confirming the check is actually gating on `e.origin` and not something the
attacker also controls or that's absent in the delivery method you're using
(e.g., `document.referrer` is empty for some `noreferrer` delivery paths).

### 3.7 Missing `event.isTrusted`
Not an origin check, but related: `event.isTrusted` distinguishes messages
dispatched by the browser's real postMessage mechanism from ones dispatched
programmatically via `dispatchEvent` from same-page script (e.g. a
third-party script on the same page forging a fake `MessageEvent`). Its
absence is a secondary hardening gap, not usually independently exploitable
from a different origin, but worth noting in a report as defense-in-depth.

---

## 4. Recon: finding postMessage code in the wild

Three complementary methods — use all three, they catch different things.

### 4.1 Browser extension (fastest recon pass)
A tracker/highlighter extension (e.g. "Fancy postMessage tracker" or
similar) instruments `postMessage` calls and `message` listeners as you
browse, surfacing sender/receiver pairs and payload shapes without manual
breakpoint setup. Good first pass across a whole application to find which
pages are even in-scope for this bug class.

### 4.2 DevTools event-listener breakpoints (best for confirming live behavior)
1. Chrome DevTools → **Sources** tab → right panel → **Event Listener
   Breakpoints** → expand **Message** → check **`message`**.
2. Interact with the page normally (load a page that embeds iframes, go
   through a checkout/auth flow, etc.).
3. Execution pauses whenever a `message` event fires anywhere on the page —
   inspect `e.data`, `e.origin`, `e.source`, and step through the handler to
   see exactly which branch/sink is reached.

This is the most reliable way to catch dynamically-loaded or minified
handlers that are hard to spot by reading source.

### 4.3 Manual source review (find the actual validation logic)
```bash
# In browser DevTools global search (Ctrl+Shift+F in Sources), or against
# saved/beautified JS bundles locally:
grep -n "addEventListener(['\"]message['\"]" -r ./bundle/
grep -n "onmessage" -r ./bundle/
grep -n "postMessage(" -r ./bundle/
```
For minified bundles, beautify first (`js-beautify`, or paste into an editor
with a "format document" action) — production JS is often *readable* even
when minified, just ugly; don't skip a target because the file is one line.

For each hit:
1. Identify the handler function.
2. Find the origin check (or confirm there isn't one) — match it against the
   bypass catalog in §3.
3. Trace `e.data` (or destructured fields off it) to wherever it's finally
   used — that's the sink, catalog it against §2.3.
4. Note any `try/catch` around `JSON.parse` — errors are usually swallowed
   silently, which is a small tell that the input is externally-supplied and
   not always well-formed (i.e., real postMessage traffic, not just internal
   plumbing).

---

## 5. Building and testing the PoC — step by step

Use `example.com` as the target throughout below; substitute your actual
authorized target.

### Step 1 — Confirm the listener is live
In DevTools console on the target page:
```js
getEventListeners(window).message
```
(Chrome-only API, console context.) Confirms a handler is attached before you
spend time building delivery infrastructure.

### Step 2 — Prove the primitive locally (same console, before any delivery page)
This isolates "does the source→sink chain work at all" from "can I deliver
it cross-origin" — always do this first, it's far faster to iterate on.

```js
// Sink type A (eval):
window.postMessage('print()', '*')

// Sink type B (innerHTML):
window.postMessage('<img src=1 onerror=print()>', '*')

// Sink type C (location/navigation), if there's NO validation:
window.postMessage('javascript:print()', '*')

// Sink type C, if there's a naive substring filter requiring "http(s):" to
// appear anywhere in the string:
window.postMessage('javascript:print()//https://a/', '*')
// or, if the filter checks the whole string for that substring but not
// position, a bare trailing marker also works:
window.postMessage('javascript:print()//http:', '*')

// Sink type D (JSON.parse + dispatcher):
window.postMessage(JSON.stringify({type: 'load-channel', url: 'javascript:print()'}), '*')
```

If nothing fires, revisit §4.3 — you likely have the wrong field name, wrong
`type`/`action` value for the dispatcher, or there's an origin check you
haven't identified yet (test from an actual different-origin tab to rule that
out before concluding the sink itself is unreachable).

> **Why `print()` and not `alert(document.domain)`?** `print()` is a safe,
> unmistakable proof of arbitrary JS execution that doesn't require reading
> anything sensitive — good default for a first confirmation on any target.
> Once confirmed, escalate the *reported* PoC to `alert(document.domain)` (or
> an OAST/collaborator callback for blind confirmation in automated flows) to
> demonstrate it's running in the target's actual origin, which matters for
> triagers assessing impact.

### Step 3 — Build the delivery page

The delivery mechanism depends on whether you have a same-page relationship
to the target already, or need to establish one:

**Iframe delivery** (target does not block framing — check response headers
`X-Frame-Options` / CSP `frame-ancestors` first):
```html
<!doctype html>
<meta charset="utf-8">
<iframe src="https://example.com/some/page"
        onload="this.contentWindow.postMessage('PAYLOAD','*')">
</iframe>
```

**Popup delivery** (fallback if framing is blocked):
```html
<!doctype html>
<meta charset="utf-8">
<button onclick="fire()">exploit</button>
<script>
function fire(){
  const win = window.open('https://example.com/some/page');
  setTimeout(() => {
    win.postMessage('PAYLOAD', '*');
  }, 2000); // give the SPA time to mount and attach its listener
}
</script>
```

Notes:
- `onload` (iframe) or a short `setTimeout` (popup) matters — firing before
  the target page has finished attaching its listener silently drops the
  message. If your PoC intermittently fails, increase the delay before
  assuming the bug isn't real.
- `targetOrigin: '*'` on your *sender* side is fine/expected for the exploit
  page itself — you don't control the victim's exact current origin state,
  and this is the attacker's own page, not the vulnerable one.
- If the receiver's origin check uses one of the §3 bypass patterns, your
  delivery page's own origin needs to satisfy that specific pattern (e.g. for
  §3.2 you need a page hosted at a URL that *starts with* the expected
  string, which in practice you generally cannot forge for an https origin —
  that bypass class mostly matters for `startsWith`/`endsWith`/`includes`
  checks against a *substring*, which you satisfy by owning a domain that
  contains the target substring, e.g. `example.com.yourtestdomain.tld`).

### Step 4 — Payload construction for `JSON.parse`-based dispatchers

When the receiver expects a JSON string (not a structured-clone object), and
you're embedding the call inside an HTML attribute, you get nested quoting —
worth understanding rather than memorizing:

```html
<iframe src="https://example.com/" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

Layers, outside in:
1. HTML attribute `onload='...'` — single-quoted, so unescaped `"` is safe
   inside it.
2. A JS statement: `postMessage(arg1, "*")`.
3. `arg1` must be **a string containing JSON text** (because the receiver
   does `JSON.parse(e.data)` — sending a structured-clone object directly
   would skip parsing and likely break the handler's expectations).
4. So `arg1` is written as a double-quoted JS string literal, with the JSON's
   own double quotes backslash-escaped so they don't terminate the JS string
   early: `"{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}"`.
5. Unescaped, that string is valid JSON: `{"type":"load-channel","url":"javascript:print()"}`.

### Step 5 — Isolate root cause (report quality)

Before writing anything up, prove *which specific defect* is the actual gate:

- Repeat delivery from an origin that should **fail** the check (e.g. a
  plain unrelated domain) and confirm the message is ignored. This isolates
  the origin-check bypass (or its absence) as the real root cause, not some
  other coincidental factor.
- If there's a content filter on the sink (like the `indexOf('https:')`
  pattern), also demonstrate the filter *without* your bypass trick fails
  cleanly (e.g. send `javascript:print()` alone, confirm it's rejected), then
  show the bypassed version succeeding — this makes the "weak filter, not
  missing filter" distinction clear to a triager.

---

## 6. Escalating impact beyond `print()`/`alert()`

Once execution is confirmed, the *reportable* impact depends on what's
reachable from the target's origin at that point. Common escalation paths,
roughly ascending severity:

1. **Open redirect / phishing** (sink type C with an `https:` URL, even
   without JS execution) — check whether `window.open` was called without
   `"noopener"`; if so this is also **reverse tabnabbing**
   (`opener.location = 'https://phishing-page'` from the *opened* page back
   onto the *opener*).
2. **Session/token theft via storage** — if script execution is confirmed in
   the target's origin, check `localStorage`/`sessionStorage` for
   auth tokens (`localStorage.getItem(...)`) — JS-readable storage is
   readable by any XSS in that origin, cookies with `HttpOnly` are not.
   **Prove read-capability only** (e.g. `alert(value.length)` or confirm key
   existence) — do not exfiltrate real tokens/secrets, even in your own test
   account, and never send them to an external OAST/collaborator endpoint.
3. **CSRF-token / anti-CSRF bypass** — if a page-embedded CSRF token is
   readable via the DOM once you have XSS, you can chain into state-changing
   requests as the victim.
4. **Full account takeover** — chaining 2 or 3 into session hijacking or
   credential/settings modification, if in scope and not requiring
   destructive action against a real account.
5. **Sensitive-data exfiltration via sink type E** — if the receiver replies
   to requests with data without validating the *requester's* origin, a
   simple `postMessage` from your page requesting that data may leak it
   directly, no script execution needed at all.

Always check program rules of engagement before performing 2–4 against a
live/production target — many programs want you to stop at "provable
primitive" (e.g. `alert(document.domain)` or an OAST hit) rather than
demonstrating full token theft.

---

## 7. Case-study patterns (abstracted, generalizable)

These are recurring shapes seen across real targets — useful as pattern-match
templates when reviewing a new target's code, not tied to any one program.

**Pattern 1 — `endsWith`-style bypass into a `window.open` URL sink.**
A 404/error-handling message handler checks `e.origin` with an `endsWith`
(or equivalent loose suffix) match against the expected domain, then passes
`e.data` (a URL) straight to `window.open()`. A domain merely *ending with*
the expected string (`https://junk-example.com`) satisfies the check; a
`javascript:` URL as the payload gets executed on open.

**Pattern 2 — No origin check at all, location sink.**
A handler reads `e.data` directly into `location.href` / `location.assign`
with zero origin validation of any kind. Simplest and most severe variant —
no bypass technique needed, just send the `javascript:` payload.

**Pattern 3 — Sanitized-but-incompletely-sanitized iframe `src` sink.**
A handler extracts a URL fragment from `e.data` (e.g. parsing it out of a
larger string via bracket/delimiter matching), then applies a chain of
sanitization steps (strip HTML tags, strip `javascript:` scheme, strip other
dangerous schemes, strip control characters) before assigning it to an
`iframe.src`. Vulnerability requires understanding *the order and completeness*
of the sanitization chain — e.g. if scheme-stripping happens before
control-character stripping, an embedded control character or encoding trick
can reconstitute a `javascript:` scheme post-sanitization. This class needs
careful, incremental testing (mutate one sanitizer-defeating trick at a time)
rather than a single canned payload.

**Pattern 4 — CSS-injection sink chained into a side-channel exfiltration.**
Not classic script-execution XSS, but relevant to the same message-handling
surface: a receiver accepts style/content properties from `e.data` with a
CSS-focused sanitizer (blacklist-based, missing CSS escape-sequence handling
per Unicode/backslash escaping rules). A CSS injection alone doesn't execute
JS, but can be chained into a keystroke/value exfiltration channel using
per-character web-font loads gated by CSS attribute/Unicode-range selectors
— each character typed into a field triggers a distinguishable external font
request, effectively building a side-channel keylogger over CSS alone,
without any JavaScript executing. High-effort but demonstrates that "no XSS"
doesn't always mean "no impact" from a message-handling bug.

---

## 8. Where to actually go looking

Prioritize these flow types — they're where postMessage shows up because it
*has* to (crossing an origin boundary is the whole point of the flow), not
incidentally:

- **Payment/checkout pages** — PCI segmentation typically forces card-field
  iframes to be on a separate origin from the merchant page, communicating
  state via postMessage.
- **OAuth/SSO popups** — token or auth-code handback from the popup to the
  opener window is almost always postMessage-based.
- **Customer support / live chat widgets** — third-party widget iframe
  talking back to host page.
- **Ad / analytics / tracking iframes** — often invisible (1x1 or
  `display:none`), still fully functional postMessage endpoints.
- **Any explicit "widget" or "embed" product** a company offers for other
  sites to embed — the embed almost certainly uses postMessage to
  communicate back to its own backend/parent context.

---

## 9. Reporting checklist

- [ ] Exact vulnerable file/line or minified-but-located function.
- [ ] The specific origin-check defect, named against §3's taxonomy (or
      "missing entirely").
- [ ] The specific sink, named against §2.3's taxonomy.
- [ ] Root-cause isolation: a negative-control test (fails from a
      non-matching origin) and, if relevant, a filter-bypass isolation test
      (§5 Step 5).
- [ ] PoC HTML (iframe or popup delivery), with placeholders (`example.com`,
      lab/test IDs) clearly marked for the triager to swap in.
- [ ] Screenshot/screen-recording of the PoC firing.
- [ ] Impact statement scoped to what you actually demonstrated — don't
      claim "account takeover" if you only proved `alert(document.domain)`;
      state the escalation path as a reasoned but unconfirmed next step if
      you didn't chain further, and say so explicitly.
- [ ] Suggested remediation:
  ```js
  // Exact-origin allowlist, not prefix/suffix/substring matching:
  const ALLOWED_ORIGINS = ["https://example.com"];
  window.addEventListener('message', function(e) {
    if (!e.isTrusted || !ALLOWED_ORIGINS.includes(e.origin)) return;
    // ... only now touch e.data, and still validate its shape/content
    // before it reaches any sink (URL scheme allowlist for navigation
    // sinks, proper escaping/DOM-safe insertion instead of innerHTML, etc.)
  });
  ```
  Add `"noopener"` to any `window.open` call regardless of the other fixes,
  to remove the reverse-tabnabbing angle independently.

---

## 10. Guard rails for testing on live/production targets

- Confirm the vulnerability class and target are in an active program's
  scope before testing against anything you don't own.
- Use only benign, non-destructive PoC payloads (`print()`,
  `alert(document.domain)`, your own OAST/collaborator callback URL).
- Never exfiltrate real user data, tokens, or PII — even from your own test
  account, prefer proving *capability* (e.g. "this key exists and is
  readable, length N") over transmitting the actual secret anywhere,
  including your own collaborator server.
- Don't chain into destructive account actions or automate repeated requests
  against production infrastructure.
- Don't persist payloads (stored variants) on shared/production state beyond
  what's needed to demonstrate the bug once.
