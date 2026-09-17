# DOM-Based Vulnerabilities — Methodology

A reference workflow for finding and exploiting the broader **DOM-based**
vulnerability family during authorized testing: DOM XSS from sources other
than `postMessage`, DOM-based open redirection, DOM-based cookie
manipulation, behavioral fuzzing for undiscovered browser quirks, and DOM
clobbering. Target placeholder throughout: `example.com`.

**Companion documents:**
- [`postmessage-bugbounty-methodology.md`](./postmessage-bugbounty-methodology.md)
  — deep-dive on `postMessage` specifically, one DOM-XSS *source* among
  several covered here. That document assumes you already know the general
  source/sink model taught in §1–2 below.
- [`api-credential-access-control-methodology.md`](./api-credential-access-control-methodology.md)
  — a genuinely different vulnerability class (hardcoded credentials, broken
  backend access control) that sometimes turns up during the same recon pass
  as these do, but needs a different testing discipline. Keep them separate.

**Companion reading:** [PortSwigger's XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
is the payload reference to reach for once you've identified a sink and its
*context* (HTML body, HTML attribute, JS string, URL, CSS) — this document
tells you how to find and prove the sink exists; the cheat sheet supplies the
exact payload shape once you know the context. Use them together. §5 and §7
of this document draw directly on Gareth Heyes' *JavaScript for Hackers* —
its core thesis (don't trust the spec, test the actual engine) is the mindset
underlying everything in those two sections.

**Companion tooling:** Burp Suite's **DOM Invader** extension (built into
Burp's embedded browser) is purpose-built for this exact vulnerability class
— it auto-detects sources/sinks as you browse, and can auto-generate DOM
clobbering payloads for §7. Worth having enabled for every recon pass in this
document; treat it as a first-pass accelerant, not a replacement for manually
reading the code (it will miss custom sinks it doesn't recognize).

---

## 1. What actually makes a vulnerability "DOM-based"

The test that matters, and the one worth applying to *every* finding before
you file it under this methodology: **could this be exploited with zero
server involvement in the vulnerable data flow — no request the server has to
mishandle, just a browser executing client-side script against
attacker-controllable data already sitting in the page/URL/storage?**

- Reflected XSS: server echoes untrusted input into an HTML response — the
  *server* is part of the vulnerable flow.
- Stored XSS: server persists and later serves untrusted input — same.
- **DOM-based XSS: the vulnerable step happens entirely in client-side
  JavaScript, reading data from a browser-side source and writing it into a
  sink, without the server ever seeing or mishandling the payload in that
  request/response pair.** The URL fragment (`#...`) is the canonical
  example — it's never even sent to the server, so no server-side scanner or
  log will ever see the "attack."

This distinction isn't academic — it changes your tooling (server-side
scanners are blind to DOM XSS by construction) and it changes how you
classify findings. If you can reproduce something with `curl` alone, no
browser, it is **not** DOM-based, regardless of where you found the leading
clue (e.g., a hardcoded credential discovered while reading client-side JS is
still not a DOM vulnerability — see the companion access-control doc).

---

## 2. The DOM-XSS source/sink model

Same mental model as the postMessage document's "triangle," generalized: a
**source** (attacker-influenceable data already available client-side) flows,
possibly through some processing, into a **sink** (a JS/DOM API that can turn
a string into executed code, a navigation, a cookie, or a DOM structure).
Every entry in this document is this same shape with a different source
and/or sink.

### 2.1 Sources

| Source | Attacker control | Notes |
|---|---|---|
| `location.hash` | Full — set via URL fragment, **never sent to the server** | The classic DOM-XSS source; also why DOM XSS is often unfixable by a WAF |
| `location.search` | Full — query string | Sent to server too, but often read again client-side for SPA routing |
| `location.href` / `location.pathname` | Full, via navigation | Some apps parse routing info back out of the full URL |
| `document.referrer` | Attacker-controlled if they linked you here; empty under `Referrer-Policy: no-referrer` or cross-origin `noreferrer` links | Easy to overlook as a source since it "feels" server-supplied |
| `document.cookie` | Attacker-controlled if they can set a cookie for the domain (subdomain cookie, or an earlier DOM-cookie-manipulation bug — see §4) | Chainable: one cookie-write bug can seed a second read-side bug |
| `window.name` | Full — persists **across navigations**, including cross-origin ones | Underused source; a same-tab navigation chain can smuggle data in even after leaving the attacker's own page |
| `postMessage` (`e.data`) | Full, from any page that can get the victim to load it | Covered in depth in the companion document |
| `localStorage` / `sessionStorage` | Depends — only directly attacker-controlled if there's a separate injection point (e.g. another XSS, or a same-origin subdomain with looser rules writing to shared storage) | Still worth checking: a low-severity issue elsewhere can become a source for a high-severity sink here |
| DOM-clobbered globals | Full, via injected HTML (no `<script>` needed) | See §7 — the source itself is the attacker's HTML, not a URL/browser API |

### 2.2 Sinks

| Sink | Example | Primitive |
|---|---|---|
| `eval()` / `Function()` / `setTimeout(str, ...)` / `setInterval(str, ...)` | `eval(location.hash.slice(1))` | Direct code execution |
| `document.write()` / `document.writeln()` | `document.write(location.hash)` | Markup injection, executes in document context |
| `.innerHTML` / `.outerHTML` / `insertAdjacentHTML()` | `el.innerHTML = location.hash` | Classic markup-based XSS |
| `location` / `location.href` / `location.assign()` / `location.replace()` | `location = location.hash.slice(1)` | `javascript:` URI execution, or open redirect (§3) |
| `element.src` (`script`, `iframe`, `img`, `object`, `embed`) | `iframe.src = location.hash.slice(1)` | Script load, or `javascript:` navigation for framing-capable elements |
| `document.cookie` (as a **sink**, not just a source) | `document.cookie = "lastPage=" + location.hash` | DOM-based cookie manipulation — §4 |
| jQuery `$()`, `.html()`, `.append()`, `.attr()` | `$(location.hash)` | jQuery's `$()` sink-behavior on strings starting with `<` — a very common real-world variant |
| `Range.createContextualFragment()` | | Parses a string to a DOM fragment — same risk as `innerHTML` |
| `DOMParser.parseFromString()` (with `text/html`) | | Same risk class again |
| `WebSocket(url)` / `XMLHttpRequest.open(method, url)` | | Sink for URL-shaped data — SSRF-adjacent client-side, or protocol-smuggling |

Use §2.1 × §2.2 as a matrix: for any given target, grep for every sink in
§2.2, then trace backward to see if any §2.1 source reaches it, possibly
through several hops of variable assignment/function calls.

---

## 3. DOM-based open redirection

**Shape:** a source (usually a query parameter or hash value — commonly named
`returnUrl`, `redirect`, `next`, `continue`, `dest`) flows into a navigation
sink (`location`, `location.href`, `location.replace()`, `window.open()`)
without validating that the resulting destination stays on the same site.

```js
// example.com's post-login redirect logic:
const params = new URLSearchParams(location.search);
const returnUrl = params.get('returnUrl');
if (returnUrl) {
  location.href = returnUrl; // no validation at all
}
```

### 3.1 Testing methodology

1. Identify the sink (`location`-family assignment) and trace back to its
   source (§2.1) — usually a URL parameter, occasionally a fragment.
2. Try an absolute, fully-attacker-controlled URL first:
   `https://example.com/login?returnUrl=https://attacker.tld` — if that
   redirects off-site with zero validation, you're done (Pattern: no
   validation at all).
3. If there's validation, it commonly assumes **relative paths only** and
   checks something like "does it start with `/`?" — bypass patterns to try,
   roughly in order of how often they work in practice:
   - **Protocol-relative URL:** `//attacker.tld` — starts with `/`, but
     browsers resolve a leading `//` as "same scheme, different host."
   - **Backslash confusion:** `/\attacker.tld` or `\/attacker.tld` — some
     browsers/parsers normalize backslashes to forward slashes *after* the
     validation check ran, but *before* navigation. (This is a directly
     fuzzable claim, not folklore — see §5.3's worked example, which is
     exactly how this specific bypass gets discovered from first principles
     rather than memorized.)
   - **Embedded credentials/userinfo trick:** `https://example.com@attacker.tld`
     — if validation only checks the string *starts with* `https://example.com`,
     this satisfies that naive check while actually navigating to
     `attacker.tld` (the part before `@` is HTTP userinfo, not the host).
   - **Whitespace/control-character prefix:** a leading tab/newline/null byte
     before `https://attacker.tld` sometimes survives a same-origin-prefix
     check that uses `.startsWith()` but gets stripped by the browser's own
     URL parser before navigation.
   - **Open redirect chaining:** if `example.com` itself has *any* other
     legitimate open-redirect endpoint, `returnUrl=/legit-redirect-endpoint?to=https://attacker.tld`
     can satisfy a same-origin check while still ending up off-site after a
     second hop.
4. If the sink also happens to accept a `javascript:` scheme (some
   `location =` assignments do, depending on browser/context), this escalates
   from an open redirect straight into DOM XSS — always test
   `returnUrl=javascript:alert(document.domain)` alongside the redirect
   payloads above, not as a separate pass.

### 3.2 Impact framing

Open redirect alone is often under-valued by programs (many treat it as
informational) — the impact case that gets taken seriously is usually
**chained**: phishing credibility (a redirect through the real, trusted
`example.com` login domain before landing on an attacker page defeats the
"check the URL bar" advice most users are given), or **OAuth/SSO token
theft** if the redirect target is the `redirect_uri`/callback step of an auth
flow — an attacker-controlled final hop there can capture an auth code or
token intended for the legitimate app.

---

## 4. DOM-based cookie manipulation

**Shape:** a source (again, usually `location.hash` or `location.search`)
flows into a `document.cookie` **write**, without sanitizing characters that
have special meaning in the `Set-Cookie`-style grammar the DOM API also
respects — critically, `;` (attribute delimiter).

```js
// example.com stores the last-viewed section in a cookie, sourced from the hash:
document.cookie = "lastSection=" + location.hash.slice(1);
```

### 4.1 Why the `;` matters

`document.cookie = "name=value"` parses the assigned string the same way a
`Set-Cookie` header would — a `;` starts a new attribute (or, positioned
right, a whole new cookie in some parsing contexts). If `location.hash` is
concatenated in unsanitized:

```
https://example.com/#foo; sessionid=attacker-controlled-value
```

can inject a *second* cookie name/value pair (or overwrite an existing
cookie's value if the name collides) purely client-side, no server request
involved. This becomes serious when:
- The overwritten/injected cookie is one the application's **own logic**
  trusts for something (a feature flag, a CSRF token echo, a
  language/locale selector that's later read back into another sink — chain
  this into §2's sink table again once you've landed a value).
- Combined with a **second, separate** DOM-XSS bug elsewhere that reads
  `document.cookie` as its *source* — the cookie-write bug becomes the
  delivery mechanism for the second bug, since you don't need to control the
  page the second bug lives on, just get the victim to visit the
  cookie-writing page once first (cookies persist across page loads on the
  same domain).

### 4.2 Testing methodology

1. Grep for `document.cookie\s*=` (a write, not just `document.cookie` reads)
   and trace what flows into the right-hand side.
2. Confirm whether `;`, `=`, and whitespace are stripped/encoded before the
   assignment. If not, test with a fragment like
   `#x=1; anothercookie=poc` and confirm via DevTools **Application → Cookies**
   panel that a second cookie actually landed.
3. Look specifically for what *other* code reads the cookie you can now
   influence — that's where actual impact lives; the write primitive alone is
   rarely the full story.

---

## 5. Behavioral fuzzing — discovering new primitives

Everything catalogued in §3, §4, and §7 of this document is **pre-discovered
knowledge** — useful for pattern-matching quickly against a target, but
somebody had to find each of those bypasses first by testing the actual
engine rather than reading a spec or a cheat sheet. This section is the
method for generating a *new* bypass when nothing catalogued matches what a
target's filter is doing — the single most useful skill for standing out from
"knows a checklist."

### 5.1 The core method

Loop over every Unicode code point (`0` to `0x10FFFF` — a modern browser
handles this in seconds, not minutes), inject it into one specific position
in a test string, and use an **observable detector** to check whether that
character produced the behavior you're probing for. The skill is picking the
right detector for what you're testing — five reusable patterns:

| Testing... | Detector | Why it works |
|---|---|---|
| Characters inside/around a `javascript:` URL | `anchor.protocol === 'javascript:'` | The DOM normalizes the parsed protocol — if it reports `javascript:`, the browser will honor it on click/navigation |
| Characters inside an HTTP(S) or protocol-relative URL | `anchor.hostname === 'expected.host'` | If the hostname still parses to the expected value around your injected character, that character didn't break URL parsing |
| Characters inside HTML (comments, tags) | `div.querySelector('span')` present/absent after `innerHTML` write | innerHTML actually renders the DOM tree — a following element rendering (or not) proves your character opened/closed a construct |
| "Known behavior" candidates (whitespace, string/regex delimiters, comment syntax) | `eval(...)` throws or not, inside `try/catch` | A thrown error means the character didn't behave as hypothesized; silent success confirms it |
| Characters inside escape sequences (`\u{}`, hex) | Same `eval` + reference-to-a-declared-variable trick | No `ReferenceError` means the escape sequence resolved to your variable's name — proves the engine accepted a non-obvious encoding |

### 5.2 Fuzzing JavaScript URLs

```js
let log = [];
let anchor = document.createElement('a');
for (let i = 0; i <= 0x10ffff; i++) {
  anchor.href = `javascript${String.fromCodePoint(i)}:`;
  if (anchor.protocol === 'javascript:') log.push(i);
}
console.log(log); // e.g. 9,10,13,58 — tab, LF, CR, and the colon itself
```

Move the placeholder to fuzz a different position — e.g. *before* the scheme
(`${String.fromCodePoint(i)}javascript:`) surfaces a much larger accepted set
(whitespace variants, NULL at position 0 — **DOM-only**, doesn't work in raw
HTML via entity, so always verify a DOM-discovered result in both contexts;
see §5.4).

### 5.3 Fuzzing HTTP and protocol-relative URLs

```js
let a = document.createElement('a');
let log = [];
for (let i = 0; i <= 0x10ffff; i++) {
  a.href = `${String.fromCodePoint(i)}https://example.com`;
  if (a.hostname === 'example.com') log.push(i);
}
```

Same technique against the inside of a protocol-relative URL's double slash
(`/${char}/example.com`) is what actually *proves* — rather than asserts from
memory — the "backslash confusion" open-redirect bypass in §3.1: fuzzing this
position surfaces that whitespace characters **and the backslash** both
satisfy `a.hostname === 'example.com'`, because the browser normalizes `\` to
`/` during URL parsing. This is the exact mechanism behind that bypass, not a
coincidence — worth running yourself once rather than taking the catalogued
entry on faith.

### 5.4 Fuzzing HTML via `innerHTML`

```js
let log = [];
let div = document.createElement('div');
for (let i = 0; i <= 0x10ffff; i++) {
  div.innerHTML = `<!----${String.fromCodePoint(i)}><span></span>-->`;
  if (div.querySelector('span')) log.push(i);
}
console.log(log); // Chrome: 33,45,62 → ! - >
```

Same idea run the other direction (check the span is **absent**, with the
placeholder inside the *opening* comment tag `<!-${char}- >...`) finds
opening-tag quirks instead of closing-tag quirks — different browsers
diverge here (a documented finding: Firefox has historically accepted
newlines before the closing `>` where Chrome didn't), which is itself the
whole point — **cross-browser testing, not single-browser testing, is what
DOM Invader and ad-hoc fuzzing are both for.**

**Important defensive-coding note for your own fuzz vectors:** guard against
false positives in the surrounding markup. In the example above, the
deliberate `>` right after the space-hyphen in the opening-tag variant exists
specifically so a "successful" character doesn't get misread as the `<span>`
being consumed as a different, unintended tag. Bad fuzz-vector construction
wastes far more time than it saves.

**DOM properties vs. `innerHTML`/raw HTML are genuinely different code
paths — always test both.** A character that works when set via a DOM
property (`anchor.href = ...`) is not guaranteed to work identically via
HTML-entity encoding in markup (`<a href="&#0;javascript:...">`), and vice
versa. NULL is the standing example: valid in the DOM path, silently
rejected via HTML entity in raw HTML. Never generalize a DOM-fuzz result to
an HTML-injection context (or the reverse) without confirming separately.

### 5.5 Fuzzing "known" behaviors (whitespace, strings, comments)

```js
function x(){}
let log = [];
for (let i = 0; i <= 0x10ffff; i++) {
  try { eval(`x${String.fromCodePoint(i)}()`); log.push(i); } catch(e) {}
}
// Chrome: a long list including 160, 5760, 8192-8203, 8232, 8233, 8239, 8287,
// 12288, 65279 — far beyond ASCII space/tab/newline
```

Useful directly for **filter-bypass discovery**: a naive character blacklist
that only blocks ASCII whitespace misses every one of these Unicode
lookalikes. This is a *different* mechanism from the parenthesis-free
`ToPrimitive` technique in the postMessage document's §3.8 — that technique
removes `(`/`)` entirely; this one keeps them and instead defeats a
whitespace-only filter. Know both; they apply to different filter shapes.

The same `eval`+`try/catch` detector, applied to a *pair* of identical
characters surrounding junk content, finds string/regex delimiters:

```js
let log = [];
for (let i = 0; i <= 0x10ffff; i++) {
  try { eval(`${String.fromCodePoint(i)}%$£234${String.fromCodePoint(i)}`); log.push(i); } catch(e) {}
}
// 34, 39, 47, 96 → " ' / ` (double/single quote, regex delimiter, template literal)
```

And **nested fuzzing** (two loops, two code points — expensive, so
range-limit to keep it tractable) finds multi-character sequences, e.g. the
genuinely obscure discovery that `#!` (shebang, chars 35/33) acts as a
single-line comment **only** when it's the very first thing in the script —
a Node.js-shell-script compatibility quirk with zero presence in any
JavaScript specification, findable only by testing the actual engine.

### 5.6 Fuzzing escape sequences

```js
let a = 123;
let log = [];
for (let i = 0; i <= 0x10ffff; i++) {
  try { eval(`\\u{${String.fromCodePoint(i)}0061}`); log.push(i); } catch(e) {}
}
// 48 → the engine accepts zero-padding inside \u{} unicode escapes
```

Swap the placeholder to fuzz hex digits directly (`i.toString(16)`), or a
character positioned *before* a fixed hex value, to map exactly what an
engine's escape-sequence parser tolerates beyond the strict spec grammar —
directly useful for smuggling an identifier (e.g. a blacklisted function
name) past a filter that only pattern-matches the literal, un-escaped text.

### 5.7 Verifying results

Always manually reconstruct a positive hit before relying on it — pick a
result at random, build the minimal real DOM/HTML for it, and confirm by
hand:

```js
let anchor = document.createElement('a');
anchor.href = `${String.fromCodePoint(12)}javascript:alert(1337)`;
anchor.append('Click me');
document.body.append(anchor);
```

For repeated verification across many hits, or across multiple browsers,
automate this step (Puppeteer/Playwright) rather than clicking through each
one by hand.

---

## 6. Obtaining the `window` object when it's not directly accessible

Relevant specifically to **JS-sandbox-escape and restricted-execution-context
scenarios** — you have *some* code execution (a limited eval sandbox, an
event-handler attribute, a scoped callback) but `window`/global scope isn't
directly reachable, and you need it to reach real sinks (`eval`, `alert`,
`fetch`, etc.). This escalates a constrained DOM-XSS primitive into full
script execution.

### 6.1 Standard aliases

`frames`, `globalThis`, `parent`, `self`, `top` — all reference `window` in
an unframed page. Framing changes the semantics: `top` always points to the
outermost window regardless of cross-origin framing; `parent` points
specifically to the immediate parent frame.

### 6.2 From any DOM node

```js
document.defaultView.alert(1337);          // document → window
node.ownerDocument.defaultView.alert(1337); // any node → its document → window
```

`ownerDocument` exists on every DOM node; chaining `.defaultView` off it is
the general-purpose "I have a node reference, I want `window`" primitive —
useful whenever a sandbox specifically blocks direct `window`/`self`/`top`
access but hands you a node reference (e.g. `this` inside an event handler,
or a DOM element returned from a sandboxed API).

### 6.3 Via the event object

```html
<img src onerror=event.path.pop().alert(1337)>          <!-- Chrome-specific -->
<img src onerror=event.composedPath().pop().alert(1337)> <!-- standard, cross-browser -->
```

`composedPath()` returns the full event-propagation path as an array; the
**last element is always the `window` object**, so `.pop()` grabs it
directly. Prefer `composedPath()` over the Chrome-only `path` property for
anything meant to be reliable across browsers.

**SVG elements are a special case** worth knowing purely because it
demonstrates *how* to find this kind of quirk yourself: SVG event handlers
receive the event as `evt`, not `event` — a legacy naming inconsistency.

```html
<svg><image href=1 onerror=evt.composedPath().pop().alert(1337)></svg>
```

The way to *discover* this (rather than just memorize it) is to print the
handler function's own source from inside itself:

```html
<svg><image href=1 onerror=alert(onerror)></svg>
```

which reveals `function onerror(evt) { ... }` — the parameter name is right
there in the stringified function. This is a generally useful technique any
time you suspect a handler's local-scope argument name might differ from the
conventional one: ask the function to print itself.

### 6.4 Via `Error.prepareStackTrace` (Chrome)

```js
Error.prepareStackTrace = function(error, callSites) {
  callSites.shift().getThis().alert(1337);
};
new Error().stack; // accessing .stack triggers the callback
```

`CallSite.getThis()` returns `window` when the executing code has no
explicit `this` binding — a Chrome-specific but powerful primitive when
other access paths are blocked.

### 6.5 Implicit scoping inside HTML event handlers

An inline event-handler attribute is executed roughly as if wrapped in:

```js
with (document) {
  with (element) {
    // your handler code
  }
}
```

This is *why* `defaultView` works bare, unqualified, inside an `onerror=`
attribute — the browser checks the element first (not found), then falls
back to `document` (found):

```html
<img/src/onerror=defaultView.alert(1337)>
```

The same scoping lets you chain DOM-construction calls without fully
qualifying each one:

```html
<img/src/onerror=s=createElement('script');s.append('alert(1337)');appendChild(s)>
```

One sharp edge worth remembering: `appendChild()` here executes on the
**image element**, not `document` — even though `document` also has an
`appendChild` method, the element (checked first by the `with` scoping)
takes precedence. `append()` (note: not `appendChild`) would throw in this
exact position on Chrome if called unqualified for a similar reason — when
chaining shorthand DOM calls inside a handler, verify which object in the
scope chain actually owns the method you're calling, don't assume.

---

## 7. DOM clobbering — thinking like the parser, not the developer

This is the section most directly in the spirit of *JavaScript for
Hackers*-style thinking: the bug isn't in application logic at all, it's in
a browser behavior most developers don't know exists, which is exactly why
it survives in production code that looks completely safe on read-through.

### 7.1 The core mechanic: named access on `window` and `document`

When the HTML parser encounters an element with an `id` or `name` attribute,
the browser can create a **global reference** to it automatically — **before
any `<script>` on the page has executed a single line.** The two attributes
behave differently, and the difference matters for how deep you can clobber:

- **`id`** creates a global on `window` only.
- **`name`** creates a global on `window` **and** a property on `document` —
  but only for a specific set of elements (`embed`, `form`, `iframe`, `img`,
  `object`, and a couple of others depending on browser — verify the current
  set for your target browser rather than assuming a fixed list, per §5's
  whole thesis).

```html
<form id=x></form><form name=y></form>
<script>
  alert(x);                 // [object HTMLFormElement] — id → window only
  alert(typeof document.x); // "undefined" — id does NOT reach document
  alert(y);                 // [object HTMLFormElement] — name → window
  alert(document.y);        // [object HTMLFormElement] — name → document too
</script>
```

```js
// The vulnerable pattern this whole technique targets:
let url = window.currentUrl || 'https://example.com/default';
```

`window.currentUrl` looks developer-controlled here, but it's equally
satisfiable by `<form name=currentUrl>` (or `<img name=currentUrl>`, etc.)
anywhere earlier in the page's HTML — no `<script>` tag required, which is
exactly why this survives sanitizers that only strip script tags and
`on*=` handlers.

### 7.2 Getting an attacker-controlled *string* out of the clobber

A bare clobbered form/img element stringifies to `[object HTMLFormElement]`
— not directly useful as attacker-controlled text. **Anchor elements are
different: their `toString()` returns the resolved `href`.**

```html
<a href="clobbered:1337" id=x></a>
<script>
  alert(x);         // "clobbered:1337" — used as a string
  alert(typeof x);  // "object" — it's still the anchor element itself
</script>
```

This is why anchors are the primary primitive for **value injection**
specifically, while forms/inputs are used for **structural** (multi-level
property-path) clobbering — see §7.3. Also worth remembering: you can only
read *known HTML attributes* this way (`x.title` works, `x.notAnAttribute`
does not) — the clobber rides on real DOM property getters, it isn't
arbitrary property injection.

### 7.3 Multi-level property paths

**Via duplicate `id`/`name` → collections.** Multiple elements sharing an
`id` form an `HTMLCollection` rather than clobbering each other away; a
second element in that collection can then be addressed either by its own
`name` or by numeric index:

```html
<a id=x></a>
<a id=x name=y href=clobbered:1337></a>
<script>alert(x.y);   // "clobbered:1337"</script>
```
```html
<a id=x></a>
<a id=x name=y href=clobbered:1337></a>
<script>alert(x[1]);  // "clobbered:1337" — same result, by index</script>
```

**Anchors max out at two named levels.** A third same-`id` anchor is only
reachable by index (`x[2]`), not by a third `name` — `name` doesn't
contribute a second collection layer. For a genuine three-level property
path (`x.y.z`), switch to nested form/input elements:

```html
<form id=x name=y><input id=z></form>
<form id=x></form>
<script>alert(x.y.z);</script>  // "[object HTMLInputElement]" — structure works,
                                 // but the *string value* reverts to the object
                                 // stringification, since input isn't an anchor
```

To get a genuinely attacker-controlled **string** four levels deep, read a
specific attribute-mapped property off the final node rather than the node
itself:

```html
<form id=x name=y><input id=z value=1337></form>
<form id=x></form>
<script>alert(x.y.z.value);  // "1337"</script>
```

**For unlimited depth, use `iframe` + `srcdoc` + `name`.** An iframe's
`name` clobbers with the iframe's own `window` object (not just an element),
and if the `srcdoc` content is same-origin (it is, by default), you can
recurse — clobber further levels *inside* the iframe's own document. The one
practical wrinkle: `srcdoc` content takes a moment to render, so a script
reading the nested clobbered value immediately may see it as `undefined`
before rendering completes. A cross-origin `@import` in a `<style>` block is
a reliable, if unintuitive, way to introduce just enough delay:

```html
<iframe name=foo srcdoc="<a id=bar href=clobbered:1337></a>"></iframe>
<style>@import 'https://example.com';</style>
<script>
  alert(foo);      // [object Window] — the iframe's own window
  alert(foo.bar);  // "clobbered:1337" — now resolved, thanks to the render delay
</script>
```

Nesting this pattern (iframe inside iframe, each with its own `srcdoc`) lets
you clobber arbitrarily many levels deep (`a.b.c.d.e...`), at the cost of
needing HTML-entity-encode the inner `srcdoc` content progressively (once per
nesting level, since each level of unescaping consumes one layer of
encoding) — useful to know the mechanism exists; work out the exact encoding
depth needed for your specific target rather than reusing a fixed template,
since it's sensitive to exactly how many levels you need.

### 7.4 Filter exploitation — clobbering the *filter's own* introspection

Distinct use-case from value injection: clobber a property a **client-side
sanitizer/filter itself** relies on to make a security decision, so the
filter's logic silently no-ops or checks the wrong thing. Three concrete,
high-value targets:

**Clobbering `.attributes` to defeat an attribute-stripping loop:**
```html
<form id=x onclick=alert(1) onmouseover=alert(2)>
  <input name=attributes>  <!-- clobbers the form's .attributes property -->
</form>
<script>
  // A filter loop like this silently does nothing once .attributes is clobbered,
  // because the clobbered value's .length is undefined:
  for (let i = document.getElementById('x').attributes.length - 1; i >= 0; i--) { ... }
</script>
```
The dangerous `onclick`/`onmouseover` attributes on the form survive
untouched, because the removal loop never iterates.

**Clobbering `.tagName`/`.nodeName` to defeat a tag blocklist:**
```html
<form id=x>
  <input name=nodeName>
</form>
<script>
  alert(document.getElementById('x').nodeName); // "[object HTMLInputElement]", not "FORM"
</script>
```
A filter checking `element.nodeName === 'FORM'` (or similar) to block/strip
form elements reads the clobbered value instead and never recognizes the
element as one it should act on.

**Clobbering `.parentNode` / `.nextSibling` / `.previousSibling` to defeat
DOM-traversal-based filters:** the same principle — any filter that walks
the tree using these properties to decide what to sanitize can be misdirected
to check/clean the wrong nodes entirely, by clobbering the traversal
properties on the node the filter is currently inspecting.

**The general lesson for §7.4:** any client-side sanitizer that reads DOM
properties (`.attributes`, `.tagName`, `.nodeName`, `.parentNode`,
`.children`, etc.) via a bare property access on an element **you can inject
markup into or near** is a candidate — the fix is always the same (use
`Object.getPrototypeOf(el).attributes` or equivalent to bypass an own-property
shadow, or a hardened library like DOMPurify that's specifically built to
resist this), but finding the specific vulnerable read requires reading the
filter's actual implementation, not guessing.

### 7.5 What to look for as tells (fast triage before deep-diving)

- Client-side code with `typeof X === 'undefined'` / `X = X || {}` /
  `if (!window.X)` guard patterns, especially around config objects,
  feature flags, or anything loaded conditionally.
- Any client-side HTML sanitizer/cleaner that isn't a well-known hardened
  library (DOMPurify et al. handle clobbering-adjacent cases deliberately) —
  homegrown sanitizers are the highest-yield target for §7.4.
- An HTML injection point that strips `<script>` and `on*=` handlers but
  permits `id`/`name` attributes on otherwise-"safe" tags (`<a>`, `<form>`,
  `<img>`) — this is the actual prerequisite that makes clobbering reachable
  at all; without *some* HTML injection point, there's nothing to clobber
  with.

---

## 8. Recon toolkit for this whole family

Builds on the postMessage document's §4, generalized:

1. **DOM Invader** (Burp's embedded browser) — enable it, browse the target
   normally, let it flag sources/sinks and offer to auto-test DOM clobbering
   candidates. Fastest first pass across a whole app.
2. **Manual sink-grepping**, expanded beyond `postMessage`:
   ```bash
   grep -nE "\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\(" -r ./bundle/
   grep -nE "document\.write(ln)?\(" -r ./bundle/
   grep -nE "\beval\(|new Function\(" -r ./bundle/
   grep -nE "location(\.href)?\s*=|location\.(assign|replace)\(" -r ./bundle/
   grep -nE "document\.cookie\s*=" -r ./bundle/
   grep -nE "typeof\s+\w+\s*===?\s*['\"]undefined['\"]" -r ./bundle/  # clobbering-guard candidates
   grep -nE "\.attributes\b|\.nodeName\b|\.tagName\b|\.parentNode\b" -r ./bundle/  # filter-clobbering targets
   ```
3. **DevTools breakpoints beyond Event Listener Breakpoints:** "DOM Change
   Breakpoints" (right-click an element → Break on → subtree/attribute
   modifications) catch dynamic `innerHTML` writes you can't easily grep for
   in heavily-templated frameworks; "URL Change" / hash-change listeners for
   SPA-routed `location.hash` sinks.
4. **View-source / Sources pretty-print** as always — DOM clobbering and
   window-access candidates specifically reward reading the *whole* file for
   guard-pattern variable names and scoping quirks, not just grepping sink
   function calls, since the vulnerable line (the guard) and the dangerous
   line (the sink) are often far apart in the same file.
5. **Behavioral fuzzing (§5)** — when nothing above surfaces a working
   bypass against a target's specific filter, this is the fallback: run the
   relevant detector loop against the actual filter/browser in question
   rather than assuming a catalogued bypass transfers unchanged.

---

## 9. Suggested lab progression

Roughly ascending difficulty, matching PortSwigger's own tiering — useful as
a study order if you're building this skill systematically alongside
*JavaScript for Hackers*:

1. **DOM XSS, direct sink** (`location.hash` → `eval`/`innerHTML`) — confirms
   the basic source/sink model.
2. **DOM XSS using web messages** (`postMessage` as source) — see companion
   document; same sink types, different source, adds origin-validation
   reasoning on top.
3. **DOM-based open redirection** (§3) — same source/sink model, but the sink
   is navigation rather than code execution; teaches URL-parsing-mismatch
   thinking (browser vs. naive string check) that recurs constantly, and is
   directly fuzzable (§5.3).
4. **DOM-based cookie manipulation** (§4) — introduces sink-as-source
   chaining (a write bug becomes a read bug's delivery mechanism).
5. **DOM clobbering — enabling XSS** (§7.3) — requires holding two
   simultaneous mental models (parser-time HTML behavior + runtime JS
   variable resolution) rather than just source→sink tracing; the jump in
   PortSwigger's own difficulty rating (Practitioner → Expert) reflects that.
6. **DOM clobbering — bypassing HTML filters** (§7.4) — hardest variant:
   requires understanding *both* the application's intended sanitizer logic
   *and* the clobbering primitive well enough to attack the sanitizer's own
   assumptions, not just application business logic.

Study §6 (getting `window`) and §5 (behavioral fuzzing) alongside this
progression rather than after it — they're the escalation and discovery
skills that turn a constrained DOM-XSS primitive (§1-4) into full script
execution, and the method for finding entirely new primitives when a
target's specific filter doesn't match anything above.

---

## 10. Reporting checklist

- [ ] Exact source (§2.1) and sink (§2.2), named against this document's
      taxonomy.
- [ ] For open redirect: which specific bypass class (§3.1) worked — "no
      validation," "protocol-relative," "userinfo trick," etc. — named
      explicitly, not just "bypassed the filter."
- [ ] For cookie manipulation: the injected cookie's actual downstream
      effect (what reads it, and what changes because of the injected
      value) — a bare "I can set an arbitrary cookie" without a consumer is
      a weak report on its own.
- [ ] For DOM clobbering: **both** halves of the chain — the HTML injection
      point that delivers the clobbering markup, *and* the guard/sink pair
      (§7.3) or filter-introspection property (§7.4) it defeats. A clobbering
      PoC with no realistic injection point isn't reportable as-is; note
      explicitly if the injection point is itself a separate, already-known/
      reported issue you're chaining into.
- [ ] For a window-access-escalation chain (§6): the specific constrained
      context you started from (which sandbox/handler/scope), and exactly
      which alias/property chain reached `window` from there.
- [ ] For a novel bypass found via behavioral fuzzing (§5): the exact fuzz
      vector and detector used, plus a manually-reconstructed, verified PoC
      (§5.7) — don't report a raw fuzzer hit without hand-verifying it fires.
- [ ] PoC HTML, `example.com` placeholders clearly marked.
- [ ] Screenshot/recording of the PoC firing, plus (for clobbering
      specifically) a DevTools console screenshot showing the clobbered
      global's actual runtime value/type — this is often the single most
      convincing piece of evidence for a triager unfamiliar with the
      technique, since it makes the "the browser did this, not a script"
      point concrete.
- [ ] Suggested remediation, tailored to the specific bug:
  - Open redirect: validate against a strict allowlist of destinations, or
    require relative paths and reject anything containing `//`, `\`, or a
    scheme.
  - Cookie manipulation: encode/strip `;`, `=`, and control characters
    before any `document.cookie` write built from page-controlled data.
  - DOM clobbering (value injection): use `Object.create(null)` or a
    `const`/`let` module-scope binding instead of an implicit-global/`var`
    pattern that's shadowable by named DOM access in the first place; never
    trust `typeof x === 'undefined'` as proof `x` is safe to initialize —
    check `x instanceof ExpectedType` or similar instead.
  - DOM clobbering (filter bypass): don't read security-relevant DOM
    properties as bare own-property access on attacker-influenceable
    elements — use a hardened sanitizer library, or explicitly read via the
    prototype to bypass own-property shadowing.

---

## 11. Guard rails for testing on live/production targets

Same as the postMessage document's §10 — confirm scope, use benign
non-destructive PoCs (`alert(document.domain)`, `print()`, your own
OAST/collaborator callback), don't exfiltrate real data, don't persist
stored-XSS-shaped payloads on shared production state beyond what's needed
to prove the bug once. Behavioral fuzzing (§5) specifically should be run
against your own local test pages / a lab environment first — only carry a
verified, minimal, hand-reconstructed PoC (§5.7) to a live target, never a
raw fuzzing loop.
