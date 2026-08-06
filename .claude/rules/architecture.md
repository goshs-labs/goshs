# goshs — Project Architecture & Feature Map

> **Purpose of this file.** This is the standing reference for the goshs codebase so
> Claude does **not** have to re-scan and re-analyze the repo every session. It is
> loaded as project instructions on every session start.
>
> **KEEP THIS FILE UPDATED.** Whenever you add/remove a protocol server, a CLI flag,
> a WebUI module, a TUI pane, or change the build/release pipeline, update the
> relevant section here in the same change. If something below turns out to be stale,
> fix it here rather than working around it. Treat drift between this file and the
> code as a bug. Verify a claim against the code before relying on it if it looks old.

---

## What goshs is

goshs is a multi-protocol "rogue server" + file-server toolkit for pentesting / CTF.
It is far more than an HTTP file server: it bundles a whole arsenal of capture and
delivery protocols, a reverse-shell catcher, a payload generator, an OOB collaborator,
and both a Web UI and an interactive terminal UI (TUI) — all driven from one binary.

Module path: `goshs.de/goshs/v2`. Current version lives in
`goshsversion/version.go` (`var GoshsVersion`, currently `v2.1.2`).

---

## Feature / protocol surface

All of these are toggled via CLI flags / config and launched together by
`server.StartAll(opts)` in `server/server.go` (serving goroutines, one per enabled
protocol; no per-protocol stop handles). **Every listening protocol is bound
synchronously first:** each server exposes a `Bind()` method that acquires its
socket(s) and stores them on the struct, and `StartAll` calls `Bind()` before
`go …Start()`, returning `(*Servers, error)`. So a port conflict (or any bind
error) surfaces to `main.go` and is fatal *before* the `--tui` dashboard takes
over the terminal — instead of a serving goroutine calling `logger.Fatalf` →
`os.Exit` behind Bubble Tea's back (which under `--tui` discarded the message and
left the terminal in raw mode needing `reset`) or, for FTP, silently swallowing
the error in the launching goroutine. Each `Start()` still binds lazily if `Bind()`
was not called first, so direct callers keep working. Coverage: `httpserver`
(`FileServer.Bind(what)`, HTTP + WebDAV), `dnsserver` (UDP+TCP, served via
`ActivateAndServe`), `smtpserver`/`sftpserver` (library `Serve(l)`), `ftpserver`
(ftplib `Listen()`+`Serve()`), `smbserver`/`ldapserver` (hand-rolled
`net.Listen`), `tftpserver` (`net.ListenPacket`). `main.go` orchestrates startup;
`sanity` does flag validation + `FurtherProcessing` (e.g. parsing `--tpl-var`).

| Capability | Package | Notes |
|---|---|---|
| HTTP(S) file server, upload, listing, preview | `httpserver/` | Core. Templates + static assets embedded (see Assets). Auth, ACL (`.goshs` dirs), bulk zip download. |
| WebDAV | `httpserver/` (WebDav flag), separate port | `WebDavPort` default 8001 |
| FTP / SFTP | `ftpserver/`, `sftpserver/` | `FTP`, `FTPSFTPMode`, port 2121 |
| TFTP (UDP transfer) | `tftpserver/` | `TFTP`, port 69. Hand-rolled, dependency-free (RFC 1350 + blksize/tsize OACK). RRQ download / WRQ upload, octet only, path-traversal-safe, honours whitelist + ReadOnly/UploadOnly. Registered in mDNS (`_tftp._udp`). |
| SMB (rogue/share + NTLM capture) | `smbserver/` | NTLM hash capture, optional wordlist cracking |
| SMTP (rogue, attachment capture) | `smtpserver/`, `smtpattach/` | port 2525 |
| DNS (rogue) | `dnsserver/` | port 8053 |
| LDAP (rogue + JNDI / log4shell) | `ldapserver/` | `LDAPJNDIEnabled`, NTLM capture + optional wordlist cracking |
| Reverse-shell catcher + listeners | `catcher/` | Session/listener model; surfaced in Web UI catcher + TUI SHELLS pane |
| Reverse-shell payload generator | `assets/js/src/catcher.js` (web) + `tui/generator.go` (TUI) | See "Generator" below |
| OOB callback capture ("HTTP Collaborator") | `assets/js/src/collab.js` | Self-hosted interactsh/requestbin for blind SSRF/RCE/XXE. **Already exists — do not propose building it.** |
| Team chat (web ↔ TUI) | `chat/` | Live, markdown-rendered (+ emoji) message log. Each web browser picks a nickname (localStorage); the TUI authors as `tui@<host>`. In-memory by default; **`--persist-chat`** writes the full log (messages, edit flags, per-emoji reaction authors, monotonic `nextID`) to `<webroot>/.goshs-chat/chat.json` after every mutation and pre-stages it on restart (`chat.Load`/`save`, `persistState`). Web supports **in-place edit** of your own messages (↑ in the composer recalls/cycles your messages; `editMessage`→`chatEdit`, shows `(edited)`), **emoji reactions** (toggle by nickname; `react`→`chatReaction`; `Reactions map[string][]string` on `chat.Message`, rendered server-side via `ChatMessage.ReactionsJSON`→`data-reactions`; the web chip shows a hover tooltip of who reacted), **full `:shortcode:` emoji set** (the Mattermost catalog minus skin-tone variants — ~1800 emoji / ~2300 shortcodes; `generate.py` drops any `unified` containing a Fitzpatrick modifier 1F3FB–1F3FF, keeping the neutral base — generated from `mattermost/webapp/channels/src/utils/emoji.json` by `assets/emoji/generate.py` into the static asset `httpserver/static/js/emoji.json`, fetched at chat init; `chat.js` keeps a tiny built-in fallback if the fetch fails), with **composer autosuggest** and a **searchable reaction picker** (shared `#chat-emoji-picker`, results capped at 180, search matches aliases), **image paste** (inline base64, or written to disk with `--persist-chat-images`), **file upload** (📎 → `POST /?chatUpload` → `.goshs-chat/`, respects `--read-only`, hidden from the dir listing), **collapsible long code blocks** (>10 lines), **own-message highlight** (`.chat-msg.own` when author == nickname; re-evaluated on nick change via `refreshOwnHighlight`), and **opt-in desktop notifications** (Web Notifications API; 🔕/🔔 toggle in the composer, pref in localStorage `goshs-chat-notify`; `maybeNotify` fires for others' messages when the tab is hidden or chat panel inactive). Synced across web clients and the TUI via the ws hub. Evolved from the former shared clipboard. NB: chat messages can inline base64 images, so `ServeWS` raises the coder/websocket read limit to 16 MiB (`wsReadLimit`; the 32 KiB default silently drops such messages). |
| Webhooks (notifications) | `webhook/` | Discord provider; `WebhookEvents` filter |
| Tunneling (public URL) | `tunnel/` | `Tunnel` flag |
| mDNS advertisement | (MDNS flag) | |
| Payload templating | `?tpl` + `--tpl-var KEY=VALUE` | `TemplateVars` → `TemplateVarsParsed` |
| TTL self-destruct | `TTL` duration | server shuts down after duration; TUI shows countdown |
| CLI (non-server) mode | `cli/` | `-c` |
| Config file | `config/` | `-C` |
| Cert generation / CA | `ca/` | self-signed, P12, Let's Encrypt |
| Self-update | `update/` | |
| Websocket hub | `ws/` | pushes live events to Web UI + TUI |
| Interactive terminal dashboard | `tui/` | `--tui`; see "TUI" below |

Full flag/field list is the source of truth in `options/options.go` (`type Options struct`).
Repeatable flags use `stringSliceFlag` (e.g. `--tpl-var`).

### CHECKLIST: adding a new flag / protocol / server

A flag or protocol touches **many** places. Missing any of these ships a
half-wired feature. Use `tftpserver/` (commit that added TFTP) as the reference
example. Work through **all** of these:

**Core (Go):**
1. `options/options.go` — add struct field(s); register flag(s) in `Parse()`
   (give both short + `--long` aliases like the siblings); add a block to the
   `usage()` help text.
2. `config/config.go` — add the field to the `Config` struct (with `json:"…"`
   tag), map it in `LoadConfig` (`opts.X = cfg.X`), and add it to the
   `PrintExample()` default struct.
3. `example/goshs.json.example` — add the JSON key(s) with default value(s).
   (Verify with `go run . -P`.)
4. For a new server: create the `xserver/` package (`New…Server(opts, …)` +
   `Bind() error` + `Start()`). `Bind()` acquires the socket(s) and stores them on
   the struct; `Start()` serves them (and binds lazily if `Bind()` wasn't called).
   Launch it in `server.StartAll` as `if opts.X { if err := srv.Bind(); err != nil
   { return nil, err }; go srv.Start() }` so port conflicts are fatal *before* the
   `--tui` dashboard grabs the terminal (see the StartAll bind note above).
5. `sanity/checks.go` — if it's a noisy/listening server, disable it in the
   invisible-mode block (and update that block's log message).
6. `utils/utils.go` `RegisterZeroconfMDNS(...)` — add a param + a
   `zeroconf.Register` block for the new service, AND update the **call site** in
   `server.StartAll` (the arg list is long and positional).

**UI:**
7. `tui/tui.go` `statusSegments()` — add a segment so the TUI status line shows
   the server when enabled (the pattern: `if o.X { add("<emoji> name :port") }`).
   Note: capture protocols (DNS/SMB/LDAP/SMTP) also have dedicated **panes**;
   transfer protocols (FTP/TFTP) only appear in the status line.
8. Web UI (`assets/js/src/…`) — only if the feature is web-facing; run
   `make generate` afterwards.

**Completions (all three):**
9. `completion/goshs.bash`, `completion/goshs.fish`, `completion/_goshs` (zsh) —
   add the new flag(s) to each. (These have historically drifted; keep them in
   sync.)

**External repos (separate GitLab Pages — see Related repositories):**
10. `goshs-docs` — add/extend a page under `content/usage/<feature>/_index.md`
    and update the flag reference in `content/usage/_index.md`.
11. `goshs-landing` — update `hugo.toml` description, plus `layouts/index.html`
    (meta keywords, the FAQ/answer prose, and the `featureList`).

**Dependencies:** adding a Go module is fine — the COPR build has networking
enabled and `go mod download` works at build time (see Releases). Choose
hand-rolling vs. a dependency on normal engineering merits (footprint, quality,
maintenance), not packaging constraints.

---

## Web UI

- **Hand-edited source** lives in `assets/js/src/*.js` (ES modules) and
  `assets/css/src/main.scss`. Edit these, never the built artifacts.
- **Built artifacts** (do not hand-edit) are committed under
  `httpserver/static/js/main.min.js` and `httpserver/static/css/style.css`.
- **Build step:** `make generate` runs `esbuild assets/js/src/main.js --bundle --minify
  --outfile=httpserver/static/js/main.min.js`, compiles SCSS with `sass`, and copies
  `embedded/` → `httpserver/embedded/`. **You must run `make generate` after editing
  `assets/js/src/` or the SCSS, or the served UI won't reflect your changes.**
- **Embedding:** `httpserver/embed_static.go` (`//go:embed static`) and
  `embed_embedded.go` (`//go:embed embedded`) bake assets into the binary.
- **HTML:** `httpserver/static/templates/index.html` is the served page; it pulls in
  `main.min.js?static`, plus vendored libs (marked, purify, highlight, xterm + addons).
- **Server→JS data passing:** done via `<meta>` tags injected into the template
  (e.g. TTL countdown), read by JS at load. There is no JSON config endpoint for this.
- JS modules of note: `catcher.js` (shells + generator), `collab.js` (collaborator),
  `share.js`, `chat.js`, `files.js`, `preview.js`, `ws.js`, `state.js`,
  `modals.js`, `context-menu.js`, `theme.js`, `cli.js`, `globals.js`, `main.js` (entry).

---

## TUI (`tui/`)

- Entry: `tui.Run(...)` → Bubble Tea model in `tui/tui.go`. 7-pane model with keybinding
  dispatch and tick-based refresh; consumes live events from the ws hub.
- Panes include EVENTS, SHELLS, CHAT (`paneChat`), and **GENERATOR** (`paneGenerator`).
- Colors use the Nord palette constants (`nord4`, `nord7`, …) — do not hardcode ANSI.
- **Password reveal popup:** the status bar shows the auth *user* but never the
  password. Pressing **`p`** (in any pane except GENERATOR, where `p` edits LPORT)
  opens a modal overlay showing the basic-auth credentials — masked with dots
  until **`u`** toggles the plaintext; **`y`/`c`** copy it; **esc/q** close. Handled
  by `handlePasswordKey` (intercepted at the top of `handleKey`, so it's fully
  modal — `q` dismisses the popup instead of quitting) and rendered by
  `passwordPopup()` via `lipgloss.Place` over the body region. Only offered when
  `opts.Password != ""`; a bcrypt-hashed secret is shown but flagged as
  unrecoverable. Useful when the password was generated inline at launch
  (`-b "user:$(xkcdpass …)"`) and is otherwise unknown to the operator.
- Generator pane: `tui/generator.go` + the `generator*` methods in `tui.go`
  (`handleGeneratorKey`, `generatorView`, `generatorList`, `generatorOutput`).
  Keys: ↑↓/jk select, g/G first/last, i LHOST, p LPORT, n cycle encoding,
  y/c copy, q quit. Layout is **stacked vertically** (list on top, output below)
  so the output rows span full width and stay cleanly mouse-selectable.
- Clipboard copy (y/c): `copyToClipboard` writes via **two complementary paths**,
  because neither works everywhere:
  - **Native tool (`nativeCopy`)** — shells out to `xclip`/`xsel` (X11),
    `wl-copy` (Wayland), `pbcopy` (macOS) or `clip` (Windows). On Linux/BSD it
    only runs when a local display is present (`$DISPLAY`/`$WAYLAND_DISPLAY`).
    This is the path that works **locally**: many local emulators
    (gnome-terminal, konsole, plain xterm) do **not** honour OSC 52, so the
    escape sequence alone copies nothing there. On X11/Wayland it fills **both**
    the CLIPBOARD selection (Ctrl+V) and the PRIMARY selection (middle-click /
    Shift+Insert) — two independent writer processes, so the OSC 52
    "two-sequences-break-each-other" caveat does **not** apply here. Best-effort,
    returns bool; a plain SSH session has no display so it no-ops.
  - **OSC 52** — `osc52Seq` builds a sequence for a given buffer; `copyToClipboard`
    stages **two** back-to-back in `m.clipSeq` — system clipboard (`c`) **and** X11
    PRIMARY (`p`) — so both Ctrl+V and middle-click / Shift+Insert paste work over
    SSH. `View()` appends the pair to the frame exactly once then clears it
    (race-free way to reach the terminal under Bubble Tea v1, which has no
    `SetClipboard`). This is the path that reaches the operator **over SSH**, where
    the terminal is remote. **Multiplexers:** under **screen** the sequence is
    wrapped in screen's DCS passthrough (`$TERM` prefix `screen`, and not also in
    tmux). Under **tmux** it is emitted **plain** (no `osc52.Tmux()` wrap): tmux's
    passthrough needs `allow-passthrough on` (off by default, security-gated),
    whereas the far more common `set-clipboard on` makes tmux natively intercept a
    plain OSC 52, set its buffer and relay it out — so `set-clipboard on` is the
    documented tmux requirement (its default `external` blocks in-pane apps).
    Verified on operator terminals: bare kitty over SSH, screen, and tmux with
    `set-clipboard on` all copy both selections; gnome-terminal (no OSC 52) no-ops.
    (Historical note: a prior session found dual `c`+`p` sequences "broke copying"
    and reverted to `c` only; on operator retest that was a false negative — kitty
    over SSH accepts both — so the second sequence is back. If a terminal regresses
    on the pair, that history is why.)
  Both fire on every copy; each is a no-op where it does not apply, so local and
  remote operation are both covered. OSC 52 support is still best-effort (iTerm2,
  kitty, WezTerm, foot, recent xterm); the render path is verified — a real
  bubbletea program (with a window size) does emit the bytes. Dependency:
  `github.com/aymanbagabas/go-osc52/v2`.
- Helpers: `trunc` (guards n<=0), `hardWrap` (safe for width>=1), `padRight`,
  `padLines`, `sepRow` (horizontal divider for the stacked generator).

---

## Generator (dual-maintained — keep in sync!)

The reverse-shell generator exists **twice** and the two copies must stay in lockstep:

- Web: `SHELL_DB` (object) + `updateGeneratorOutput()` in `assets/js/src/catcher.js`.
- TUI: `var shellDB` ([]shellEntry) + `generateCommand()` in `tui/generator.go`.

Both hold the **same 29 payloads in the same order**. Encoding pipeline is identical
and must produce byte-identical output:
- placeholders: `{IP}`/`{ip}` and `{PORT}`/`{port}` (both cases) substituted.
- `none` → raw; `url` → JS-`encodeURIComponent` semantics (unreserved `-_.!~*'()`,
  space→`%20`); `base64` → standard base64.
- Templates prefixed `PS_B64:` are **always** emitted as UTF-16LE → base64 wrapped in
  `powershell -e`, ignoring the encoding selector.

There is currently **no automated test guarding drift** between the two tables. If you
edit one, edit the other in the same change. Tests: `tui/generator_test.go` covers the
Go side's substitution/encoding/keys/view.

---

## Build / test / release

Makefile targets: `generate` (build assets, above), `check` (= `fmt-check` + `vet`),
`fmt`, `vet`, `security`, `run-unit`, `run-unit-no-network`, `run-integration`,
`run-tests`, `run`, `install`, `new-version`, `clean`.

- Standard Go build/test: `go build ./...`, `go test ./...`. The `tui` package has a
  full test suite (`go test ./tui/`).
- `run-unit-no-network` runs the unit tests with network access disabled — useful for
  confirming tests don't depend on outbound connectivity (the COPR build itself now
  has networking, see Releases).
- Code must be `gofmt`-clean and pass `go vet`.

### Releases & packaging
- Packaging lives in `packaging/` (COPR specs) and `snap/`.
- **COPR builds have networking enabled and the debug build disabled.** The spec's
  `go mod download` step works at build time, so adding new Go dependencies is fine
  and no vendoring is needed. (This resolved earlier failures — empty
  `debugsourcefiles.list` with `CGO_ENABLED=0` on fedora-rawhide-aarch64, and
  `go mod download` blocked by network isolation — which are now historical.)

---

## Related repositories (documentation & landing page)

Both are static [Hugo](https://gohugo.io) sites deployed as **GitLab Pages**:

- **Docs:** http://gitlab.com/patrickhener/goshs-docs/ — user-facing documentation.
- **Landing:** http://gitlab.com/patrickhener/goshs-landing/ — project landing page.

When adding/changing a user-visible feature or flag, the docs repo likely needs a
matching update.

> **Docs Hugo version skew:** build/verify docs against the Hugo version **pinned in
> the docs repo's CI**, not whatever Hugo is installed locally (they have diverged
> before — CI was on Hugo 0.154.5, theme "relearn" bumped to 8.3.0). Check the CI
> config in the docs repo for the current pinned version before trusting a local build.

---

## Security-sensitive areas (be careful editing)

- **ACL / auth** in `httpserver/`: `.goshs` per-directory auth/block files,
  `aclSatisfied()` (response-safe ACL checks), `verifyCredentials` (brute-force
  lockout with reset-after-duration), `sanitizePath` (path traversal; deliberately
  does **not** double-URL-decode, to preserve literal `%`/`+` in filenames).
- **Bulk download** zip walker enforces per-file ACL and excludes `.goshs` during the
  recursive walk (regression-tested in `httpserver/bulk_acl_test.go`) — a prior bug let
  parent-dir bulk selection bypass nested `.goshs` auth/block.
- The rogue protocol servers (SMB/LDAP/SMTP/DNS) capture credentials/NTLM by design;
  changes there have real security impact.

---

## Conventions

- Match surrounding code style; keep comments at the density of the file you're in.
- Don't commit/push unless asked; if on `main`, branch first.
- `.ghfs/` is read-only GitHub issues (see `.claude/rules/ghfs.md`); never write to it.
- Persistent cross-session memory & past-work observations: see the user's memory store
  and the claude-mem tooling (the SessionStart context lists recent observation IDs).
