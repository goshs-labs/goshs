![Version](https://img.shields.io/github/v/release/goshs-labs/goshs?label=Version&color=green)
[![GitHub License](https://img.shields.io/github/license/goshs-labs/goshs)](https://github.com/goshs-labs/goshs/blob/main/LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/goshs-labs/goshs)
[![GitHub issues](https://img.shields.io/github/issues-raw/goshs-labs/goshs)](https://github.com/goshs-labs/goshs/issues)
[![Downloads](https://img.shields.io/github/downloads/goshs-labs/goshs/total?label=Downloads&color=blue)](https://github.com/goshs-labs/goshs/releases)
[![Stars](https://img.shields.io/github/stars/goshs-labs/goshs?style=flat)](https://github.com/goshs-labs/goshs/stargazers)
![goreleaser](https://github.com/goshs-labs/goshs/workflows/goreleaser/badge.svg)
[![codecov](https://codecov.io/gh/goshs-labs/goshs/branch/main/graph/badge.svg)](https://codecov.io/gh/goshs-labs/goshs)
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/goshs-labs/goshs?label=openssf+scorecard&style=flat)](https://scorecard.dev/viewer/?uri=github.com/goshs-labs/goshs)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13477/badge)](https://www.bestpractices.dev/projects/13477)

<img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-banner-light.png?raw=true" alt="goshs-logo" height="100">

You're mid-engagement. You need to transfer a file, catch an SMB hash, or stand up a quick HTTPS server — and `python3 -m http.server` won't cut it.

**goshs** is a single-binary file server built for the moments when you need more than Python's SimpleHTTPServer but don't want to configure Apache. HTTP/S, WebDAV, FTP/SFTP, SMB, LDAP/S, basic auth, share links, DNS/SMTP callbacks, NTLM hash capture + cracking — all from one command.

![intro](https://github.com/patrickhener/image-cdn/blob/main/goshs.gif?raw=true)

<kbd><img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-screenshot-v2.png?raw=true" alt="goshs-screenshot-light"></kbd>
<kbd><img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-screenshot-v2-dark.png?raw=true" alt="goshs-screenshot-dark"></kbd>

### Demo

**Try it out yourself: [demo.goshs.de](https://demo.goshs.de)**

![goshs-demo](https://github.com/patrickhener/image-cdn/blob/main/goshs-demo.gif?raw=true)

# Quick Start

```bash
# Serve the current directory on port 8000
goshs

# Serve with HTTPS (self-signed) and basic auth
goshs -s -ss -b user:password

# Capture SMB hashes
goshs -smb -smb-domain CORP

# Capture LDAP credentials and NTLM hashes (with optional wordlist cracking)
goshs -ldap
goshs -ldap -ldap-wordlist /usr/share/wordlists/rockyou.txt

# Catch DNS callbacks and receive emails
goshs -dns -dns-ip 1.2.3.4 -smtp -smtp-domain your-domain.com

# Self-destruct after 2 hours
goshs --ttl 2h

# Run with the interactive terminal dashboard (great for headless SSH sessions)
goshs --tui

# Serve payloads that auto-fill your callback host/port at download time
goshs -i 10.10.14.7 --template --tpl-var LPORT=4444
# fetch rendered: curl 'http://10.10.14.7:8000/rev.ps1?tpl'
```

# Documentation

For a detailed documentation go to [docs.goshs.de](https://docs.goshs.de)

# Features

| | |
|---|---|
| 📁 **File Operations** | Download (resumable & seekable via HTTP Range), upload (drag & drop, POST/PUT), delete, bulk ZIP, QR codes |
| 🔌 **Protocols** | HTTP/S, WebDAV, FTP/SFTP, SMB, LDAP/S |
| 🔒 **Auth & Security** | Basic auth, certificate auth, TLS (self-signed, Let's Encrypt, custom cert), IP whitelist, file-based ACLs |
| ⚙️ **Server Modes** | Read-only, upload-only, no-delete, silent, invisible, CLI command execution, TTL self-destruct |
| 🔗 **Share Links** | Token-based sharing, download limit, time limit |
| 🎯 **Collaboration / CTF** | DNS server, SMTP server, SMB NTLM hash capture + cracking, LDAP credential capture + NTLM hash cracking (JNDI mode for Log4Shell), redirect endpoint, Rev Shell Catcher + Payload generator |
| 🧩 **Payload Templating** | Render `{{.LHOST}}`/`{{.LPORT}}` + custom `--tpl-var` values into served files on demand (`?tpl`) |
| 🔔 **Integration** | Webhooks, tunnel via localhost.run, config file, JSON API, mDNS |
| 🖥️ **TUI Dashboard** | Interactive full-screen terminal dashboard; live panes for HTTP, DNS, SMB, LDAP, SMTP, reverse shells and clipboard; attach and upgrade shells from the terminal |
| 🛠️ **Misc** | Dark/light themes, clipboard, self-update, log output, embed files, drop privileges |

# Installation

| Method | |
|---|---|
| 🐧 **curl \| sh** | `curl -sSfL https://goshs.de/install.sh \| sh` |
| 🦫 **Go** | `go install goshs.de/goshs/v2@latest` |
| 🐉 **Kali & Parrot OS** | `sudo apt install goshs` |
| 🎗️ **Arch Linux (AUR)** | `yay -S goshs-bin` |
| 🖤 **BlackArch** | `pacman -S goshs` |
| 🏔️ **Alpine Linux (edge)** | `apk add goshs` |
| 🫙 **Snap** | `snap install goshs` |
| 🎩 **Fedora / RHEL (COPR)** | `dnf copr enable goshs-labs/goshs && dnf install goshs` |
| 🦎 **openSUSE** | `sudo zypper install goshs` |
| ❄️ **Nix / NixOS** | `nix-env -iA nixpkgs.goshs` |
| 🍺 **Homebrew** | `brew install goshs` |
| 🪟 **Scoop** | `scoop bucket add extras && scoop install extras/goshs` |
| 🪟 **winget** | `winget install GoshsLabs.Goshs` |
| 🍫 **Chocolatey** | `choco install goshs` |
| 🐳 **Docker** | `docker run --rm -it -p 8000:8000 -v "$PWD:/pwd" goshs-labs/goshs:latest -d /pwd` |
| 📦 **Release** | [Download from GitHub Releases](https://github.com/goshs-labs/goshs/releases) |

<details>
<summary>🐚 Shell completion</summary>

goshs can install tab completion for bash, fish, and zsh:

```bash
goshs --completion bash
goshs --completion fish
goshs --completion zsh
```

On macOS with Homebrew the correct Homebrew path is used automatically.
After installation the command prints an exact activation instruction, e.g.:

```
source ~/.local/share/bash-completion/completions/goshs
```

</details>

<details>
<summary>🔧 Build yourself</summary>

The bundled web assets are committed, so a plain build just works:

```bash
git clone https://github.com/goshs-labs/goshs.git
cd goshs
go build -o goshs .
```

If you change the JavaScript or SCSS sources, rebuild the assets first with
[esbuild](https://github.com/evanw/esbuild) and [sass](https://sass-lang.com/install) installed:

```bash
make generate
go build -o goshs .
```

</details>

# Code Contributors

[![Contributors](https://contrib.rocks/image?repo=goshs-labs/goshs)](https://github.com/goshs-labs/goshs/graphs/contributors)

# Security Contributors

These are the awesome contributors that made `goshs` even more secure :heart:

<table><tr>
  <td align="center"><a href="https://github.com/marduc812"><img src="https://github.com/marduc812.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/autobot23920"><img src="https://github.com/autobot23920.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/R1ZZG0D"><img src="https://github.com/R1ZZG0D.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/jaisurya-me"><img src="https://github.com/jaisurya-me.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/offset"><img src="https://github.com/offset.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/black-shadow-007"><img src="https://github.com/black-shadow-007.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/anir0y"><img src="https://github.com/anir0y.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/yukikamome316"><img src="https://github.com/yukikamome316.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/tonghuaroot"><img src="https://github.com/tonghuaroot.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/arpitjain099"><img src="https://github.com/arpitjain099.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/manus-use"><img src="https://github.com/manus-use.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/shotintoeternity"><img src="https://github.com/shotintoeternity.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/leanworld7-netizen"><img src="https://github.com/leanworld7-netizen.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/arbor-s"><img src="https://github.com/arbor-s.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/decsecre583"><img src="https://github.com/decsecre583.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/Forrof"><img src="https://github.com/Forrof.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/wooseokdotkim">wooseokdotkim</a></td>
  <td align="center"><a href="https://github.com/Guilhem7">Guilhem7</a></td>
</tr></table>

# Community

Join the Discord Community and start connecting.

[![Join Discord](https://invidget.switchblade.xyz/3ZnskY8HcJ)](https://discord.gg/3ZnskY8HcJ)

# Star History

[![Star History Chart](https://api.star-history.com/chart?repos=goshs-labs/goshs&type=date&legend=top-left&sealed_token=JZUOT38xrIEwfInuMDamZ5UcOjq1_fW_qLnmQ2JaEH1ng6cDwLM5ri6dFhpyYYELzQZd3wNbvATwUX3ZhoQVOA44BJDOgoZjmvY-0w_JPWoyGsyuT3ISKw)](https://www.star-history.com/?repos=goshs-labs%2Fgoshs&type=date&legend=top-left)

# Credits

A special thank you goes to *sc0tfree* for inspiring this project with his project [updog](https://github.com/sc0tfree/updog) written in Python.
