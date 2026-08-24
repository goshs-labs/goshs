Name:           goshs
Version:        2.1.6
Release:        1%{?dist}
Summary:        Beyond Python's http.server — single-binary file server for pentesters

License:        MIT
URL:            https://github.com/goshs-labs/goshs
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires:  golang

# The binary is built with `-ldflags=-s -w`, which strips all symbol and
# DWARF debug info. There is therefore nothing for Fedora's automatic
# debuginfo/debugsource extraction to collect, which otherwise fails the
# build with an "Empty %%files file debugsourcefiles.list" error.
%global debug_package %{nil}

%description
A single-binary file server for pentesters, CTF players, and sysadmins.

HTTP/S, WebDAV, SFTP, SMB, LDAP/S, NTLM hash capture, DNS/SMTP
callbacks — all from one command, zero dependencies.

Features:
- File sharing: upload/download, drag & drop, QR codes, bulk ZIP, share links
- Protocols: HTTP/S, WebDAV, SFTP, SMB, LDAP/S
- Auth: basic auth, certificate auth, TLS (self-signed, Let's Encrypt, custom)
- Red team: SMB/LDAP NTLM hash capture + cracking, JNDI/Log4Shell,
  DNS/SMTP out-of-band callbacks, reverse shell catcher, redirect endpoint
- Tunnel via localhost.run, webhooks, mDNS, IP allowlist, shell completion

%prep
%autosetup

%build
export CGO_ENABLED=0
go mod download
go build -trimpath -ldflags="-s -w" -o %{name} .

%install
install -Dm 0755 %{name} %{buildroot}%{_bindir}/%{name}

%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}

%changelog
* Mon Aug 24 2026 Patrick Hener <patrickhener@gmx.de> - 2.1.6-1
- Add new version v2.1.6
* Sun Aug 02 2026 Patrick Hener <patrickhener@gmx.de> - 2.1.5-1
- Add new version v2.1.5
* Fri Jul 03 2026 Patrick Hener <patrickhener@gmx.de> - 2.1.4-1
- Add new version v2.1.4
* Thu Jun 25 2026 Patrick Hener <patrickhener@gmx.de> - 2.1.3-1
- Add new version v2.1.3
* Tue Jun 23 2026 Patrick Hener <patrickhener@gmx.de> - 2.1.2-1
- Add new version v2.1.2
* Wed Jun 17 2026 Patrick Hener <patrickhener@gmx.de> - 2.1.1-1
- Add new version v2.1.1
* Fri May 29 2026 Patrick Hener <patrickhener@gmx.de> - 2.1.0-1
- Add new version v2.1.0
* Wed May 27 2026 Patrick Hener <patrickhener@gmx.de> - 2.0.9-1
- Add new version v2.0.9
* Wed May 13 2026 Patrick Hener <patrickhener@gmx.de> - 2.0.8-1
- Add more packaging
* Wed May 13 2026 Patrick Hener <patrickhener@gmx.de> - 2.0.7-1
- Initial COPR package
