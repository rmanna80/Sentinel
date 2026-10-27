# Checks

Generated from the agent's registry by `scripts/gen_checks_doc.py`. Every check is read-only. "Admin" checks are skipped (and listed with that reason) unless you run an elevated scan.

## Posture

| Check | Platforms | Admin | What it reads |
| --- | --- | --- | --- |
| `diag.resources` — System resources and uptime | Linux, Windows | No | CPU and memory use, disk space per drive, and time since last boot |
| `linux.accounts` — Only root has administrator user id 0 | Linux | No | User names, user ids and login shells from /etc/passwd (no password hashes; /etc/shadow is never read) |
| `linux.firewall` — A host firewall is active | Linux | Yes | Whether ufw is active (`ufw status`), or else the nftables ruleset (`nft list ruleset`) |
| `linux.ssh_config` — The SSH server does not allow root or password sign-ins | Linux | No | Sign-in settings (PermitRootLogin, PasswordAuthentication, KbdInteractiveAuthentication, PubkeyAuthentication, PermitEmptyPasswords, Port, ListenAddress) from /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf |
| `linux.unattended_upgrades` — Security updates install automatically | Linux | No | The APT::Periodic::Unattended-Upgrade setting from the files in /etc/apt/apt.conf.d |
| `linux.updates` — Package updates are installed | Linux | No | Names, versions and source suites of packages with an available update (from APT's cached lists), and whether the system flags that a restart is required (with the packages that asked for it) |
| `net.dns_config` — DNS servers are configured | Linux, Windows | No | The DNS server addresses configured per network adapter (Windows) or in /etc/resolv.conf (Linux) |
| `net.interfaces` — Network interfaces | Linux, Windows | No | Name, up/down state, speed, MTU and addresses of each network interface |
| `net.listening` — No risky services are listening for network connections | Linux, Windows | No | Local addresses, ports, process ids and process names of listening TCP and UDP sockets |
| `net.unusual_outbound` — No unusual outbound connections | Linux, Windows | No | Local and remote addresses, ports and process names of established TCP connections |
| `proc.suspicious_locations` — No programs are running from temporary or download folders | Linux, Windows | No | Process ids, names, program paths and owning user of running processes |
| `win.accounts` — Local accounts and administrators | Windows | No | Names, SIDs and enabled/password-required flags of local user accounts with their last password change and last sign-in times, the members of the local Administrators group, and which account runs the agent |
| `win.bitlocker` — The system drive is encrypted | Windows | Yes | Encryption status, percentage, method, protection status and key protector types of the system drive (from Get-BitLockerVolume, or manage-bde -status C: when the BitLocker module is unavailable) |
| `win.defender.status` — Microsoft Defender Antivirus is protecting this PC | Windows | No | Microsoft Defender's on/off states (service, antivirus, real-time protection, tamper protection), the age and date of its virus definitions, its running mode, and the names and state codes of antivirus products registered with Windows Security Center |
| `win.firewall.profiles` — Windows Firewall is on for every profile | Windows | No | On/off state and default inbound action of the Domain, Private and Public firewall profiles |
| `win.lsa_protection` — LSA protection guards stored credentials | Windows | No | The RunAsPPL, RunAsPPLBoot and LsaCfgFlags values of the LSA registry key |
| `win.network_profile` — Connected networks are classified | Windows | No | Name, adapter, Public/Private category and connectivity of each connected network |
| `win.os.updates` — Windows updates are being installed | Windows | No | The last 100 entries of the Windows Update history (update title, date, result and whether it was an install or uninstall) and the start type of the Windows Update service |
| `win.password_policy` — Local accounts lock out after repeated wrong passwords | Windows | No | The local password and lockout policy shown by `net accounts` (no account names or passwords) |
| `win.rdp` — Remote Desktop is off or requires Network Level Authentication | Windows | No | Whether Remote Desktop connections are allowed (fDenyTSConnections), whether Network Level Authentication is required (UserAuthentication) and the listening port (PortNumber) |
| `win.secureboot` — Secure Boot is on | Windows | Yes | Whether UEFI Secure Boot is on, off or unsupported (Confirm-SecureBootUEFI) |
| `win.smartscreen` — SmartScreen checks downloaded apps | Windows | No | The SmartScreenEnabled value under Explorer settings and the EnableSmartScreen group policy value |
| `win.startup` — Programs that start automatically look legitimate | Windows | No | Names and command lines of programs registered under the Run and RunOnce registry keys (machine-wide, 32- and 64-bit, and for the current user) and the file names in the two Startup folders |
| `win.uac` — User Account Control prompts before elevation | Windows | No | EnableLUA, ConsentPromptBehaviorAdmin and PromptOnSecureDesktop registry values |
| `win.wifi_security` — The connected Wi-Fi network is secured | Windows | No | For each Wi-Fi adapter: its name and connection state, and for a connected network its name (SSID), authentication, cipher, radio type and profile name |

## Inventory

| Check | Platforms | Admin | What it reads |
| --- | --- | --- | --- |
| `dev.dependencies` — Dependencies of your development projects | Linux, Windows | No | Package names and exact versions from requirements.txt and package-lock.json in the project folders you configured (nothing else in those folders is read) |
| `dev.secrets` — No secrets or risky config are committed in your projects | Linux, Windows | No | File names and matched line numbers in your configured project folders; the matched secret values themselves are never stored. |
| `linux.packages` — Installed packages | Linux | No | Names and versions of installed packages from dpkg (or rpm); on Debian and Ubuntu, listed by source package as security advisories are |
| `win.os.inventory` — Windows version | Windows | No | Windows name, edition, version and build number (already known to the agent) |
| `win.software.inventory` — Installed programs | Windows | No | Name, version, publisher and install date of programs listed in the Uninstall registry keys (machine-wide 64- and 32-bit, and the current user's) |

## Logs

| Check | Platforms | Admin | What it reads |
| --- | --- | --- | --- |
| `linux.logs.auth` — SSH and sudo activity from the system journal | Linux | No | Journal entries from sshd and sudo: time, account name, source IP, sign-in method, and the commands run with sudo |
| `win.logs.defender` — Microsoft Defender log: detections and protection changes | Windows | No | Microsoft Defender events for malware detections (threat name, file path, severity), actions taken, real-time protection being turned off and configuration changes |
| `win.logs.security` — Windows Security log: sign-ins and account changes | Windows | Yes | Security log events for sign-ins (successful, failed, explicit credentials, admin privileges), account creation, enabling, password resets, group membership changes, lockouts, service and scheduled-task installs, and audit log clearing: time, account names, source IP, logon type and the program involved |
| `win.logs.system` — Windows System log: new services, log clearing and crashes | Windows | No | System log events for new services (name, program path, start type, account), log clearing, unexpected shutdowns, and start-type changes of Microsoft Defender, Windows Update and the firewall service |

## Network (needs targets in scope)

| Check | Platforms | Admin | What it reads |
| --- | --- | --- | --- |
| `net.http_headers` — Web pages send security headers | Linux, Windows | No | For the URLs you entered: the HTTP status code and response headers (the page body is not read) |
| `net.nmap_discovery` — Network discovery (Nmap) | Linux, Windows | No | For the targets you entered: which hosts answered, their open TCP ports, and the service name, product and version Nmap identified on each port |
| `net.tls_certificate` — TLS certificates are valid and not expiring | Linux, Windows | No | For the endpoints you entered: the TLS version and cipher negotiated, and the certificate's subject, issuer and validity dates |

## Malware (needs folders you configure)

| Check | Platforms | Admin | What it reads |
| --- | --- | --- | --- |
| `malware.clamav` — ClamAV scan of your chosen folders | Linux, Windows | No | For the folders you configured on the agent: the paths of files that match a ClamAV malware signature and the signature name (file contents are scanned locally and never uploaded) |

Total: 38 checks.
