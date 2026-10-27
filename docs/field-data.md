# Field Data and threat intelligence

Two additions that bring outside information into Sentinel without changing what the agent does on your machines.

## Threat-intelligence advisory feed

When you turn on the **Hacker News** integration (Integrations page, off by default like every outbound source), Sentinel periodically reads public Hacker News security stories and matches the headlines against your software inventory and open findings. A story about a product you run, or about a CVE that is in CISA's Known Exploited list, shows up on the **Advisories** page, highest-relevance first. Nothing about your machines is sent; the request is an ordinary public search, and it is logged on the Outbound data page.

Each matched advisory carries a short, plain-text **"possible coverage gap"** note — for example, "you run OpenVPN; check whether your version is affected and turn on OSV/NVD matching." That note is for you to read and act on.

**What it will never do:** rewrite, add, or run any check. Auto-updating executable code from scraped web content is remote code execution by design, and it is exactly what Sentinel's security model exists to prevent. Advisories are information. You decide what to do with them.

## Field Data

The **Field Data** section stores data you captured with your own equipment and correlates it defensively. It is import-only: Sentinel does not drive any radio, adapter, or device itself — you upload a file your own tooling produced.

### Wi-Fi survey

`scripts/field/wifi-survey.sh` runs a **passive, listen-only** survey with a monitor-mode adapter such as the Alfa AWUS036ACHM: it records the access points broadcasting around you to a CSV and transmits nothing. Upload that CSV under Field Data.

First, on the **Known networks** tab, add your own SSIDs and access-point MAC addresses. Then, for each uploaded survey, Sentinel flags:

- a **possible evil twin** — an access point broadcasting one of your SSIDs from a radio you did not list as yours (high);
- a **weak network of yours** — one of your own access points that is open or using WEP (open is high, WEP is medium).

Everyone else's networks are listed as "unknown" and left alone — they are not yours to assess.

Serious findings raise a notification (subject to your severity threshold), and the raw survey stays attached to the capture so you can see exactly what was observed.

### Other captures

The upload endpoint also accepts a generic list of observations (`kind: rf_survey`, `host_report`, `generic`) as JSON, so data from other sensors you build can be stored and shown alongside the Wi-Fi surveys. Only the Wi-Fi access-point correlation is automated today.

## Turning the Raspberry Pi into a portable sensor

Rather than an attack device, point the Pi at defence: install the Sentinel **Linux agent** on it (`scripts/install.sh`, then enroll it like any device). It then does the same read-only posture and inventory checks as any other machine and reports to your server, so you have a small, portable node that audits the networks and hosts you own. Pair it with the passive Wi-Fi survey above and it becomes a travelling environment monitor.
