# Security score

The score is computed from stored findings and check coverage. It is never random and never shown when the data behind it is too thin.

## Formula

```
score = max(0, 100 − 20·C − 8·H − 3·M − 1·L)
```

C, H, M and L count **open** findings by severity (statuses new, confirmed, in progress, accepted risk, reopened) that **count toward the score**:

| Finding kind | Counts? |
| --- | --- |
| Verified (directly observed state, version-matched vulnerability) | Yes |
| Heuristic with high confidence | Yes |
| Heuristic with medium or low confidence | No (shown, not scored) |
| Informational, or severity "info" | Never |

Accepted-risk findings still count: accepting a risk does not remove it.

## Coverage and "Incomplete"

Coverage = checks that completed (passed or failed) ÷ checks that applied, taken from the latest full or posture scan. Not-applicable checks (for example Remote Desktop on Windows Home) are left out of both numbers. Skipped, errored, timed-out and cancelled checks count as applicable but not completed.

Below **75% coverage** the score is shown as **Incomplete** instead of a number, with the raw value available on request. A scan that skipped half its checks can never look like a clean 100. Change the threshold with `SENTINEL_MIN_SCORE_COVERAGE`.

## Across devices

With "All devices" selected, the score is the **lowest** device score: one weak machine is the weak point. Counts are summed.

## Threat level

The highest severity among open alerts (new, acknowledged, investigating) and open counted findings. With nothing open it is "informational", which still does not mean the device is secure: it means nothing Sentinel checks for was observed.

## Score history

Each completed full or posture scan freezes its score, raw score, coverage and check-status counts in `scans.summary`, so history reflects what was known at the time.

## Worked example

One open high (firewall off on the Public profile) and two open lows, 11 of 12 applicable checks completed:
100 − 8 − 2 = **90**, coverage 92%, threat level **high**.
