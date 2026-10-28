# Sentinel X — a guided build

This is the companion notebook to Sentinel X, the behavioural-detection layer we are adding to Sentinel. It
is written to be *read while the code is built*, in a teacher-and-student voice: each lesson explains an idea,
then points at the exact code where that idea lives, and ends with a couple of questions to check that the
idea landed. You do not need to have written the code to follow it — but you should be able to open the file
it names and recognise what you are looking at.

The plan is built in increments. This document grows one chapter per increment, so you can always see how far
we are and why each piece exists.

- **Chapter 1 — The engine (done).** The event schema and the detection engine, tested entirely against
  synthetic event streams. No live data collection yet.
- **Chapter 2 — The Windows collector (done).** A real collector that produces the events Chapter 1 invented,
  from Sysmon telemetry on your machine. ← *you are here*
- **Chapter 3 — Surfacing detections (next).** Storing detections on the server and showing them in the
  dashboard.
- **Chapter 4 — The measurement lab.** Scoring the engine against documented attacks: true/false positives,
  detection latency, and overhead.

---

## Chapter 1 — The engine

### Lesson 0: Why this is a different kind of thing from the rest of Sentinel

Everything in Sentinel so far is a **scanner**. It runs a check — "is the firewall on?", "is this package
out of date?" — looks at the answer *right now*, and records a finding. A scan is a photograph: true at the
instant it was taken, silent about everything between photographs.

Sentinel X is a **sensor**. Instead of asking questions at a moment, it watches a continuous stream of things
the operating system *did* — every process that started, every network connection, every change to a
sensitive setting — and reasons about sequences of them over time. A sensor is a video, not a photograph.

> **Q (student):** Isn't that just "more checks"?
>
> **A (teacher):** No, and the difference is the whole project. A check answers a question about *state*. The
> interesting attacks don't live in any single piece of state — they live in a *sequence of actions*. "Word
> is running" is fine. "Word started PowerShell, which called out to the internet, which then switched off
> Defender" is not fine — but no single one of those facts is a problem on its own. You can only catch it by
> remembering what happened and tying the pieces together. That remembering-and-tying-together is what a
> detection engine is, and it is what commercial tools call EDR (Endpoint Detection and Response).

The industry name for the thing we are building is an EDR engine. The valuable part is not an alarm that goes
off on a single event; it is the **correlation** and the **evidence** behind a conclusion.

### Lesson 1: Telemetry, and where it comes from

The raw material is *telemetry*: a timestamped record of each security-relevant action on the machine. On
Windows the source is **Event Tracing for Windows (ETW)** — a firehose of events that the kernel and
thousands of components emit continuously. We care about a few families:

- **process creation** — a new process started, with its command line and, crucially, *who started it*;
- **network connections** — a process opened a connection, and to where;
- **file and registry changes** — a process wrote a file or changed a setting.

> **Q:** If ETW already emits all this, what is there to build?
>
> **A:** ETW gives you a torrent of low-level, Windows-shaped events in dozens of formats. Three jobs remain,
> and they are the project: (1) **normalise** that torrent into one clean shape you can reason about;
> (2) **correlate** the normalised events into conclusions; (3) **measure** how good those conclusions are.
> Chapter 2 does the collecting. Chapter 1 — this one — does the normalising and correlating, and it does it
> against *invented* streams so we can build and test the brain before we wire up the senses.

> **Q:** Isn't it cheating to build the detection engine before we can collect real events?
>
> **A:** It's the opposite — it's the same discipline the rest of Sentinel already uses. Every check in
> Sentinel is tested against hand-written fixtures shaped like real command output, not against a live
> machine. We do the same here: a *stream* of events, built in code or loaded from a recording, stands in for
> the live collector. The engine cannot tell the difference, which is exactly the point.

### Lesson 2: The event schema — one flat shape, keyed by GUID

Open [`packages/core/src/sentinel_core/telemetry.py`](../packages/core/src/sentinel_core/telemetry.py). The
model `TelemetryEvent` is the contract: every collector must produce this, and the engine only ever consumes
this. Two design decisions are worth dwelling on.

**It is one flat model with a `kind` field, not a class per event type.** A `process_create` and a
`network_connect` share a model; the fields that don't apply are just left unset. This mirrors the existing
`LogEvent` and it buys three things: it serialises to one line of JSON trivially, a new collector can add a
field without breaking old recordings, and storing a mixed stream is simple.

**Every event is keyed by `process_guid`, never by PID.** This is the single most important line in the file.

> **Q:** Why not just use the process ID? Every OS has one.
>
> **A:** Because Windows *reuses* PIDs within seconds. A malicious process can run as PID 4812, exit, and ten
> seconds later your text editor is PID 4812. If you correlated by PID you would blame the editor for the
> malware's network connection. A **GUID** — a unique id the collector assigns from the boot id, PID, and
> creation time (this is what Sysmon does) — is unique for the life of the machine. Correlate by GUID and that
> confusion is impossible. Look at how `ProcessTree` keys everything off `process_guid`.

### Lesson 3: The process tree — the engine's memory of lineage

Open [`packages/detect/src/sentinel_detect/process_tree.py`](../packages/detect/src/sentinel_detect/process_tree.py).

Almost every detection is a question about *relationships between processes*: "what launched this?", "is this
connection coming from a descendant of that suspicious shell?". To answer those you need **lineage**, and
lineage means remembering every process creation and tying each child to its parent. `ProcessTree` is that
memory. Its key method is `ancestry(guid)`, which walks from a process up through its parents.

Three details that look small and are not:

- **Exited processes are kept, not deleted** (just flagged `exited`). Events about a process can arrive just
  after it dies, and a detection needs to describe ancestry that may already be gone.
- **The store is bounded and evicts exited processes first.** A sensor runs forever; memory cannot grow
  forever. When full, we drop the oldest *dead* processes and never evict live lineage to make room.
- **`ancestry` stops on a cycle and on an unknown parent.** Hostile or corrupt input must never make the
  engine loop forever. See `test_ancestry_tolerates_a_cycle`.

> **Q:** Why synthesise a "stub" node for a process we never saw created?
>
> **A:** Because the collector might have started *after* that process did. If a network connection arrives
> from a GUID we have no creation record for, we still want to reason about it, so `ingest` creates a minimal
> stub marked `synthesized=True`. It's honest about what it is, and it keeps the acting process resolvable.

### Lesson 4: Two shapes of rule — stateless and stateful

Open [`packages/detect/src/sentinel_detect/rules.py`](../packages/detect/src/sentinel_detect/rules.py). This is
where events become conclusions, and there are exactly two shapes of logic here.

A **contextual** rule looks at *one event* in the light of the process tree. `OfficeSpawnsInterpreter` is the
simplest: on a process-creation event, if the new process is a script interpreter (`powershell.exe`,
`cmd.exe`, `mshta.exe`, …) and its *parent* is an Office application, that's the classic macro/phishing
execution pattern — fire. It needs lineage, but it does not need to remember *time*.

A **sequence** rule watches for several events that only mean something together, within a time window,
correlated by lineage. That is the hard and interesting case, and it has its own lesson.

> **Q:** The `Rule` base class has an `observe(event, tree, emit)` method. Why that shape?
>
> **A:** It makes rules cheap to add and keeps each rule's state its own. The engine just hands every event to
> every rule's `observe` and gives it a callback to `emit` detections. A stateless rule ignores the callback
> until it sees something; a stateful rule keeps a little dictionary of partial matches between calls. The
> engine doesn't need to know which kind a rule is — that's what makes adding the twentieth rule as easy as
> the first.

### Lesson 5: The worked example — `SuspiciousExecChain`

This is the rule the whole chapter exists to produce. Read `SuspiciousExecChain` in `rules.py` alongside this.

It looks for three stages, **in any order, within a time window, tied together by lineage**:

1. **Unusual execution** — an interpreter is created by an *unusual* parent: an Office app, a
   living-off-the-land binary (`mshta`, `rundll32`, …), or a process running from a user-writable location
   like `\AppData\Local\Temp\` or `\Downloads\`.
2. **Command & control** — that interpreter, *or any descendant of it*, opens an outbound connection to a
   **public** address.
3. **System change** — that interpreter, or a descendant, modifies an autorun entry or a security setting.

When all three have been seen for one lineage, it fires `CRITICAL`, and it carries the three triggering events
and the process ancestry along as evidence.

> **Q:** How does stage 2 know the connection came from "a descendant of" the interpreter? The connection
> event only has its own process's GUID.
>
> **A:** That's where the process tree earns its keep. When a network event arrives, the rule calls
> `tree.ancestry(event.process_guid)` and checks whether any ancestor is an interpreter it is already
> tracking (`_nearest_tracked`). So a connection from `rundll32.exe`, whose grandparent is the tracked
> PowerShell, is correctly tied back to that chain. Run the shipped sample and you'll see exactly this — the
> connection comes from `rundll32`, not PowerShell, and the chain still fires.

> **Q:** Why require *all three* stages? Each one sounds bad on its own.
>
> **A:** Because each one *alone* is also completely ordinary. Admins spawn shells. Shells download things.
> Settings get changed during legitimate work. If you fired on any one, you'd drown the user in false alarms
> and they'd turn you off — which is the real-world failure mode of bad detection. The three *together*, from
> one lineage, inside a few minutes, is a shape that ordinary administration almost never produces. The
> correlation is worth far more than the sum of its parts. That is the thesis of the entire project in one
> rule.

> **Q:** What stops a chain's half-finished state from living in memory forever?
>
> **A:** `_expire` drops any chain whose first event is older than the window (default 10 minutes) relative to
> the current event's timestamp — note: the *event's* clock, not the wall clock, so replays are deterministic.
> `test_chain_expires_outside_the_window` proves a chain spread over 20 minutes never fires.

### Lesson 6: The hardest problem — telling malice from ordinary administration

Open [`packages/detect/src/sentinel_detect/suppression.py`](../packages/detect/src/sentinel_detect/suppression.py).

Here is the uncomfortable truth of detection engineering: **every pattern you look for is also something
legitimate software does.** Your patch-management tool disables real-time protection during an update. Your
deployment script writes autorun keys. A build server spawns interpreters all day. The difference between a
usable detector and an unusable one is almost entirely its ability to say "this exact thing, from this exact
source, is expected here."

That is `Suppression`. Note two deliberate choices:

- Suppression is applied **after** a rule fires, in the engine, and it is scoped **per source**, never per
  behaviour. We stop trusting a *path* (`C:\Program Files\OurAgent\`), never a whole *class of activity*
  ("ignore PowerShell"). Blinding yourself to all PowerShell is how you miss the attack; allow-listing one
  signed tool is how you stay quiet without going blind.
- Every entry must carry a `reason`. An allowlist without reasons rots into a list nobody dares touch.

> **Q:** This is just a glob list. Isn't that primitive compared to machine learning?
>
> **A:** It is primitive, on purpose, for now. The honest order of operations is: get the correlation right and
> provably quiet on ordinary activity first; grow the allowlist as you learn your own environment; reach for
> baselining or ML only when you can *measure* that it beats the simple thing. Chapter 4 builds the
> measurement that would justify that step. Reaching for the fancy tool before you can measure it is how
> projects produce confident, unfalsifiable nonsense.

### Lesson 7: A shared vocabulary — MITRE ATT&CK

Open [`packages/detect/src/sentinel_detect/attack.py`](../packages/detect/src/sentinel_detect/attack.py). Each
rule tags itself with **MITRE ATT&CK** technique ids — `T1059` (Command and Scripting Interpreter), `T1562.001`
(Disable or Modify Tools), and so on. ATT&CK is the industry's shared catalogue of *what attackers do*.

> **Q:** Why bother mapping to ids? The detection works without them.
>
> **A:** Two reasons, both about the future. First, coverage becomes a question you can answer: "which
> techniques do we actually catch, and which are blind spots?" Second, it's the vocabulary the measurement lab
> in Chapter 4 speaks — documented attack tests (like Atomic Red Team) are themselves organised by ATT&CK
> technique, so tagging rules now means we can line detections up against a recognised test corpus later
> instead of inventing our own yardstick.

### Lesson 8: Why everything is a replay, and a gotcha to remember

Open [`packages/detect/src/sentinel_detect/replay.py`](../packages/detect/src/sentinel_detect/replay.py) and
[`engine.py`](../packages/detect/src/sentinel_detect/engine.py).

The engine is driven entirely by the **event stream's own clock**, and `feed_stream` sorts events by
`(timestamp, sequence)` before processing. Together these make a replay *deterministic*: the same stream
produces the same detections every single time. That is what makes the engine testable today and *measurable*
in Chapter 4 — you cannot score something whose output wanders.

Try it yourself:

```bash
uv run sentinel-detect packages/detect/samples/suspicious_chain.jsonl   # three detections, including CRITICAL
uv run sentinel-detect packages/detect/samples/benign_admin.jsonl       # silent, as it should be
```

**A gotcha worth internalising.** While building this, the chain *refused to fire* on a test until the cause
turned out to be the fake "attacker" IP: `203.0.113.10`. That address is in a range reserved for
*documentation*, and Python's `ipaddress.is_global` correctly reports it as not globally routable — so the
engine, also correctly, didn't count it as an outbound-to-the-internet event. The lesson is double: (1) special
ranges — documentation, private, loopback, link-local — are not "the internet", and real detection logic has
to know that (`_is_external_ip` does); (2) when a detector is silent, suspect your *test data* before your
logic. Realistic evil needs a realistically routable address.

### What Chapter 1 gives you, concretely

- A normalised event schema any collector can target (`sentinel_core.telemetry`).
- A process tree that reconstructs lineage safely and within bounded memory.
- Four rules — one Office-macro pattern, one persistence pattern, one defense-tampering pattern, and the
  multi-stage correlation chain — each tagged to ATT&CK and each carrying its evidence.
- A suppression mechanism that keeps ordinary administration quiet.
- A deterministic replay harness, a `sentinel-detect` command, and tests that include *benign* streams which
  must stay silent — the beginnings of the measurement discipline Chapter 4 will formalise.

### Check your understanding

1. A connection to `10.0.0.5` and a connection to `8.8.8.8` reach the same engine. Only one can complete the
   suspicious chain. Which, and why? (Lesson 5 and 8.)
2. Why does correlating by PID instead of GUID eventually produce a wrong accusation? (Lesson 2.)
3. The patch tool at `C:\Program Files\Acme\agent.exe` legitimately disables real-time protection during
   updates and keeps tripping `defense.security_tooling_disabled`. What is the *right* fix, and what is the
   tempting wrong one? (Lesson 6.)
4. Why is the engine driven by the event timestamps rather than the real-world clock? (Lesson 8.)

---

---

## Chapter 2 — The Windows collector

In Chapter 1 we built a brain and fed it invented events. Now we give it senses: a collector that produces
real `TelemetryEvent`s from what actually happened on a Windows machine. This is the part that has to earn the
word *trustworthy*, because every conclusion the engine draws is only as good as the events it was fed.

### Lesson 9: The honest choice — raw ETW, or stand on Sysmon?

The project brief said "build a collector using Event Tracing for Windows." Let's be precise about what that
means, because there's a fork in the road and picking the wrong branch costs months.

**ETW** is Windows' built-in firehose. The kernel and thousands of components are *providers* that emit
events; a *consumer* opens a *session*, subscribes to some providers, and receives their events in real time.
It is genuinely the right foundation — it's how everything on Windows sees process and network activity.

But raw ETW is unforgiving. Each provider has its own schema (some modern manifests, some ancient MOF
classes); the kernel providers that carry process and network events need a privileged session; and — the
detail that matters most for us — the raw kernel process events do **not** hand you a stable process GUID.
You'd have to synthesise one yourself from boot id, PID, and creation time, correctly, under race conditions,
or inherit exactly the PID-reuse bug Chapter 1's whole design exists to avoid.

> **Q (student):** So do we write a raw ETW consumer or not?
>
> **A (teacher):** We stand on **Sysmon**, and here's the reasoning. Sysmon is a free Microsoft tool that is
> *itself* a hardened ETW consumer. It has already solved the fragile parts: it subscribes to the right kernel
> providers, and — crucially — it assigns every process a stable `ProcessGuid`, the exact key our model is
> built on. It writes clean, documented, named-field events to its own event-log channel. Re-implementing that
> from raw ETW would be months of work to arrive at a *worse* version of something Microsoft ships for free.
> So "use ETW" becomes "consume a trustworthy ETW consumer." That is the pragmatic engineering call, and it's
> the one real detection teams make.

> **Q:** Isn't that cheating the "learn the pipeline" goal?
>
> **A:** No — it moves the learning to where the value is. The pipeline has three stages: *subscribe*,
> *normalise*, *correlate*. Sysmon owns `subscribe` and does it better than we could; the learning that's worth
> having is in `normalise` (this chapter) and `correlate` (Chapter 1). If you later need something Sysmon can't
> give — AMSI script contents, a provider Sysmon doesn't cover — *that* is when you drop to a raw ETW consumer
> for that one stream, and you'll do it understanding exactly what you're buying. Building it first, for
> everything, would have been motion mistaken for progress.

### Lesson 10: Normalisation is where you decide what you trust

Open [`packages/agent/src/sentinel_agent/telemetry/sysmon.py`](../packages/agent/src/sentinel_agent/telemetry/sysmon.py).
This module is the *only* Windows-specific knowledge in the entire detection path, and it is deliberately
pure: give `map_sysmon` the fields of one Sysmon event and it returns one of our `TelemetryEvent`s, or `None`
for an event id we don't model yet. No I/O, no global state — which is why it's trivially testable.

Three small pieces of translation carry real weight:

- **GUID normalisation** (`strip_guid`). Sysmon wraps GUIDs in braces (`{a1b2…}`); we store the bare value so
  the key the engine correlates on is consistent no matter which collector produced it.
- **Registry value parsing** (`parse_registry_value`). Sysmon renders a value as `DWORD (0x00000001)`. The
  defense-tamper rule needs to know whether a Defender flag is 1 or 0, so we pull the integer out. A string or
  binary value becomes `None`, kept raw in `value_raw`. This is a tiny function doing load-bearing work: get
  it wrong and either the tamper rule never fires, or it fires on every benign write.
- **Capping** (`_cap`). A real command line can be enormous; our schema has limits. We truncate rather than let
  an over-long field reject the whole event — losing the tail of a command line is fine, dropping the event
  entirely is not. See `test_overlong_command_line_is_truncated_not_rejected`.

> **Q:** Why return `None` for event ids we "don't model yet" instead of storing them anyway?
>
> **A:** Because an event the engine has no rule for is just memory pressure and noise. The schema has room for
> more kinds (file writes, image loads — both already mapped), and adding the next one is a single `if` branch
> plus a test. Storing everything "just in case" is how a sensor drowns itself.

### Lesson 11: Reading the live log — and testing it without Windows

Open [`packages/agent/src/sentinel_agent/telemetry/collector.py`](../packages/agent/src/sentinel_agent/telemetry/collector.py).

`SysmonCollector` reads the live Sysmon channel through the agent's ordinary command runner — the *exact* same
`Get-WinEvent … | ForEach { $_.ToXml() }` mechanism the posture log checks already use — and keeps a
**record-id cursor** in agent state so each call returns only what's new. Two details worth noting:

- **The cursor makes it a tail, not a re-scan.** First run reads a recent window; afterwards it asks only for
  records past the last id it saw. If a log is cleared (record ids restart at 1), it notices the newest id is
  below the cursor and re-reads the window instead of waiting forever. That logic is lifted straight from the
  existing event-log checks, because it was already solved there.
- **It goes through a `CheckContext`, so it's testable without Windows.** This is the same trick as Chapter 1.
  A `FixtureContext` supplies the command's JSON output, and the collector can't tell it isn't talking to a
  real machine — so `test_telemetry_collector.py` exercises the entire read → parse → map path, cursor and
  all, on Linux CI. Look at `test_second_collect_reads_incrementally_from_cursor`: two `collect()` calls, the
  second returning only the newer process, cursor advanced — all from fixtures.

> **Q:** Where does the collector run, and what gets sent to the server?
>
> **A:** The collector runs *with the agent*, on the endpoint, where the privilege and the firehose are. The
> design rule — which Chapter 3 implements — is that the **raw events never leave the machine**; only the
> *detections*, each carrying the few events that triggered it, go to the server. That keeps the volume down
> and matches Sentinel's local-first, privacy-preserving identity: the server learns conclusions, not a
> minute-by-minute record of everything you ran.

### Lesson 12: Try it

The agent grew a command. Point it at the sample Sysmon export that ships with the repo:

```bash
uv run sentinel-agent telemetry --export packages/agent/samples/sysmon_suspicious.xml
```

That file is raw Sysmon event XML (the same shape `wevtutil` or `Get-WinEvent` produces). The command parses
it, maps it, runs the engine, and prints the detections — the full pipeline, end to end, on a file you can
open and read. On a real machine, drop the `--export` flag to read the live Sysmon log instead.

**The gotcha for Chapter 2:** none of this produces a single event unless Sysmon is installed *and configured
to log these event types*. A bare Sysmon install with an empty config logs almost nothing. You want a config
that enables process creation (event 1), network connections (event 3 — off by default in some configs),
registry value sets (event 13), and process termination (event 5). The community configs from
SwiftOnSecurity and Olaf Hartong (`sysmon-modular`) are the usual starting points. The lesson generalises: a
telemetry pipeline is only as good as what the sensor is told to record, and "I got zero events" almost always
means "the sensor wasn't asked for them," not "nothing happened."

### What Chapter 2 gives you, concretely

- A pure, fully-tested mapping from Sysmon's event schema to our `TelemetryEvent` (`telemetry/sysmon.py`).
- A live `SysmonCollector` that tails the Sysmon channel with a cursor, and an `ExportCollector` for saved
  logs — both reusing the agent's existing, trusted command machinery, both driven by fixtures in tests.
- A `sentinel-agent telemetry` command that runs the whole pipeline over live or exported telemetry.
- A realistic sample Sysmon export, and tests that carry raw Sysmon XML all the way to a `CRITICAL` detection.

### Check your understanding

1. We "used ETW" without writing a raw ETW consumer. In one sentence, how — and what would make you write a raw
   consumer later? (Lesson 9.)
2. `parse_registry_value("DWORD (0x00000000)")` returns `0`. Why does that specific value matter to the
   defense-tamper rule, and what would break if the function returned `None` here instead? (Lesson 10 and
   Chapter 1's Lesson 5.)
3. The collector reads live Windows logs, yet its tests run on Linux. What makes that possible, and why is it
   the same idea as Chapter 1? (Lesson 11.)
4. A user runs `sentinel-agent telemetry` on a real machine and gets zero events, though they were clearly
   active. What is the first thing to check, and why isn't it the code? (Lesson 12.)

---

*Next: Chapter 3, where detections stop living in a terminal and start living in Sentinel — shipped from the
agent to the server (conclusions only, never the firehose) and shown on a page in the dashboard beside the
posture findings.*
