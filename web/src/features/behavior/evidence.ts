/**
 * A detection's `process_tree` and `events` arrive as open JSON objects on the wire (the server stores the
 * agent's evidence verbatim). These helpers read the known fields out of them safely, so the drawer renders
 * real structure instead of dumping JSON, and never trusts a field to be the type it expects.
 */

function str(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** The last path segment of a Windows or POSIX image path, e.g. `C:\Windows\powershell.exe` -> `powershell.exe`. */
export function basename(path: string | null | undefined): string {
  if (!path) return "";
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : path;
}

export interface ProcessNode {
  processGuid: string | null;
  pid: number | null;
  image: string | null;
  commandLine: string | null;
  user: string | null;
  parentGuid: string | null;
}

/** Ancestry as the server sends it: nearest (acting) process first, then its parents. */
export function processAncestry(tree: ReadonlyArray<Record<string, unknown>> | null | undefined): ProcessNode[] {
  if (!Array.isArray(tree)) return [];
  return tree.map((raw) => {
    const node = raw ?? {};
    return {
      processGuid: str(node.process_guid),
      pid: num(node.pid),
      image: str(node.image),
      commandLine: str(node.command_line),
      user: str(node.user),
      parentGuid: str(node.parent_guid),
    };
  });
}

export interface DetectionEvent {
  kind: string;
  kindLabel: string;
  summary: string;
  ts: string | null;
  host: string | null;
  pid: number | null;
  image: string | null;
}

const KIND_LABELS: Record<string, string> = {
  process_create: "Process created",
  process_exit: "Process exited",
  network_connect: "Network connection",
  file_write: "File written",
  file_delete: "File deleted",
  registry_set: "Registry set",
  image_load: "Image loaded",
};

export function eventKindLabel(kind: string): string {
  return KIND_LABELS[kind] ?? kind.replace(/_/g, " ");
}

/** A one-line human summary of a single telemetry event, keyed off its `kind`. */
export function eventSummary(ev: Record<string, unknown>): string {
  const actor = basename(str(ev.image)) || "(unknown)";
  switch (ev.kind) {
    case "process_create": {
      const parent = basename(str(ev.parent_image));
      const cmd = str(ev.command_line);
      const spawned = parent ? `${parent} → ${actor}` : actor;
      return cmd ? `${spawned} · ${cmd}` : spawned;
    }
    case "network_connect": {
      const dest = str(ev.dest_ip);
      const port = num(ev.dest_port);
      const where = dest ? (port !== null ? `${dest}:${port}` : dest) : "(unknown host)";
      const proto = str(ev.protocol);
      const dir = str(ev.direction);
      const tail = [dir, proto].filter(Boolean).join(" ");
      return `${actor} → ${where}${tail ? ` (${tail})` : ""}`;
    }
    case "registry_set": {
      const path = str(ev.registry_path);
      const valueName = str(ev.registry_value);
      const where = path ? (valueName ? `${path}\\${valueName}` : path) : "(unknown key)";
      return `${actor} set ${where}`;
    }
    case "file_write":
    case "file_delete": {
      const verb = ev.kind === "file_delete" ? "deleted" : "wrote";
      return `${actor} ${verb} ${str(ev.file_path) ?? "(unknown path)"}`;
    }
    case "image_load":
      return `${actor} loaded ${str(ev.file_path) ?? "(unknown image)"}`;
    default:
      return actor;
  }
}

export function detectionEvents(events: ReadonlyArray<Record<string, unknown>> | null | undefined): DetectionEvent[] {
  if (!Array.isArray(events)) return [];
  return events.map((raw) => {
    const ev = raw ?? {};
    const kind = str(ev.kind) ?? "event";
    return {
      kind,
      kindLabel: eventKindLabel(kind),
      summary: eventSummary(ev),
      ts: str(ev.ts),
      host: str(ev.host),
      pid: num(ev.pid),
      image: str(ev.image),
    };
  });
}
