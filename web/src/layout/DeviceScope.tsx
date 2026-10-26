import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { readStored, writeStored } from "../lib/storage";

const KEY = "sentinel-device-scope";

interface DeviceScope {
  /** null means "All devices". */
  deviceId: number | null;
  setDeviceId: (id: number | null) => void;
}

const Ctx = createContext<DeviceScope>({ deviceId: null, setDeviceId: () => undefined });

export function DeviceScopeProvider({ children }: { children: ReactNode }) {
  const [deviceId, setState] = useState<number | null>(() => {
    const raw = readStored(KEY);
    const n = raw ? Number(raw) : NaN;
    return Number.isInteger(n) && n > 0 ? n : null;
  });
  const setDeviceId = useCallback((id: number | null) => {
    setState(id);
    writeStored(KEY, id === null ? null : String(id));
  }, []);
  const value = useMemo(() => ({ deviceId, setDeviceId }), [deviceId, setDeviceId]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useDeviceScope(): DeviceScope {
  return useContext(Ctx);
}
