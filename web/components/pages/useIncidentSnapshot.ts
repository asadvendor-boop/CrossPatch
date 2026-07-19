"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { getIncidentRoom } from "@/lib/api";
import { readIncidentId, storeIncidentId } from "@/lib/session";
import type { IncidentRoomSnapshot } from "@/lib/types";

export type IncidentLoadState = "restoring" | "unselected" | "loading" | "ready" | "error";

export function useIncidentSnapshot() {
  const [incidentId, setIncidentId] = useState("");
  const [incidentInput, setIncidentInput] = useState("");
  const [snapshot, setSnapshot] = useState<IncidentRoomSnapshot | null>(null);
  const [state, setState] = useState<IncidentLoadState>("restoring");
  const [error, setError] = useState<string | null>(null);
  const controllerRef = useRef<AbortController | null>(null);

  const loadIncident = useCallback(async (input: string): Promise<void> => {
    const normalized = input.trim();
    if (!normalized) {
      storeIncidentId("");
      setIncidentId("");
      setSnapshot(null);
      setError(null);
      setState("unselected");
      return;
    }

    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    storeIncidentId(normalized);
    setIncidentId(normalized);
    setIncidentInput(normalized);
    setSnapshot(null);
    setError(null);
    setState("loading");

    try {
      const loaded = await getIncidentRoom(normalized, controller.signal);
      if (controller.signal.aborted) return;
      setSnapshot(loaded);
      setState("ready");
    } catch (caught) {
      if (controller.signal.aborted) return;
      setSnapshot(null);
      setError(caught instanceof Error ? caught.message : "Incident projection unavailable");
      setState("error");
    }
  }, []);

  useEffect(() => {
    const restore = window.setTimeout(() => {
      const remembered = readIncidentId();
      setIncidentInput(remembered);
      if (remembered) void loadIncident(remembered);
      else setState("unselected");
    }, 0);
    return () => {
      window.clearTimeout(restore);
      controllerRef.current?.abort();
    };
  }, [loadIncident]);

  return {
    error,
    incidentId,
    incidentInput,
    loadIncident,
    setIncidentInput,
    snapshot,
    state,
  };
}
