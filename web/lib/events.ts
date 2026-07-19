"use client";

import { useEffect, useRef } from "react";

import { authenticatedHeaders } from "./api";
import type { StreamConnectionState, TimelineEvent } from "./types";

const STORAGE_PREFIX = "crosspatch:timeline:";

export function normalizeTimelineEvent(event: TimelineEvent): TimelineEvent {
  return event;
}

export function persistEvent(event: TimelineEvent): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(`${STORAGE_PREFIX}${event.id}`, JSON.stringify(normalizeTimelineEvent(event)));
}

export async function persistedEvent(id: string): Promise<TimelineEvent | null> {
  if (typeof window === "undefined") return null;
  const value = window.localStorage.getItem(`${STORAGE_PREFIX}${id}`);
  return value ? (JSON.parse(value) as TimelineEvent) : null;
}

export function mergeTimelineEvents(
  current: readonly TimelineEvent[],
  incoming: readonly TimelineEvent[],
): TimelineEvent[] {
  const events = new Map(current.map((event) => [event.id, event]));
  for (const event of incoming) events.set(event.id, normalizeTimelineEvent(event));
  return [...events.values()].sort(
    (left, right) => left.sequence - right.sequence || left.id.localeCompare(right.id),
  );
}

interface StreamOptions {
  incidentId: string;
  enabled?: boolean;
  initialLastEventId?: string;
  onEvent: (event: TimelineEvent) => void;
  onState: (state: StreamConnectionState) => void;
  decode: (value: unknown) => TimelineEvent;
  url: string;
}

export interface SseFrame {
  id: string;
  event: string;
  data: string;
}

export class SseFrameDecoder {
  private buffer = "";

  push(chunk: string): SseFrame[] {
    this.buffer += chunk.replaceAll("\r\n", "\n");
    const frames: SseFrame[] = [];
    let boundary = this.buffer.indexOf("\n\n");
    while (boundary !== -1) {
      const raw = this.buffer.slice(0, boundary);
      this.buffer = this.buffer.slice(boundary + 2);
      const id: string[] = [];
      const event: string[] = [];
      const data: string[] = [];
      for (const line of raw.split("\n")) {
        if (!line || line.startsWith(":")) continue;
        const separator = line.indexOf(":");
        const field = separator === -1 ? line : line.slice(0, separator);
        const fieldValue = separator === -1 ? "" : line.slice(separator + 1).replace(/^ /, "");
        if (field === "id") id.push(fieldValue);
        if (field === "event") event.push(fieldValue);
        if (field === "data") data.push(fieldValue);
      }
      if (data.length) {
        frames.push({ id: id.at(-1) ?? "", event: event.at(-1) ?? "message", data: data.join("\n") });
      }
      boundary = this.buffer.indexOf("\n\n");
    }
    return frames;
  }
}

export function useIncidentEventStream({
  incidentId,
  enabled = true,
  initialLastEventId = "",
  onEvent,
  onState,
  decode,
  url,
}: StreamOptions): void {
  const initialLastEventIdRef = useRef(initialLastEventId);

  useEffect(() => {
    initialLastEventIdRef.current = initialLastEventId;
  }, [incidentId, initialLastEventId]);

  useEffect(() => {
    if (!enabled) return;
    if (!incidentId || typeof fetch === "undefined") {
      onState("offline");
      return;
    }

    let stopped = false;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let lastEventId = initialLastEventIdRef.current;
    const controller = new AbortController();

    async function connect() {
      onState(lastEventId ? "reconnecting" : "connecting");
      try {
        const headers = authenticatedHeaders({ Accept: "text/event-stream" });
        if (lastEventId) headers.set("Last-Event-ID", lastEventId);
        const response = await fetch(url, {
          cache: "no-store",
          headers,
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error(`Event stream failed (${response.status})`);
        onState("live");
        const reader = response.body.getReader();
        const utf8 = new TextDecoder();
        const frames = new SseFrameDecoder();
        while (!stopped) {
          const { done, value } = await reader.read();
          if (done) break;
          for (const frame of frames.push(utf8.decode(value, { stream: true }))) {
            if (frame.id) lastEventId = frame.id;
            onEvent(decode(JSON.parse(frame.data) as unknown));
          }
        }
        if (!stopped) {
          onState("reconnecting");
          retry = setTimeout(connect, 1_000);
        }
      } catch (error) {
        if (stopped || (error instanceof DOMException && error.name === "AbortError")) return;
        onState("reconnecting");
        retry = setTimeout(connect, 1_000);
      }
    }

    void connect();

    return () => {
      stopped = true;
      controller.abort();
      if (retry) clearTimeout(retry);
    };
  }, [decode, enabled, incidentId, onEvent, onState, url]);
}
