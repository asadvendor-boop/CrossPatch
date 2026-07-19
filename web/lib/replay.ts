export const RECORDED_REPLAY_BANNER = "RECORDED REPLAY — signed export, no model calls";

export function isRecordedReplay(): boolean {
  return process.env.NEXT_PUBLIC_CROSSPATCH_REPLAY_MODE === "1";
}
