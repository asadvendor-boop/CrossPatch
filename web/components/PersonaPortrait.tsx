"use client";

import { useState } from "react";

import { PORTRAIT_ASSETS } from "@/lib/tokens";
import type { SeatName } from "@/lib/types";
import portraitManifest from "@/public/personas/manifest.json";

export const PORTRAIT_CONTRACT = {
  source: [1024, 1536] as const,
  crop: [800, 1000] as const,
  card: [72, 90] as const,
  expanded: [160, 200] as const,
};

type ReplacementKind = "source" | "crop";
type DimensionSource = { width: number; height: number } | Blob;

async function dimensions(image: DimensionSource): Promise<{ width: number; height: number }> {
  if ("width" in image && "height" in image) return image;
  if (typeof createImageBitmap !== "function") {
    throw new Error("This browser cannot inspect replacement image dimensions");
  }
  const bitmap = await createImageBitmap(image);
  const result = { width: bitmap.width, height: bitmap.height };
  bitmap.close();
  return result;
}

export async function validateReplacement(image: DimensionSource, kind: ReplacementKind): Promise<boolean> {
  const actual = await dimensions(image);
  const expected = PORTRAIT_CONTRACT[kind];
  return actual.width === expected[0] && actual.height === expected[1];
}

interface PersonaPortraitProps {
  seat: SeatName;
  expanded?: boolean;
  assetAvailable?: boolean;
}

export function PersonaPortrait({ seat, expanded = false, assetAvailable = false }: PersonaPortraitProps) {
  const [failed, setFailed] = useState(false);
  const size = expanded ? PORTRAIT_CONTRACT.expanded : PORTRAIT_CONTRACT.card;
  const style = { width: `${size[0]}px`, height: `${size[1]}px` };
  const configuredAvailable =
    assetAvailable || portraitManifest.assets.some((asset) => asset.seat === seat && asset.available);
  const showImage = configuredAvailable && !failed;

  if (showImage) {
    return (
      // Native img preserves the exact, auditable crop dimensions without Next image transformations.
      // eslint-disable-next-line @next/next/no-img-element
      <img
        className="persona-portrait persona-portrait--image"
        src={`/personas/${PORTRAIT_ASSETS[seat].crop}`}
        alt={`${seat} portrait`}
        width={size[0]}
        height={size[1]}
        style={style}
        onError={() => setFailed(true)}
      />
    );
  }

  return (
    <div
      className="persona-portrait persona-portrait--placeholder"
      role="img"
      aria-label={`${seat} portrait placeholder`}
      style={style}
      title={`Replace with ${PORTRAIT_ASSETS[seat].crop}`}
    >
      <span aria-hidden="true">{seat.charAt(0)}</span>
    </div>
  );
}
