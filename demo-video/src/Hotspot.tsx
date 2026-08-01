import { interpolate, useCurrentFrame } from "remotion";
import React from "react";

export const Hotspot: React.FC<{ x: number; y: number; label: string }> = ({
  x,
  y,
  label,
}) => {
  const frame = useCurrentFrame();

  const scale = interpolate(frame, [0, 10], [0, 1], {
    extrapolateRight: "clamp",
    extrapolateLeft: "clamp",
  });

  return (
    <div
      style={{
        position: "absolute",
        left: x,
        top: y,
        transform: `scale(${scale})`,
      }}
    >
      <div className="absolute -inset-4 border-2 border-red-500 rounded-full animate-ping opacity-75" />
      <div className="bg-red-500 text-white font-bold px-2 py-1 rounded shadow-lg">
        {label}
      </div>
    </div>
  );
};
