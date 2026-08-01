import "./index.css";
import React from "react";
import { Composition } from "remotion";
import { SplitScreenComposition } from "./SplitScreenComposition";

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Composition
        id="KiteRailDemo"
        component={SplitScreenComposition}
        durationInFrames={1000}
        fps={30}
        width={1920}
        height={1080}
      />
    </>
  );
};
