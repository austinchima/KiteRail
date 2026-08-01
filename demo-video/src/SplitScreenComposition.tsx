import React from 'react';
import { AbsoluteFill } from 'remotion';
import { AgentTerminal } from './AgentTerminal';
import { DashboardMock } from './DashboardMock';

export const SplitScreenComposition: React.FC = () => {
  return (
    <AbsoluteFill className="bg-zinc-900 flex flex-row p-8 gap-8 items-center justify-center">
      <div className="w-1/2 h-full rounded-2xl overflow-hidden shadow-2xl flex relative">
        <AgentTerminal />
      </div>
      <div className="w-1/2 h-full rounded-2xl overflow-hidden shadow-2xl flex relative">
        <DashboardMock />
      </div>
    </AbsoluteFill>
  );
};
