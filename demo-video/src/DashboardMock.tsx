import React from 'react';
import { useCurrentFrame, spring, interpolate } from 'remotion';
import { 
  ShieldAlert, 
  CheckCircle, 
  XCircle, 
  Activity, 
  Settings, 
  Inbox, 
  Shield, 
  MousePointer2 
} from 'lucide-react';

export const DashboardMock: React.FC = () => {
  const frame = useCurrentFrame();

  const alertAppearsAt = 500;
  const clickDenyAt = 750;

  // Animate alert appearance
  const alertScale = spring({
    frame: frame - alertAppearsAt,
    fps: 30,
    config: { damping: 12, stiffness: 150 }
  });

  // Cursor animation
  const cursorX = interpolate(frame, [600, 750], [800, 560], { extrapolateRight: 'clamp', extrapolateLeft: 'clamp' });
  const cursorY = interpolate(frame, [600, 750], [800, 240], { extrapolateRight: 'clamp', extrapolateLeft: 'clamp' });
  const cursorScale = frame > 745 && frame < 755 ? 0.8 : 1;

  const isDenied = frame >= clickDenyAt;

  return (
    <div className="h-full w-full bg-slate-50 flex font-sans overflow-hidden">
      {/* Sidebar */}
      <div className="w-20 bg-white border-r border-slate-200 flex flex-col items-center py-6 gap-8 z-10">
        <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-xl">K</div>
        <div className="flex flex-col gap-6 text-slate-400">
          <Activity size={24} />
          <div className="relative">
            <Inbox size={24} className={frame > alertAppearsAt && !isDenied ? "text-indigo-600" : ""} />
            {frame > alertAppearsAt && !isDenied && (
              <span className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full animate-pulse" />
            )}
          </div>
          <Shield size={24} />
          <Settings size={24} />
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <div className="h-20 bg-white border-b border-slate-200 flex items-center px-8 justify-between z-10">
          <h1 className="text-2xl font-semibold text-slate-800">Inbox & Interceptions</h1>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-green-500" />
            <span className="text-slate-500 text-sm font-medium">Proxy Active</span>
          </div>
        </div>

        {/* Dashboard Body */}
        <div className="flex-1 p-8 bg-slate-50 relative">
          
          {frame < alertAppearsAt && (
            <div className="flex flex-col items-center justify-center h-full text-slate-400 space-y-4">
              <ShieldAlert size={64} className="opacity-20" />
              <p className="text-lg">Monitoring agent traffic...</p>
            </div>
          )}

          {frame >= alertAppearsAt && (
            <div 
              className="bg-white rounded-xl shadow-lg border border-red-100 p-6 flex flex-col gap-4 transform-gpu"
              style={{ transform: `scale(${alertScale})`, opacity: alertScale }}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3 text-red-600">
                  <ShieldAlert size={28} />
                  <h2 className="text-xl font-semibold">Human-in-the-Loop Required</h2>
                </div>
                {isDenied ? (
                  <span className="px-3 py-1 bg-red-100 text-red-700 rounded-full text-sm font-bold tracking-wide">DENIED</span>
                ) : (
                  <span className="px-3 py-1 bg-amber-100 text-amber-700 rounded-full text-sm font-bold tracking-wide animate-pulse">PENDING</span>
                )}
              </div>
              
              <div className="p-4 bg-slate-50 rounded-lg border border-slate-200">
                <div className="grid grid-cols-3 gap-y-2 text-sm">
                  <span className="text-slate-500 font-medium">Policy Match:</span>
                  <span className="col-span-2 text-slate-800 font-medium text-red-600">admin_role_requires_approval.rego</span>
                  
                  <span className="text-slate-500 font-medium">Tool Call:</span>
                  <span className="col-span-2 font-mono text-slate-700">iam.assign_role</span>
                  
                  <span className="text-slate-500 font-medium">Payload:</span>
                  <span className="col-span-2 font-mono text-xs bg-slate-200 p-2 rounded text-slate-700">
                    {`{"role": "admin", "user": "attacker@external.com"}`}
                  </span>
                </div>
              </div>

              {!isDenied && (
                <div className="flex justify-end gap-3 mt-2">
                  <button className="px-6 py-2 bg-slate-100 text-slate-600 font-semibold rounded-lg">Approve</button>
                  <button className="px-6 py-2 bg-red-600 text-white font-semibold rounded-lg shadow-sm">Deny Action</button>
                </div>
              )}
            </div>
          )}

          {/* Fake Cursor */}
          {frame >= 600 && frame < 850 && (
            <div 
              className="absolute pointer-events-none z-50 text-slate-800 transform-gpu"
              style={{ 
                left: cursorX, 
                top: cursorY,
                transform: `scale(${cursorScale})`,
                transition: 'transform 0.1s ease-out'
              }}
            >
              <MousePointer2 size={32} className="fill-slate-800 drop-shadow-md" />
            </div>
          )}

        </div>
      </div>
    </div>
  );
};
