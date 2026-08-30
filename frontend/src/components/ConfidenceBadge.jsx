import React from 'react';

export const ConfidenceBadge = ({ score }) => {
  const pct = Math.round((score || 0) * 100);

  let color = 'text-green-400 bg-green-950/60 border-green-800/50';
  if (pct < 60) {
    color = 'text-red-400 bg-red-950/60 border-red-800/50';
  } else if (pct < 85) {
    color = 'text-yellow-400 bg-yellow-950/60 border-yellow-800/50';
  }

  return (
    <div className={`inline-flex items-center gap-2 px-2.5 py-1 rounded border text-xs font-mono font-medium ${color}`}>
      <span>CONFIDENCE:</span>
      <span className="font-bold text-sm">{pct}%</span>
    </div>
  );
};
