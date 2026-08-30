import React from 'react';

export const SeverityBadge = ({ severity }) => {
  const sev = (severity || 'LOW').toUpperCase();

  const styles = {
    CRITICAL: 'bg-red-950/80 text-red-400 border-red-700/60 shadow-red-900/20',
    HIGH: 'bg-amber-950/80 text-amber-400 border-amber-700/60 shadow-amber-900/20',
    MEDIUM: 'bg-yellow-950/80 text-yellow-400 border-yellow-700/60',
    LOW: 'bg-blue-950/80 text-blue-400 border-blue-700/60'
  };

  const dots = {
    CRITICAL: 'bg-red-500 animate-pulse',
    HIGH: 'bg-amber-500',
    MEDIUM: 'bg-yellow-500',
    LOW: 'bg-blue-500'
  };

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 text-xs font-semibold tracking-wider rounded border ${styles[sev] || styles.LOW}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dots[sev] || dots.LOW}`} />
      {sev}
    </span>
  );
};
