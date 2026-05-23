import React from 'react';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'secondary' | 'success' | 'destructive' | 'warning' | 'muted';
}

export default function Badge({
  className = '',
  variant = 'default',
  children,
  ...props
}: BadgeProps) {
  
  const baseClasses = 'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-medium tracking-wide border select-none transition-colors';

  const variants = {
    default: 'bg-cyan-950/20 border-cyan-800/40 text-cyan-400',
    secondary: 'bg-slate-950 border-slate-800 text-slate-400',
    success: 'bg-emerald-950/20 border-emerald-900/30 text-emerald-400',
    destructive: 'bg-rose-950/20 border-rose-900/30 text-rose-400',
    warning: 'bg-amber-950/20 border-amber-900/30 text-amber-400',
    muted: 'bg-slate-900/50 border-transparent text-slate-500',
  };

  const combinedClasses = [
    baseClasses,
    variants[variant],
    className
  ].filter(Boolean).join(' ');

  return (
    <span className={combinedClasses} {...props}>
      {children}
    </span>
  );
}
