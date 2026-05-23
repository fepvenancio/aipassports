import React from 'react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'outline' | 'secondary' | 'ghost' | 'destructive';
  size?: 'default' | 'sm' | 'xs' | 'icon';
}

export default function Button({
  className = '',
  variant = 'default',
  size = 'default',
  children,
  ...props
}: ButtonProps) {
  
  // Base classes
  const baseClasses = 'inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-all duration-150 select-none outline-none disabled:opacity-50 disabled:cursor-not-allowed disabled:pointer-events-none cursor-pointer';

  // Variant styles
  const variants = {
    default: 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold shadow-md shadow-cyan-500/10 active:scale-[0.98]',
    outline: 'bg-transparent border border-slate-800 hover:bg-slate-800/80 hover:border-slate-700 text-slate-300 hover:text-slate-100',
    secondary: 'bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-100',
    ghost: 'bg-transparent hover:bg-slate-800/60 text-slate-400 hover:text-slate-200 border border-transparent',
    destructive: 'bg-transparent border border-rose-950/40 text-rose-400 hover:bg-rose-950/20 hover:border-rose-900/50 hover:text-rose-300',
  };

  // Size styles
  const sizes = {
    default: 'px-4 py-2 text-sm',
    sm: 'px-3 py-1.5 text-xs',
    xs: 'px-2 py-1 text-[10px] rounded-md',
    icon: 'p-1.5 rounded-lg',
  };

  const combinedClasses = [
    baseClasses,
    variants[variant],
    sizes[size],
    className
  ].filter(Boolean).join(' ');

  return (
    <button className={combinedClasses} {...props}>
      {children}
    </button>
  );
}
