import React from 'react';

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  mono?: boolean;
}

export default function Select({
  className = '',
  mono = false,
  children,
  ...props
}: SelectProps) {
  
  const baseClasses = 'w-full bg-slate-950 border border-slate-800 text-slate-100 rounded-lg px-3 py-2 text-xs outline-none transition-all focus:border-cyan-500/55 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed';
  const fontClass = mono ? 'font-mono' : 'font-sans';
  
  const combinedClasses = [
    baseClasses,
    fontClass,
    className
  ].filter(Boolean).join(' ');

  return (
    <select className={combinedClasses} {...props}>
      {children}
    </select>
  );
}
