import React from 'react';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  mono?: boolean;
}

export default function Input({
  className = '',
  mono = false,
  ...props
}: InputProps) {
  
  const baseClasses = 'w-full bg-slate-950 border border-slate-800 text-slate-100 rounded-lg px-3 py-2 text-xs outline-none transition-all focus:border-cyan-500/55 placeholder:text-slate-600 disabled:opacity-50 disabled:cursor-not-allowed';
  const fontClass = mono ? 'font-mono' : 'font-sans';
  
  const combinedClasses = [
    baseClasses,
    fontClass,
    className
  ].filter(Boolean).join(' ');

  return (
    <input className={combinedClasses} {...props} />
  );
}
