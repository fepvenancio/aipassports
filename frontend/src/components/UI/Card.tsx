import React from 'react';

export function Card({ className = '', ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`bg-slate-900 border border-slate-800/80 rounded-xl overflow-hidden shadow-md ${className}`}
      {...props}
    />
  );
}

export function CardHeader({ className = '', ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`px-4 py-3 bg-slate-900/50 border-b border-slate-800/80 flex items-center justify-between shrink-0 gap-4 ${className}`}
      {...props}
    />
  );
}

export function CardTitle({ className = '', ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3
      className={`text-xs font-bold text-slate-500 tracking-wider uppercase select-none ${className}`}
      {...props}
    />
  );
}

export function CardDescription({ className = '', ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return (
    <p
      className={`text-xs text-slate-400 mt-0.5 leading-relaxed ${className}`}
      {...props}
    />
  );
}

export function CardContent({ className = '', ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`p-4 flex flex-col gap-4 ${className}`}
      {...props}
    />
  );
}

export function CardFooter({ className = '', ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`px-6 py-2.5 bg-slate-950 border-t border-slate-800/60 flex items-center justify-between gap-6 text-[10px] font-mono text-slate-500 shrink-0 ${className}`}
      {...props}
    />
  );
}
