// ─────────────────────────────────────────────────────────────────────────────
// CustomSkeleton
// Glowing shimmer placeholder for async content.
// Prevents layout shift during NEAR RPC fetches and TEE decryption.
// ─────────────────────────────────────────────────────────────────────────────

interface SkeletonProps {
  width?: string | number;
  height?: string | number;
  borderRadius?: string | number;
  className?: string;
}

export function CustomSkeleton({
  width = '100%',
  height = 16,
  borderRadius = 6,
  className = '',
}: SkeletonProps) {
  return (
    <div
      className={`skeleton ${className}`}
      style={{ width, height, borderRadius }}
      aria-hidden="true"
    />
  );
}

// ── Preset skeletons ──────────────────────────────────────────────────────────

export function SkeletonText({ lines = 3 }: { lines?: number }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {Array.from({ length: lines }).map((_, i) => (
        <CustomSkeleton
          key={i}
          width={i === lines - 1 ? '65%' : '100%'}
          height={13}
        />
      ))}
    </div>
  );
}

export function SkeletonSlugItem() {
  return (
    <div style={{ padding: '9px 16px', display: 'flex', alignItems: 'center', gap: 10 }}>
      <CustomSkeleton width={12} height={12} borderRadius={99} />
      <CustomSkeleton width="70%" height={12} />
    </div>
  );
}

export function SkeletonCard() {
  return (
    <div
      className="glass"
      style={{ borderRadius: 12, padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}
    >
      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <CustomSkeleton width={32} height={32} borderRadius={8} />
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
          <CustomSkeleton width="60%" height={13} />
          <CustomSkeleton width="40%" height={10} />
        </div>
      </div>
      <SkeletonText lines={2} />
    </div>
  );
}
