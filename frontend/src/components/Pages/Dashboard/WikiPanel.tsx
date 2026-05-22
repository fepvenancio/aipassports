import { useState } from 'react';
import { useWiki } from '../../../hooks/useWiki';
import { SkeletonSlugItem, SkeletonText } from '../../UI/CustomSkeleton';

const STATUS_LABEL: Record<string, string> = {
  'fetching-slugs':    '› Loading pages…',
  'fetching-pointer':  '› Reading NEAR index…',
  'decrypting-tee':    '› Decrypting in TEE…',
  'saving-walrus':     '› Uploading to Walrus…',
  'committing-near':   '› Committing to NEAR…',
  'deleting':          '› Removing…',
};

export default function WikiPanel({ nearAccountId }: { nearAccountId: string }) {
  const { state, hasUnsavedChanges, selectPage, startNewPage, savePage, deletePage, setContent } = useWiki(nearAccountId);
  const [newSlug, setNewSlug] = useState('');

  const isBusy = state.status !== 'idle' && state.status !== 'error';
  const statusLabel = STATUS_LABEL[state.status];

  async function handleSave() {
    const slug = state.isNewPage ? newSlug : state.selectedSlug!;
    if (!slug) return;
    await savePage(slug);
    if (state.isNewPage) setNewSlug('');
  }

  return (
    <div style={{ display: 'flex', height: '100%', gap: 16 }}>

      {/* ── Slug list ────────────────────────────────────────────────────── */}
      <div className="glass" style={{ width: 252, flexShrink: 0, borderRadius: 12, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Header */}
        <div style={{ padding: '13px 14px 10px', borderBottom: '1px solid var(--color-border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-text-3)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            WIKI PAGES
          </span>
          <button className="btn btn-ghost btn-xs" onClick={startNewPage} style={{ gap: 4, padding: '3px 9px' }}>
            <span style={{ fontSize: 13 }}>+</span> New
          </button>
        </div>

        {/* List */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '6px 0' }}>
          {state.status === 'fetching-slugs' ? (
            Array.from({ length: 4 }).map((_, i) => <SkeletonSlugItem key={i} />)
          ) : state.slugs.length === 0 && !state.isNewPage ? (
            <div style={{ padding: '28px 14px', textAlign: 'center', color: 'var(--color-text-3)', fontSize: 12 }}>
              <div style={{ fontSize: 28, marginBottom: 10 }}>📄</div>
              No pages yet
            </div>
          ) : (
            state.slugs.map((slug) => {
              const active = slug === state.selectedSlug;
              return (
                <button
                  key={slug}
                  onClick={() => selectPage(slug)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    width: '100%', padding: '8px 14px',
                    background: active ? 'var(--color-accent-dim)' : 'transparent',
                    border: 'none', cursor: 'pointer', textAlign: 'left',
                    borderLeft: `2px solid ${active ? 'var(--color-accent)' : 'transparent'}`,
                    transition: 'all 0.12s',
                  }}
                  onMouseEnter={(e) => { if (!active) (e.currentTarget as HTMLButtonElement).style.background = 'rgba(0,240,255,0.04)'; }}
                  onMouseLeave={(e) => { if (!active) (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
                >
                  <span style={{ width: 6, height: 6, borderRadius: 99, background: active ? 'var(--color-accent)' : 'var(--color-text-3)', flexShrink: 0, transition: 'background 0.12s' }} />
                  <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: active ? 'var(--color-accent)' : 'var(--color-text-2)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {slug}
                  </span>
                </button>
              );
            })
          )}
        </div>
      </div>

      {/* ── Editor ───────────────────────────────────────────────────────── */}
      <div className="glass" style={{ flex: 1, borderRadius: 12, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {!state.isNewPage && !state.selectedSlug ? (
          <EmptyEditor onNew={startNewPage} />
        ) : (
          <>
            {/* Toolbar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 18px', borderBottom: '1px solid var(--color-border)', flexShrink: 0 }}>
              {state.isNewPage ? (
                <input
                  id="input-wiki-slug"
                  className="input input-mono"
                  placeholder="page-slug"
                  value={newSlug}
                  onChange={(e) => setNewSlug(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ''))}
                  style={{ maxWidth: 220, fontSize: 12 }}
                />
              ) : (
                <span style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--color-accent)', padding: '2px 8px', background: 'var(--color-accent-dim)', borderRadius: 5 }}>
                  {state.selectedSlug}
                </span>
              )}

              <div style={{ flex: 1 }} />

              {/* Busy status */}
              {isBusy && statusLabel && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 11, color: 'var(--color-accent)', fontFamily: 'var(--font-mono)' }}>
                  <span className="spinner" style={{ width: 12, height: 12, borderWidth: 1.5 }} />
                  {statusLabel}
                </div>
              )}

              {/* Error */}
              {state.status === 'error' && (
                <span className="badge badge-alert">{state.errorMessage?.slice(0, 40)}</span>
              )}

              {/* Unsaved dot */}
              {hasUnsavedChanges && state.status === 'idle' && (
                <span style={{ width: 6, height: 6, borderRadius: 99, background: 'var(--color-amber)' }} title="Unsaved changes" />
              )}

              {/* Delete */}
              {!state.isNewPage && state.selectedSlug && (
                <button className="btn btn-alert btn-sm" onClick={() => { if (confirm(`Delete "${state.selectedSlug}"?`)) deletePage(state.selectedSlug!); }} disabled={isBusy}>
                  Delete
                </button>
              )}

              {/* Save */}
              <button
                id="btn-save-wiki"
                className="btn btn-accent btn-sm"
                onClick={handleSave}
                disabled={isBusy || (state.isNewPage ? !newSlug : !hasUnsavedChanges)}
              >
                {state.status === 'saving-walrus' || state.status === 'committing-near'
                  ? <><span className="spinner" style={{ width: 12, height: 12, borderWidth: 1.5, borderTopColor: '#03040a', borderColor: 'rgba(0,0,0,0.2)' }} /> Saving…</>
                  : state.isNewPage ? 'Create Page' : 'Save'}
              </button>
            </div>

            {/* Loading skeleton while decrypting */}
            {(state.status === 'fetching-pointer' || state.status === 'decrypting-tee') ? (
              <div style={{ flex: 1, padding: 24 }}>
                <SkeletonText lines={8} />
              </div>
            ) : (
              <textarea
                id="editor-wiki-content"
                className="input textarea input-mono"
                value={state.content}
                onChange={(e) => setContent(e.target.value)}
                placeholder={`Write your wiki page in markdown…\n\nContent is AES-256-GCM encrypted inside the IronClaw TEE before Walrus upload.`}
                style={{ flex: 1, resize: 'none', border: 'none', borderRadius: 0, background: 'transparent', padding: '20px', lineHeight: 1.75, fontSize: 13 }}
              />
            )}

            {/* Metadata footer */}
            {state.pointer && (
              <div style={{ padding: '8px 18px', borderTop: '1px solid var(--color-border)', display: 'flex', gap: 20, fontSize: 10, color: 'var(--color-text-3)', fontFamily: 'var(--font-mono)', flexShrink: 0, flexWrap: 'wrap' }}>
                <span>blob: <span style={{ color: 'var(--color-accent)', opacity: 0.7 }}>{state.pointer.blob_id.slice(0, 20)}…</span></span>
                <span>sha256: <span style={{ color: 'var(--color-accent)', opacity: 0.7 }}>{state.pointer.content_sha256.slice(0, 16)}…</span></span>
                <span>updated: {new Date(state.pointer.updated_at_ms).toLocaleString()}</span>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function EmptyEditor({ onNew }: { onNew: () => void }) {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16, color: 'var(--color-text-3)' }}>
      <div style={{ fontSize: 44 }}>📝</div>
      <p style={{ margin: 0, fontSize: 13 }}>Select a page or create a new one</p>
      <button className="btn btn-ghost btn-sm" onClick={onNew}>+ New Wiki Page</button>
    </div>
  );
}
