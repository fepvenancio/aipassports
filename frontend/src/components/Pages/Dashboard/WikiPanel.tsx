import { useState } from 'react';
import { useWiki } from '../../../hooks/useWiki';
import { SkeletonSlugItem, SkeletonText } from '../../UI/CustomSkeleton';
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '../../UI/Card';
import Button from '../../UI/Button';
import Input from '../../UI/Input';
import Badge from '../../UI/Badge';

const STATUS_LABEL: Record<string, string> = {
  'fetching-slugs':    'Loading pages...',
  'fetching-pointer':  'Reading NEAR index...',
  'decrypting-tee':    'Decrypting in TEE...',
  'saving-walrus':     'Uploading to Walrus...',
  'committing-near':   'Committing to NEAR...',
  'deleting':          'Removing page...',
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
    <div className="flex h-full w-full gap-4 animate-fade-in">

      {/* ── Page List Sidebar ────────────────────────────────────────────────── */}
      <Card className="w-60 shrink-0 flex flex-col overflow-hidden">
        
        {/* Sidebar Header */}
        <CardHeader className="py-2.5">
          <CardTitle>WIKI MEMORY</CardTitle>
          <Button
            variant="outline"
            size="xs"
            onClick={startNewPage}
          >
            + New
          </Button>
        </CardHeader>

        {/* Sidebar List */}
        <CardContent className="flex-grow overflow-y-auto py-2 p-0 gap-0">
          {state.status === 'fetching-slugs' ? (
            Array.from({ length: 4 }).map((_, i) => <SkeletonSlugItem key={i} />)
          ) : state.slugs.length === 0 && !state.isNewPage ? (
            <div className="py-12 text-center text-slate-500 text-xs flex flex-col items-center gap-2">
              <span className="text-3xl select-none">📄</span>
              <span className="font-medium font-sans">No pages found</span>
            </div>
          ) : (
            <div className="flex flex-col gap-0.5 px-2">
              {state.slugs.map((slug) => {
                const active = slug === state.selectedSlug;
                return (
                  <Button
                    key={slug}
                    onClick={() => selectPage(slug)}
                    variant={active ? 'secondary' : 'ghost'}
                    className={`w-full flex items-center gap-2.5 justify-start text-xs font-mono truncate px-3 py-2 ${
                      active ? 'bg-slate-950 border border-slate-800 text-cyan-400 font-semibold shadow-inner' : ''
                    }`}
                  >
                    <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${active ? 'bg-cyan-400' : 'bg-slate-600'}`} />
                    <span className="truncate flex-grow text-left">{slug}</span>
                  </Button>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Editor Canvas ───────────────────────────────────────────────────── */}
      <Card className="flex-1 flex flex-col overflow-hidden">
        
        {!state.isNewPage && !state.selectedSlug ? (
          <EmptyEditor onNew={startNewPage} />
        ) : (
          <>
            {/* Toolbar Header */}
            <CardHeader className="py-2.5 flex items-center justify-between gap-4">
              
              <div className="flex items-center gap-3">
                {state.isNewPage ? (
                  <Input
                    id="input-wiki-slug"
                    type="text"
                    mono
                    className="max-w-[180px] px-2.5 py-1 text-xs"
                    placeholder="page-slug"
                    value={newSlug}
                    onChange={(e) => setNewSlug(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ''))}
                  />
                ) : (
                  <Badge variant="default" className="text-xs px-2.5 py-0.5 font-semibold">
                    {state.selectedSlug}
                  </Badge>
                )}

                {/* Unsaved changes indicator */}
                {hasUnsavedChanges && state.status === 'idle' && (
                  <Badge variant="warning" className="text-[9px] px-2 py-0.5 select-none font-semibold">
                    UNSAVED
                  </Badge>
                )}
              </div>

              <div className="flex items-center gap-3 shrink-0">
                {/* Busy status */}
                {isBusy && statusLabel && (
                  <Badge variant="default" className="px-2 py-0.5 font-semibold select-none">
                    <span className="w-3 h-3 rounded-full border border-slate-800 border-t-cyan-400 animate-spin" />
                    <span>{statusLabel}</span>
                  </Badge>
                )}

                {/* Error badge */}
                {state.status === 'error' && (
                  <Badge variant="destructive" className="px-2 py-0.5 font-semibold">
                    {state.errorMessage?.slice(0, 40)}
                  </Badge>
                )}

                {/* Actions */}
                <div className="flex gap-2">
                  {!state.isNewPage && state.selectedSlug && (
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => { if (confirm(`Delete "${state.selectedSlug}"?`)) deletePage(state.selectedSlug!); }}
                      disabled={isBusy}
                    >
                      Delete
                    </Button>
                  )}

                  <Button
                    id="btn-save-wiki"
                    variant="default"
                    size="sm"
                    onClick={handleSave}
                    disabled={isBusy || (state.isNewPage ? !newSlug : !hasUnsavedChanges)}
                  >
                    {state.status === 'saving-walrus' || state.status === 'committing-near' ? (
                      <span className="flex items-center gap-1.5">
                        <span className="w-3.5 h-3.5 rounded-full border border-slate-950/20 border-t-slate-950 animate-spin" />
                        Saving...
                      </span>
                    ) : (
                      state.isNewPage ? 'Create Page' : 'Save Changes'
                    )}
                  </Button>
                </div>
              </div>
            </CardHeader>

            {/* Loading skeleton while decrypting */}
            {(state.status === 'fetching-pointer' || state.status === 'decrypting-tee') ? (
              <div className="flex-grow p-6">
                <SkeletonText lines={8} />
              </div>
            ) : (
              <textarea
                id="editor-wiki-content"
                className="flex-grow w-full bg-transparent border-0 outline-none text-slate-100 p-6 leading-relaxed font-mono text-sm resize-none focus:ring-0 focus:outline-none"
                value={state.content}
                onChange={(e) => setContent(e.target.value)}
                placeholder={`Write your wiki page in Markdown...\n\nAll content is derived, encrypted (AES-256-GCM), and sealed inside the hardware TEE before uploading.`}
              />
            )}

            {/* Metadata Footer */}
            {state.pointer && (
              <CardFooter className="py-2.5">
                <span>blob: <span className="text-slate-400">{state.pointer.blob_id.slice(0, 24)}...</span></span>
                <span>sha256: <span className="text-slate-400">{state.pointer.content_sha256.slice(0, 16)}...</span></span>
                <span>updated: <span className="text-slate-400">{new Date(state.pointer.updated_at_ms).toLocaleString()}</span></span>
              </CardFooter>
            )}
          </>
        )}
      </Card>
    </div>
  );
}

function EmptyEditor({ onNew }: { onNew: () => void }) {
  return (
    <div className="flex-grow flex flex-col items-center justify-center gap-4 text-slate-500 select-none py-16">
      <span className="text-5xl">📝</span>
      <p className="text-xs font-semibold text-slate-400">Select a wiki page to view or create a new one</p>
      <Button variant="outline" size="sm" onClick={onNew}>
        + New Wiki Page
      </Button>
    </div>
  );
}
