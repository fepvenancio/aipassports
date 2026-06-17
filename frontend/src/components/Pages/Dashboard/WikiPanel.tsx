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
  const [previewMode, setPreviewMode] = useState(false);

  const isBusy = state.status !== 'idle' && state.status !== 'error';
  const statusLabel = STATUS_LABEL[state.status];

  function handleSelect(slug: string) {
    setPreviewMode(false);
    selectPage(slug);
  }

  function handleNew() {
    setPreviewMode(false);
    startNewPage();
  }

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
            onClick={handleNew}
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
                    onClick={() => handleSelect(slug)}
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
          <EmptyEditor onNew={handleNew} />
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

                {/* Preview/Edit Toggle */}
                {!state.isNewPage && state.selectedSlug && (
                  <Button
                    variant="outline"
                    size="xs"
                    onClick={() => setPreviewMode(!previewMode)}
                    className="shrink-0"
                  >
                    {previewMode ? '📝 Edit' : '👁️ Preview'}
                  </Button>
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
            ) : previewMode ? (
              <div className="flex-grow overflow-y-auto p-6 leading-relaxed text-slate-100 markdown-preview select-text">
                {renderMarkdown(state.content || '')}
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

// ─── Simple Custom Markdown Renderer ──────────────────────────────────────────
function renderMarkdown(md: string) {
  if (!md) return null;
  const lines = md.split('\n');
  let inCodeBlock = false;
  let codeContent = '';

  const rendered = lines.map((line, index) => {
    if (line.trim().startsWith('```')) {
      if (inCodeBlock) {
        inCodeBlock = false;
        const code = codeContent;
        codeContent = '';
        return (
          <pre key={index} className="bg-slate-950 border border-slate-900 rounded-lg p-4 my-3 font-mono text-xs text-cyan-400 overflow-x-auto select-text">
            <code>{code}</code>
          </pre>
        );
      } else {
        inCodeBlock = true;
        return null;
      }
    }

    if (inCodeBlock) {
      codeContent += line + '\n';
      return null;
    }

    if (line.startsWith('# ')) {
      return <h1 key={index} className="text-2xl font-bold text-slate-100 border-b border-slate-800 pb-2 mt-6 mb-4">{parseInline(line.slice(2))}</h1>;
    }
    if (line.startsWith('## ')) {
      return <h2 key={index} className="text-xl font-bold text-slate-100 mt-5 mb-3">{parseInline(line.slice(3))}</h2>;
    }
    if (line.startsWith('### ')) {
      return <h3 key={index} className="text-base font-bold text-slate-200 mt-4 mb-2">{parseInline(line.slice(4))}</h3>;
    }
    if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
      return (
        <li key={index} className="ml-5 list-disc text-slate-300 text-sm py-1 font-sans leading-relaxed">
          {parseInline(line.trim().slice(2))}
        </li>
      );
    }
    if (line.trim() === '') {
      return <div key={index} className="h-3" />;
    }

    return (
      <p key={index} className="text-slate-300 text-sm py-1.5 leading-relaxed font-sans select-text">
        {parseInline(line)}
      </p>
    );
  }).filter(el => el !== null);

  return <div className="space-y-1 font-sans">{rendered}</div>;
}

function parseInline(text: string): React.ReactNode[] {
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/);
  return parts.map((part, idx) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={idx} className="font-bold text-slate-100">{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={idx} className="bg-slate-900 border border-slate-800/80 px-1.5 py-0.5 rounded font-mono text-xs text-cyan-300">{part.slice(1, -1)}</code>;
    }
    return part;
  });
}
