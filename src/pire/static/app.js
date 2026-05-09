const sidebar = document.getElementById('sidebar');
const toggle = document.getElementById('sidebar-toggle');
const uploadInput = document.getElementById('pcap-upload');
const metaSummary = document.getElementById('meta-summary');
const statusRight = document.getElementById('status-right');
const chatForm = document.getElementById('chat-form');
const chatInput = document.getElementById('chat-input');
const chatScroll = document.getElementById('chat-scroll');
const chatAttachmentStrip = document.getElementById('chat-attachment-strip');
const activityTitle = document.getElementById('activity-title');
const activityDot = document.getElementById('activity-dot');
const activitySteps = document.getElementById('activity-steps');
const pcapList = document.getElementById('pcap-list');
const storageSummary = document.getElementById('storage-summary');
const deleteExportsButton = document.getElementById('delete-exports-button');
const pruneCacheButton = document.getElementById('prune-cache-button');
const deleteCaseButton = document.getElementById('delete-case-button');
const mainGrid = document.querySelector('.main-grid');
const workspace = document.querySelector('.workspace');
const refreshButton = document.getElementById('refresh-button');
const detailContent = document.getElementById('detail-content');
const summaryContent = document.getElementById('summary-content');
const triageSummaryContent = document.getElementById('triage-summary-content');
const timelineTable = document.getElementById('timeline-table');
const protocolsContent = document.getElementById('protocols-content');
const conversationsContent = document.getElementById('conversations-content');
const endpointsContent = document.getElementById('endpoints-content');
const hostsContent = document.getElementById('hosts-content');
const zeekSummaryContent = document.getElementById('zeek-summary-content');
const knowledgeQueueContent = document.getElementById('knowledge-queue-content');
const knowledgeTreeContent = document.getElementById('knowledge-tree-content');
const knowledgeNoteEditor = document.getElementById('knowledge-note-editor');
const knowledgeNoteTitle = document.getElementById('knowledge-note-title');
const knowledgeNotePath = document.getElementById('knowledge-note-path');
const knowledgeNoteText = document.getElementById('knowledge-note-text');
const knowledgeNoteClose = document.getElementById('knowledge-note-close');
const knowledgeNoteSave = document.getElementById('knowledge-note-save');
const knowledgeNoteDelete = document.getElementById('knowledge-note-delete');
const zeekConnTable = document.getElementById('zeek-conn-table');
const zeekDnsTable = document.getElementById('zeek-dns-table');
const zeekHttpTable = document.getElementById('zeek-http-table');
const zeekFilesTable = document.getElementById('zeek-files-table');
const zeekSslTable = document.getElementById('zeek-ssl-table');
const zeekX509Table = document.getElementById('zeek-x509-table');
const zeekSmtpTable = document.getElementById('zeek-smtp-table');
const zeekSmbFilesTable = document.getElementById('zeek-smb-files-table');
const zeekSmbMappingTable = document.getElementById('zeek-smb-mapping-table');
const zeekDceRpcTable = document.getElementById('zeek-dce-rpc-table');
const zeekNoticeTable = document.getElementById('zeek-notice-table');
const zeekWeirdTable = document.getElementById('zeek-weird-table');
const zeekGenericTable = document.getElementById('zeek-generic-table');
const capinfosContent = document.getElementById('capinfos-content');
const metadataContent = document.getElementById('metadata-content');
const presetSelect = document.getElementById('preset-select');
const presetSwatches = document.getElementById('preset-swatches');
const applyPresetButton = document.getElementById('apply-preset');
const saveThemeButton = document.getElementById('save-theme');
const toggleEditorButton = document.getElementById('toggle-editor');
const paletteEditor = document.getElementById('palette-editor');
const paletteGrid = document.getElementById('palette-grid');

let currentEvidenceView = 'triage';
let currentLogView = 'zeek-summary';
let currentKnowledgeView = 'queue';

const themeStorageKey = 'pire-theme-palette';
const paletteKeys = ['bg', 'panel', 'panelAlt', 'panel3', 'accent', 'accentSoft', 'text', 'muted', 'border', 'success', 'danger'];
const defaultPalette = {
  bg: '#06080d',
  panel: '#0c1119',
  panelAlt: '#101722',
  panel3: '#131d2b',
  accent: '#58e4ff',
  accentSoft: 'rgba(47, 116, 255, 0.15)',
  text: '#eaf2ff',
  muted: '#91a2bf',
  border: 'rgba(110, 145, 194, 0.18)',
  success: '#52de7d',
  danger: '#ff7c7c',
};
const presetDefinitions = {
  'Midnight Cyan': { ...defaultPalette },
  'Dracula Classic': {
    bg: '#282A36', panel: '#343746', panelAlt: '#424450', panel3: '#21222C', accent: '#8BE9FD', accentSoft: '#BD93F9', text: '#F8F8F2', muted: '#6272A4', border: defaultPalette.border, success: '#50FA7B', danger: '#FF5555'
  },
  'Alucard Dark': {
    bg: '#16140f', panel: '#211d17', panelAlt: '#2a251d', panel3: '#120f0b', accent: '#036A96', accentSoft: '#644AC9', text: '#f2eee5', muted: '#b8ae96', border: defaultPalette.border, success: '#14710A', danger: '#CB3A2A'
  },
  'Midnight Amber': {
    bg: '#1e1b2e', panel: '#2b2740', panelAlt: '#35304f', panel3: '#433a5f', accent: '#f59e0b', accentSoft: '#fcd34d', text: '#fef9c3', muted: '#c4b5fd', border: defaultPalette.border, success: '#a7f3d0', danger: '#fdba74'
  },
  'Slate Harbor': {
    bg: '#222831', panel: '#393E46', panelAlt: '#2e343b', panel3: '#454f5a', accent: '#00ADB5', accentSoft: '#95E1D3', text: '#EEEEEE', muted: '#C5D3E8', border: defaultPalette.border, success: '#95E1D3', danger: '#F38181'
  },
  'Royal Grape': {
    bg: '#000000', panel: '#1b1026', panelAlt: '#2a1738', panel3: '#3b2350', accent: '#892CDC', accentSoft: '#BC6FF1', text: '#F4EFFF', muted: '#BC6FF1', border: defaultPalette.border, success: '#BC6FF1', danger: '#FF165D'
  },
  'Neon Sorbet': {
    bg: '#1a1d24', panel: '#242833', panelAlt: '#2f3441', panel3: '#3a4151', accent: '#FF9A00', accentSoft: '#F6F7D7', text: '#FFF8E8', muted: '#3EC1D3', border: defaultPalette.border, success: '#3EC1D3', danger: '#FF165D'
  },
};
let palette = { ...defaultPalette };

let currentPcap = null;
let currentOverview = null;
let openclawState = null;
let loadingPcap = null;
let knownPcaps = [];
let currentZeekSummary = null;
let currentKnowledge = null;
let currentKnowledgeNote = null;
let currentSelectedKnowledgeItemId = null;
let zeekLogState = {};
let chatAttachments = [];
let currentDossier = null;
let currentDossierSectionId = null;
let currentDossierLineIndex = null;
let currentKnowledgeAction = null;
let detailMode = 'knowledge';
let currentActivity = { title: 'Idle', steps: [], active: -1, busy: false };
let conversationPageState = null;
let hostPageState = null;
let endpointPageState = null;
let timelineState = { rows: [], page: 1, pageSize: 8 };
let dataViewSearchTimers = {};
let dataViewUiState = {
  endpoints: { columns: [], query: '', sortBy: 'interestingness', sortDir: 'desc' },
  hosts: { columns: [], query: '', sortBy: 'interestingness', sortDir: 'desc' },
  conversations: { columns: [], query: '', sortBy: 'connections', sortDir: 'desc' },
};
let currentGenericZeekLog = '';

const zeekTableRegistry = {
  'conn.log': { element: zeekConnTable, tab: 'zeek-conn' },
  'dns.log': { element: zeekDnsTable, tab: 'zeek-dns' },
  'http.log': { element: zeekHttpTable, tab: 'zeek-http' },
  'files.log': { element: zeekFilesTable, tab: 'zeek-files' },
  'ssl.log': { element: zeekSslTable, tab: 'zeek-ssl' },
  'x509.log': { element: zeekX509Table, tab: 'zeek-x509' },
  'smtp.log': { element: zeekSmtpTable, tab: 'zeek-smtp' },
  'smb_files.log': { element: zeekSmbFilesTable, tab: 'zeek-smb-files' },
  'smb_mapping.log': { element: zeekSmbMappingTable, tab: 'zeek-smb-mapping' },
  'dce_rpc.log': { element: zeekDceRpcTable, tab: 'zeek-dce-rpc' },
  'notice.log': { element: zeekNoticeTable, tab: 'zeek-notice' },
  'weird.log': { element: zeekWeirdTable, tab: 'zeek-weird' },
  '__generic__': { element: zeekGenericTable, tab: 'zeek-viewer' },
};

const zeekDefaultColumns = {
  'conn.log': ['ts', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'service', 'conn_state', 'orig_bytes', 'resp_bytes'],
  'dns.log': ['ts', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'query', 'qtype_name', 'rcode_name', 'answers'],
  'http.log': ['ts', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'method', 'host', 'uri', 'status_code', 'resp_mime_types', 'orig_mime_types', 'user_agent'],
  'files.log': ['ts', 'source', 'mime_type', 'filename', 'seen_bytes', 'sha256'],
  'ssl.log': ['ts', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'server_name', 'version', 'cipher', 'validation_status'],
  'x509.log': ['ts', 'certificate.subject', 'certificate.issuer', 'san.dns', 'certificate.key_length'],
  'smtp.log': ['ts', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'helo', 'mailfrom', 'rcptto', 'last_reply', 'tls'],
  'smb_files.log': ['ts', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'action', 'path', 'name', 'size'],
  'smb_mapping.log': ['ts', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'path', 'share_type', 'service'],
  'dce_rpc.log': ['ts', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'endpoint', 'operation', 'named_pipe', 'rtt'],
  'notice.log': ['ts', 'src_ip', 'dest_ip', 'note', 'msg', 'sub'],
  'weird.log': ['ts', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'name', 'addl', 'source'],
};

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (!value) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const digits = size >= 100 || unitIndex === 0 ? 0 : size >= 10 ? 1 : 2;
  return `${size.toFixed(digits)} ${units[unitIndex]}`;
}

function appendMessage(text, side = 'outgoing', stamp = 'You • now') {
  const wrapper = document.createElement('div');
  wrapper.className = `message ${side}`;
  wrapper.innerHTML = `<div class="stamp">${escapeHtml(stamp)}</div><div class="bubble"></div>`;
  wrapper.querySelector('.bubble').textContent = text;
  chatScroll.appendChild(wrapper);
  chatScroll.scrollTop = chatScroll.scrollHeight;
  return wrapper;
}

function renderChatAttachmentStrip() {
  if (!chatAttachmentStrip) return;
  if (!chatAttachments.length) {
    chatAttachmentStrip.innerHTML = '';
    chatAttachmentStrip.classList.remove('has-items');
    return;
  }
  chatAttachmentStrip.classList.add('has-items');
  chatAttachmentStrip.innerHTML = chatAttachments.map((attachment) => `
    <div class="chat-attachment-chip">
      <img src="${escapeHtml(attachment.previewUrl || attachment.dataUrl || '')}" alt="${escapeHtml(attachment.name || 'Pasted image')}" class="chat-attachment-thumb" />
      <div class="chat-attachment-meta">
        <strong>${escapeHtml(attachment.name || 'Pasted image')}</strong>
        <span>${escapeHtml(attachment.mimeType || 'image')}</span>
      </div>
      <button type="button" class="chat-attachment-remove" data-attachment-id="${escapeHtml(attachment.id)}" aria-label="Remove attachment">×</button>
    </div>
  `).join('');
  chatAttachmentStrip.querySelectorAll('[data-attachment-id]').forEach((button) => {
    button.addEventListener('click', () => removeChatAttachment(button.getAttribute('data-attachment-id') || ''));
  });
}

function removeChatAttachment(id) {
  const removed = chatAttachments.find((item) => item.id === id);
  if (removed?.previewUrl?.startsWith('blob:')) {
    URL.revokeObjectURL(removed.previewUrl);
  }
  chatAttachments = chatAttachments.filter((item) => item.id !== id);
  renderChatAttachmentStrip();
}

function clearChatAttachments() {
  for (const attachment of chatAttachments) {
    if (attachment.previewUrl?.startsWith('blob:')) {
      URL.revokeObjectURL(attachment.previewUrl);
    }
  }
  chatAttachments = [];
  renderChatAttachmentStrip();
}

function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => reject(new Error(`Could not read ${file.name || 'pasted image'}`));
    reader.readAsDataURL(file);
  });
}

async function addPastedImage(file) {
  if (!file || !String(file.type || '').startsWith('image/')) return false;
  const dataUrl = await fileToDataUrl(file);
  const previewUrl = URL.createObjectURL(file);
  chatAttachments.push({
    id: `attachment-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    kind: 'image',
    name: file.name || `pasted-image-${Date.now()}.png`,
    mimeType: file.type || 'image/png',
    dataUrl,
    previewUrl,
  });
  renderChatAttachmentStrip();
  return true;
}

async function handleChatPaste(event) {
  const items = Array.from(event.clipboardData?.items || []);
  const imageItems = items.filter((item) => String(item.type || '').startsWith('image/'));
  if (!imageItems.length) return;
  event.preventDefault();
  for (const item of imageItems) {
    const file = item.getAsFile();
    if (file) await addPastedImage(file);
  }
}

function defaultImageOnlyPrompt() {
  const count = chatAttachments.length;
  return `Please inspect the attached screenshot${count === 1 ? '' : 's'} in the context of the current PCAP and case. If the screenshot is visible, describe what stands out and connect it to the investigation. If it is not visually available, say that briefly and still suggest the next narrowest useful move from the current packet evidence.`;
}

function appendPendingMessage(text = 'PIRE is investigating your question...') {
  const wrapper = appendMessage(text, 'incoming pending', 'PIRE • working');
  wrapper.dataset.pending = 'true';
  return wrapper;
}

function updatePendingMessage(wrapper, text, stamp = 'PIRE • working') {
  if (!wrapper) return;
  const stampEl = wrapper.querySelector('.stamp');
  const bubbleEl = wrapper.querySelector('.bubble');
  if (stampEl) stampEl.textContent = stamp;
  if (bubbleEl) bubbleEl.textContent = text;
}

function resolvePendingMessage(wrapper, text, stamp = 'PIRE • now') {
  if (!wrapper) {
    appendMessage(text, 'incoming', stamp);
    return;
  }
  wrapper.dataset.pending = 'false';
  wrapper.classList.remove('pending');
  const stampEl = wrapper.querySelector('.stamp');
  const bubbleEl = wrapper.querySelector('.bubble');
  if (stampEl) stampEl.textContent = stamp;
  if (bubbleEl) bubbleEl.textContent = text;
}

function renderTable(rows) {
  if (!rows || !rows.length) {
    return '<div class="empty-state">No rows to show.</div>';
  }
  const columns = Object.keys(rows[0]);
  const head = columns.map((col) => `<th>${escapeHtml(col)}</th>`).join('');
  const body = rows.map((row) => `<tr>${columns.map((col) => `<td>${escapeHtml(row[col] || '')}</td>`).join('')}</tr>`).join('');
  return `<table class="data-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function renderStorageSummary(storage) {
  if (!storageSummary) return;
  if (!storage) {
    storageSummary.innerHTML = '<div class="storage-empty">Runtime storage summary unavailable.</div>';
    return;
  }
  storageSummary.innerHTML = `
    <div><span>Incoming</span><strong>${formatBytes(storage.incoming?.bytes)} • ${escapeHtml(storage.incoming?.pcap_count ?? 0)} PCAPs</strong></div>
    <div><span>Exports</span><strong>${formatBytes(storage.exports?.bytes)} • ${escapeHtml(storage.exports?.file_count ?? 0)} files</strong></div>
    <div><span>Zeek cache</span><strong>${formatBytes(storage.zeek_cache?.bytes)} • ${escapeHtml(storage.zeek_cache?.run_count ?? 0)} runs</strong></div>
    <div><span>Library</span><strong>${formatBytes(storage.library?.bytes)}</strong></div>
  `;
}

function renderTreeNodes(nodes) {
  if (!nodes || !nodes.length) {
    return '<div class="empty-state">No saved knowledge objects yet.</div>';
  }
  return `<ul class="knowledge-tree-list">${nodes.map((node) => {
    if (node.kind === 'dir') {
      return `<li class="knowledge-tree-node dir"><details open><summary>${escapeHtml(node.name)}</summary>${renderTreeNodes(node.children || [])}</details></li>`;
    }
    return `<li class="knowledge-tree-node file"><button type="button" class="knowledge-file-link" data-note-path="${escapeHtml(node.path || '')}">${escapeHtml(node.name)}</button><code>${escapeHtml(node.path || '')}</code></li>`;
  }).join('')}</ul>`;
}

function renderKnowledgeTree(tree) {
  if (!knowledgeTreeContent) return;
  knowledgeTreeContent.innerHTML = renderTreeNodes(tree || []);
}

function setKnowledgeSaveDirty(isDirty) {
  if (knowledgeNoteSave) knowledgeNoteSave.disabled = !isDirty;
}

function closeKnowledgeNote() {
  currentKnowledgeNote = null;
  knowledgeNoteEditor?.classList.add('hidden');
  if (knowledgeNoteTitle) knowledgeNoteTitle.textContent = 'No note selected';
  if (knowledgeNotePath) knowledgeNotePath.textContent = '';
  if (knowledgeNoteText) knowledgeNoteText.value = '';
  setKnowledgeSaveDirty(false);
}

async function openKnowledgeNote(path) {
  if (!path) return;
  const response = await fetch(`/api/knowledge/note?path=${encodeURIComponent(path)}`);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.detail || 'Unable to open knowledge note');
  currentKnowledgeNote = {
    path: payload.path,
    original: payload.content || '',
  };
  if (knowledgeNoteTitle) knowledgeNoteTitle.textContent = payload.path.split('/').pop() || payload.path;
  if (knowledgeNotePath) knowledgeNotePath.textContent = payload.path;
  if (knowledgeNoteText) knowledgeNoteText.value = payload.content || '';
  knowledgeNoteEditor?.classList.remove('hidden');
  setKnowledgeSaveDirty(false);
}

async function saveKnowledgeNote() {
  if (!currentKnowledgeNote || !knowledgeNoteText) return;
  const content = knowledgeNoteText.value;
  const response = await fetch('/api/knowledge/note', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: currentKnowledgeNote.path, content }),
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.detail || 'Unable to save knowledge note');
  currentKnowledgeNote.original = content;
  setKnowledgeSaveDirty(false);
  appendMessage(`Saved updates to ${currentKnowledgeNote.path}.`, 'incoming', 'PIRE • knowledge');
}

async function deleteKnowledgeNote() {
  if (!currentKnowledgeNote) return;
  if (!window.confirm(`Delete saved knowledge note ${currentKnowledgeNote.path}?`)) return;
  const path = currentKnowledgeNote.path;
  const response = await fetch(`/api/knowledge/note?path=${encodeURIComponent(path)}`, { method: 'DELETE' });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.detail || 'Unable to delete knowledge note');
  closeKnowledgeNote();
  await fetchKnowledge(currentPcap);
  appendMessage(`Deleted saved knowledge note ${path}.`, 'incoming', 'PIRE • knowledge');
}

function knowledgeChipHtml(tag, selected = false, recommended = false) {
  return `<button type="button" class="knowledge-tag ${selected ? 'selected' : ''} ${recommended ? 'recommended' : ''}" data-tag="${escapeHtml(tag)}">${escapeHtml(tag)}</button>`;
}

function renderKnowledgeQueue(queue) {
  if (!knowledgeQueueContent) return;
  if (!queue || !queue.length) {
    currentSelectedKnowledgeItemId = null;
    knowledgeQueueContent.innerHTML = '<div class="empty-state">No knowledge candidates yet. Keep investigating and OpenClaw will surface save-worthy items here.</div>';
    return;
  }
  const selectedStillExists = queue.some((item) => item.item_id === currentSelectedKnowledgeItemId);
  if (!selectedStillExists) currentSelectedKnowledgeItemId = null;
  knowledgeQueueContent.innerHTML = queue.map((item) => {
    const selected = new Set(item.selected_tags || []);
    const recommended = new Set(item.recommended_tags || []);
    const isSelected = item.item_id === currentSelectedKnowledgeItemId;
    return `
      <article class="knowledge-card ${isSelected ? 'selected' : ''}" data-item-id="${escapeHtml(item.item_id)}" data-source-kind="${escapeHtml(item.source_kind)}">
        <div class="knowledge-card-header">
          <div>
            <div class="knowledge-kicker">${escapeHtml(item.source_kind.replaceAll('_', ' '))}</div>
            <h3>${escapeHtml(item.title || 'Untitled knowledge item')}</h3>
          </div>
          <span class="knowledge-status ${escapeHtml(item.status || 'proposed')} ">${escapeHtml(item.status || 'proposed')}</span>
        </div>
        <p class="knowledge-summary">${escapeHtml(item.summary || '')}</p>
        <div class="knowledge-rationale"><strong>OpenClaw recommendation:</strong> ${escapeHtml(item.rationale || 'No rationale provided yet.')}</div>
        <div class="knowledge-selection-hint">${isSelected ? 'Selected for chat context review. Click again to unselect.' : 'Click tile to select it before asking chat about this candidate.'}</div>
        <div class="knowledge-tags">${(item.available_tags || []).map((tag) => knowledgeChipHtml(tag, selected.has(tag), recommended.has(tag))).join('')}</div>
        <label class="knowledge-comment-label">Comment / correction</label>
        <textarea class="knowledge-comment" rows="3" placeholder="Add context, correction, or storage guidance...">${escapeHtml(item.comment || '')}</textarea>
        <div class="knowledge-destinations">${(item.destinations || []).length ? `<strong>Current destinations:</strong> ${(item.destinations || []).map((value) => `<code>${escapeHtml(value)}</code>`).join(' ')}` : '<span>No saved destinations yet.</span>'}</div>
        <div class="knowledge-actions-row">
          <button type="button" class="ghost-button knowledge-action" data-knowledge-action="promoted">Promote</button>
          <button type="button" class="ghost-button knowledge-action" data-knowledge-action="reviewed">Needs Review</button>
          <button type="button" class="ghost-button knowledge-action" data-knowledge-action="deleted">Delete</button>
        </div>
      </article>
    `;
  }).join('');
}

function getSelectedKnowledgeCard() {
  if (!knowledgeQueueContent || !currentSelectedKnowledgeItemId) return null;
  return knowledgeQueueContent.querySelector(`.knowledge-card[data-item-id="${CSS.escape(currentSelectedKnowledgeItemId)}"]`);
}

function setSelectedKnowledgeCard(itemId, options = {}) {
  const { silent = false, reason = '' } = options;
  const previousId = currentSelectedKnowledgeItemId;
  const previousCard = getSelectedKnowledgeCard();
  const previousTitle = previousCard?.querySelector('h3')?.textContent?.trim() || 'Knowledge candidate';
  const nextId = previousId === itemId ? null : itemId;
  currentSelectedKnowledgeItemId = nextId;

  knowledgeQueueContent?.querySelectorAll('.knowledge-card').forEach((card) => {
    card.classList.toggle('selected', card.dataset.itemId === currentSelectedKnowledgeItemId);
    const hint = card.querySelector('.knowledge-selection-hint');
    if (hint) {
      hint.textContent = card.dataset.itemId === currentSelectedKnowledgeItemId
        ? 'Selected for chat context review. Click again to unselect.'
        : 'Click tile to select it before asking chat about this candidate.';
    }
  });

  if (silent) return;
  const activeCard = getSelectedKnowledgeCard();
  const title = activeCard?.querySelector('h3')?.textContent?.trim() || previousTitle;
  if (currentSelectedKnowledgeItemId) {
    appendMessage(`${title} selected.`, 'incoming', 'PIRE • knowledge');
  } else if (previousId) {
    appendMessage(reason ? `${title} unselected (${reason}).` : `${title} unselected.`, 'incoming', 'PIRE • knowledge');
  }
}

function clearSelectedKnowledgeCard(reason = '') {
  if (!currentSelectedKnowledgeItemId) return;
  const activeCard = getSelectedKnowledgeCard();
  const title = activeCard?.querySelector('h3')?.textContent?.trim() || 'Knowledge candidate';
  currentSelectedKnowledgeItemId = null;
  knowledgeQueueContent?.querySelectorAll('.knowledge-card.selected').forEach((card) => {
    card.classList.remove('selected');
    const hint = card.querySelector('.knowledge-selection-hint');
    if (hint) hint.textContent = 'Click tile to select it before asking chat about this candidate.';
  });
  appendMessage(reason ? `${title} unselected (${reason}).` : `${title} unselected.`, 'incoming', 'PIRE • knowledge');
}

function getSelectedKnowledgeContext() {
  if (!currentSelectedKnowledgeItemId) return null;
  const item = (currentKnowledge?.queue || []).find((entry) => entry.item_id === currentSelectedKnowledgeItemId);
  if (!item) return null;
  return {
    item_id: item.item_id,
    source_kind: item.source_kind,
    title: item.title || 'Untitled knowledge item',
    summary: item.summary || '',
    rationale: item.rationale || '',
    selected_tags: item.selected_tags || [],
    recommended_tags: item.recommended_tags || [],
    available_tags: item.available_tags || [],
    comment: item.comment || '',
    destinations: item.destinations || [],
    status: item.status || 'proposed',
  };
}

function renderKnowledgePanel(payload) {
  currentKnowledge = payload;
  renderKnowledgeQueue(payload?.queue || []);
  renderKnowledgeTree(payload?.tree || []);
}

async function fetchKnowledge(pcap = currentPcap) {
  if (!pcap) {
    renderKnowledgePanel({ queue: [], tree: currentKnowledge?.tree || [] });
    return;
  }
  const response = await fetch(`/api/knowledge?pcap=${encodeURIComponent(pcap)}`);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.detail || 'Unable to load knowledge view');
  renderKnowledgePanel(payload);
}

async function submitKnowledgeAction(card, status) {
  if (!card) return;
  const itemId = card.dataset.itemId;
  const sourceKind = card.dataset.sourceKind;
  const title = card.querySelector('h3')?.textContent?.trim() || 'Untitled knowledge item';
  const summary = card.querySelector('.knowledge-summary')?.textContent?.trim() || '';
  const rationale = card.querySelector('.knowledge-rationale')?.textContent?.replace(/^OpenClaw recommendation:\s*/, '').trim() || '';
  const comment = card.querySelector('.knowledge-comment')?.value || '';
  const tags = [...card.querySelectorAll('.knowledge-tag.selected')].map((button) => button.dataset.tag).filter(Boolean);
  const response = await fetch('/api/knowledge/object', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      pcap: currentPcap,
      item_id: itemId,
      source_kind: sourceKind,
      title,
      summary,
      rationale,
      tags,
      comment,
      status,
    }),
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.detail || 'Unable to save knowledge item');
  if (currentSelectedKnowledgeItemId === itemId) currentSelectedKnowledgeItemId = null;
  renderKnowledgePanel(payload.knowledge || payload);
  const suffix = status === 'deleted'
    ? 'deleted and moved to trash.'
    : `marked ${status}${tags.length ? ` with tags: ${tags.join(', ')}` : ''}.`;
  appendMessage(`Knowledge item "${title}" ${suffix}`, 'incoming', 'PIRE • knowledge');
}

function replyHtml(text) {
  const safe = escapeHtml(text || '');
  return safe.replace(/\n\n+/g, '</p><p>').replace(/\n/g, '<br>');
}

function updateSidebarLayout() {
  if (!mainGrid) return;
  mainGrid.classList.toggle('sidebar-collapsed-layout', sidebar.classList.contains('collapsed'));
}

function setDetailMode(mode = 'knowledge') {
  detailMode = mode;
}

function setActivity(title, steps = [], active = -1, busy = true) {
  currentActivity = { title, steps, active, busy };
  if (activityTitle) activityTitle.textContent = title || 'Idle';
  activityDot?.classList.toggle('busy', Boolean(busy));
  if (activitySteps) {
    activitySteps.innerHTML = (steps || []).map((step, index) => {
      const state = index < active ? 'done' : index === active ? 'active' : '';
      return `<span class="activity-step ${state}">${escapeHtml(step)}</span>`;
    }).join('');
  }
}

function clearActivity(title = 'Idle') {
  setActivity(title, [], -1, false);
}

function setCssVars(theme) {
  document.documentElement.style.setProperty('--bg', theme.bg);
  document.documentElement.style.setProperty('--panel', theme.panel);
  document.documentElement.style.setProperty('--panel-2', theme.panelAlt);
  document.documentElement.style.setProperty('--panel-3', theme.panel3);
  document.documentElement.style.setProperty('--cyan', theme.accent);
  document.documentElement.style.setProperty('--blue', theme.accent);
  document.documentElement.style.setProperty('--blue-soft', theme.accentSoft);
  document.documentElement.style.setProperty('--text', theme.text);
  document.documentElement.style.setProperty('--muted', theme.muted);
  document.documentElement.style.setProperty('--border', theme.border);
  document.documentElement.style.setProperty('--green', theme.success);
}

function renderPresetSwatches(theme) {
  if (!presetSwatches) return;
  presetSwatches.innerHTML = '';
  [theme.bg, theme.panel, theme.accent, theme.accentSoft, theme.text, theme.muted].forEach((color) => {
    const sw = document.createElement('span');
    sw.className = 'swatch';
    sw.style.background = color;
    sw.title = color;
    presetSwatches.appendChild(sw);
  });
}

function renderPaletteEditor() {
  if (!paletteGrid) return;
  paletteGrid.innerHTML = '';
  for (const key of paletteKeys) {
    const div = document.createElement('div');
    div.innerHTML = `<label for="pal_${escapeHtml(key)}">${escapeHtml(key)}</label><input id="pal_${escapeHtml(key)}" type="text" value="${escapeHtml(palette[key] || '')}">`;
    paletteGrid.appendChild(div);
  }
}

function readPaletteEditor() {
  for (const key of paletteKeys) {
    const el = document.getElementById(`pal_${key}`);
    if (el) palette[key] = el.value.trim();
  }
  setCssVars(palette);
  renderPresetSwatches(palette);
}

function populatePresetSelect() {
  if (!presetSelect) return;
  presetSelect.innerHTML = '';
  Object.keys(presetDefinitions).forEach((name) => {
    const opt = document.createElement('option');
    opt.value = name;
    opt.textContent = name;
    presetSelect.appendChild(opt);
  });
}

function applyPreset(name) {
  if (!presetDefinitions[name]) return;
  palette = { ...presetDefinitions[name] };
  setCssVars(palette);
  renderPaletteEditor();
  renderPresetSwatches(palette);
  activityTitle.textContent = `Theme preview: ${name}`;
}

function saveTheme() {
  try {
    localStorage.setItem(themeStorageKey, JSON.stringify(palette));
  } catch (error) {
    console.error('Could not save theme', error);
  }
  clearActivity('Theme saved');
}

function initThemes() {
  populatePresetSelect();
  try {
    const saved = localStorage.getItem(themeStorageKey);
    if (saved) palette = { ...defaultPalette, ...JSON.parse(saved) };
  } catch (error) {
    console.error('Could not read saved theme', error);
  }
  setCssVars(palette);
  renderPaletteEditor();
  renderPresetSwatches(palette);
}

function filterRows(rows, query) {
  return rows;
}

function normalizeZeekRows(logName, rows = []) {
  if (!Array.isArray(rows)) return [];
  if (logName === 'weird.log') {
    return rows.filter((row) => String(row?.name || '') !== 'line_terminated_with_single_CR');
  }
  return rows;
}

function inferColumns(rows = [], fallback = []) {
  const first = rows[0] || {};
  const keys = Object.keys(first);
  return keys.length ? keys : fallback;
}

function friendlyColumnName(name) {
  const aliases = {
    'src_ip': 'src_ip',
    'dest_ip': 'dest_ip',
    'src_port': 'src_port',
    'dest_port': 'dest_port',
    'id.orig_h': 'src_ip (Zeek)',
    'id.resp_h': 'dest_ip (Zeek)',
    'id.orig_p': 'src_port (Zeek)',
    'id.resp_p': 'dest_port (Zeek)',
  };
  return aliases[name] || name.replaceAll('_', ' ');
}

function defaultColumnsForLog(logName, rows = [], fields = []) {
  const allColumns = inferColumns(rows, fields);
  const preferred = (zeekDefaultColumns[logName] || []).filter((col) => allColumns.includes(col));
  return preferred.length ? preferred : allColumns;
}

function candidateValues(row, names = []) {
  return names
    .map((name) => row?.[name])
    .filter((value) => value && value !== '-' && value !== '(empty)');
}

function buildZeekInvestigationPrompt(logName, row) {
  const ips = [...new Set(candidateValues(row, ['src_ip', 'dest_ip', 'id.orig_h', 'id.resp_h', 'src', 'dst', 'san.ip']))];
  const hosts = [...new Set(candidateValues(row, ['host', 'server_name', 'query', 'certificate.subject', 'certificate.issuer']))];
  const artifacts = [...new Set(candidateValues(row, ['filename', 'name', 'path', 'uri', 'sha256', 'fingerprint', 'uid', 'endpoint', 'operation', 'note']))];

  if (logName === 'conn.log' && ips.length >= 2) {
    return `Inspect activity between ${ips[0]} and ${ips[1]} from ${logName}. What looks notable?`;
  }
  if (logName === 'dns.log' && hosts[0]) {
    return `Investigate the DNS activity for ${hosts[0]} from ${logName}. Is it normal or suspicious?`;
  }
  if (logName === 'http.log' && hosts[0]) {
    return `Investigate the HTTP activity for ${hosts[0]}${artifacts[0] ? ` and artifact ${artifacts[0]}` : ''} from ${logName}. What stands out?`;
  }
  if ((logName === 'files.log' || logName === 'smb_files.log') && (artifacts[0] || ips[0])) {
    return `Investigate the file activity${artifacts[0] ? ` for ${artifacts[0]}` : ''}${ips[0] ? ` involving ${ips[0]}` : ''} from ${logName}. What should I notice?`;
  }
  if (logName === 'smb_mapping.log' && artifacts[0]) {
    return `Investigate the SMB share mapping ${artifacts[0]} from ${logName}. Who is using it and why does it matter?`;
  }
  if (logName === 'dce_rpc.log' && (artifacts[0] || ips[0])) {
    return `Investigate the DCE/RPC activity${artifacts[0] ? ` (${artifacts[0]})` : ''}${ips[0] ? ` involving ${ips[0]}` : ''} from ${logName}.`;
  }
  if ((logName === 'ssl.log' || logName === 'x509.log' || logName === 'notice.log') && (hosts[0] || artifacts[0] || ips[0])) {
    return `Investigate the TLS/certificate signal${hosts[0] ? ` for ${hosts[0]}` : ''}${artifacts[0] ? ` (${artifacts[0]})` : ''}${ips[0] ? ` involving ${ips[0]}` : ''} from ${logName}.`;
  }
  if (logName === 'smtp.log' && (ips[0] || hosts[0])) {
    return `Investigate the SMTP activity${ips[0] ? ` involving ${ips[0]}` : ''}${hosts[0] ? ` for ${hosts[0]}` : ''} from ${logName}.`;
  }
  if (logName === 'weird.log' && (artifacts[0] || ips[0])) {
    return `Investigate the weird event${artifacts[0] ? ` ${artifacts[0]}` : ''}${ips[0] ? ` involving ${ips[0]}` : ''} from ${logName}.`;
  }
  if (ips[0] || hosts[0] || artifacts[0]) {
    return `Investigate this ${logName} row${ips[0] ? ` involving ${ips[0]}` : ''}${hosts[0] ? ` and ${hosts[0]}` : ''}${artifacts[0] ? ` with artifact ${artifacts[0]}` : ''}.`;
  }
  return `Investigate this selected row from ${logName}. What should I notice?`;
}

function zeekRowOrderValue(row = {}) {
  const offsetMs = Number(row.pcap_offset_ms || NaN);
  if (Number.isFinite(offsetMs)) return offsetMs;
  const ts = Number(row.ts || row['ts'] || NaN);
  if (Number.isFinite(ts)) return ts * 1000;
  const frame = Number(row.request_frame || row.frame || row.response_frame || NaN);
  if (Number.isFinite(frame)) return frame;
  return Number.POSITIVE_INFINITY;
}

function sortZeekRows(rows = [], sortDir = 'asc') {
  const sorted = [...rows].sort((a, b) => {
    const av = zeekRowOrderValue(a);
    const bv = zeekRowOrderValue(b);
    if (av === bv) {
      const af = String(a.request_frame || a.frame || a.response_frame || '');
      const bf = String(b.request_frame || b.frame || b.response_frame || '');
      return af.localeCompare(bf, undefined, { numeric: true });
    }
    return av - bv;
  });
  return sortDir === 'desc' ? sorted.reverse() : sorted;
}

function renderZeekLogTable(logName) {
  const config = zeekTableRegistry[logName] || zeekTableRegistry.__generic__;
  const state = zeekLogState[logName] || { rows: [], query: '', selectedColumns: [], fields: [], fallbackUsed: false, loading: false, progressLabel: '', sortDir: 'asc' };
  if (!config?.element) return;
  const orderedRows = sortZeekRows(state.rows || [], state.sortDir || 'asc');
  const filteredRows = filterRows(orderedRows, state.query || '');
  const allColumns = inferColumns(state.rows || [], state.fields || []);
  const selectedColumns = (state.selectedColumns && state.selectedColumns.length ? state.selectedColumns : defaultColumnsForLog(logName, state.rows || [], state.fields || [])).filter((col) => allColumns.includes(col));
  const tableHtml = renderNamedTable(filteredRows, selectedColumns);
  const columnControls = allColumns.map((column) => {
    const checked = selectedColumns.includes(column) ? 'checked' : '';
    return `<label class="column-chip"><input type="checkbox" data-zeek-column="${escapeHtml(logName)}" value="${escapeHtml(column)}" ${checked} /> <span>${escapeHtml(friendlyColumnName(column))}</span></label>`;
  }).join('');
  config.element.innerHTML = `
    <div class="zeek-log-controls${state.loading ? ' busy' : ''}">
      <form class="zeek-log-search-row" data-zeek-search-form="${escapeHtml(logName)}">
        <input class="zeek-search-input" type="search" placeholder="Try src_ip=1.2.3.4 AND NOT (dest_ip=5.6.7.8 || rcode_name=NOERROR)" value="${escapeHtml(state.query || '')}" data-zeek-search="${escapeHtml(logName)}" ${state.loading ? 'disabled' : ''} />
        <button class="ghost-button zeek-search-button${state.loading ? ' searching' : ''}" type="submit" ${state.loading ? 'disabled' : ''}>${state.loading ? 'Searching…' : 'Search'}</button>
        <button class="ghost-button" type="button" data-zeek-clear-search="${escapeHtml(logName)}" ${state.loading ? 'disabled' : ''}>Clear</button>
        <button class="ghost-button" type="button" data-zeek-sort-toggle="${escapeHtml(logName)}" ${state.loading ? 'disabled' : ''}>${state.sortDir === 'desc' ? 'Last → First' : 'First → Last'}</button>
      </form>
      <div class="zeek-search-hint">${escapeHtml(logName)} • ${filteredRows.length}/${orderedRows.length} rows shown${state.fallbackUsed ? ' • packet rows merged' : ''} • ordered ${state.sortDir === 'desc' ? 'last to first' : 'first to last'} • double-click a row to ask PIRE about it</div>
      <div class="zeek-search-progress${state.loading ? ' active' : ''}"><div class="zeek-search-progress-bar"></div></div>
      ${state.loading ? `<div class="zeek-search-progress-text">${escapeHtml(state.progressLabel || `Refreshing ${logName}`)}</div>` : ''}
    </div>
    <details class="column-picker">
      <summary>Columns (${selectedColumns.length}/${allColumns.length})</summary>
      <div class="column-chip-wrap">${columnControls}</div>
    </details>
    ${tableHtml}
  `;

  const input = config.element.querySelector('[data-zeek-search]');
  config.element.querySelector('[data-zeek-search-form]')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    zeekLogState[logName] = { ...(zeekLogState[logName] || {}), query: input?.value || '' };
    await fetchZeekLog(logName, config.element, currentPcap);
  });
  config.element.querySelector('[data-zeek-clear-search]')?.addEventListener('click', async () => {
    zeekLogState[logName] = { ...(zeekLogState[logName] || {}), query: '' };
    await fetchZeekLog(logName, config.element, currentPcap);
  });
  config.element.querySelector('[data-zeek-sort-toggle]')?.addEventListener('click', () => {
    const nextDir = (zeekLogState[logName]?.sortDir || 'asc') === 'asc' ? 'desc' : 'asc';
    zeekLogState[logName] = { ...(zeekLogState[logName] || {}), sortDir: nextDir };
    renderZeekLogTable(logName);
  });

  config.element.querySelectorAll('[data-zeek-column]').forEach((checkbox) => {
    checkbox.addEventListener('change', () => {
      const selected = Array.from(config.element.querySelectorAll('[data-zeek-column]:checked')).map((el) => el.value);
      zeekLogState[logName] = { ...(zeekLogState[logName] || {}), selectedColumns: selected.length ? selected : defaultColumnsForLog(logName, state.rows || [], state.fields || []) };
      renderZeekLogTable(logName);
    });
  });

  config.element.querySelectorAll('tbody tr').forEach((rowEl, index) => {
    const row = filteredRows[index];
    rowEl.classList.add('clickable-row');
    rowEl.title = 'Double-click to ask PIRE about this row';
    rowEl.addEventListener('dblclick', async () => {
      const prompt = buildZeekInvestigationPrompt(logName, row || {});
      activateTab('overview');
      await sendChat(prompt);
    });
  });
}

function renderNamedTable(rows, preferredColumns = []) {
  if (!rows || !rows.length) {
    return '<div class="empty-state">No rows to show.</div>';
  }
  const first = rows[0] || {};
  const columns = preferredColumns.length
    ? preferredColumns.filter((col) => col in first)
    : Object.keys(first);
  const head = columns.map((col) => `<th>${escapeHtml(col)}</th>`).join('');
  const body = rows.map((row) => `<tr>${columns.map((col) => `<td>${escapeHtml(row[col] || '')}</td>`).join('')}</tr>`).join('');
  return `<table class="data-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function renderPaginatedTable(container, payload, kind) {
  if (!container) return;
  const uiState = dataViewUiState[kind] || { columns: payload?.default_columns || payload?.columns || [], query: '', sortBy: payload?.sort_by || '', sortDir: payload?.sort_dir || 'desc' };
  dataViewUiState[kind] = uiState;
  const allColumns = payload?.columns || Object.keys(payload?.rows?.[0] || {});
  if (!uiState.columns?.length) uiState.columns = payload?.default_columns || allColumns;
  if (!payload?.rows?.length) {
    container.innerHTML = '<div class="empty-state">No rows to show.</div>';
    return;
  }
  const columns = (uiState.columns || payload?.default_columns || allColumns).filter((col) => allColumns.includes(col));
  const tableHtml = renderNamedTable(payload.rows, columns);
  const label = kind === 'hosts' ? 'hosts' : 'conversations';
  const columnControls = allColumns.map((column) => {
    const checked = columns.includes(column) ? 'checked' : '';
    return `<label class="column-chip"><input type="checkbox" data-data-column="${escapeHtml(kind)}" value="${escapeHtml(column)}" ${checked} /> <span>${escapeHtml(column)}</span></label>`;
  }).join('');
  const canSearch = ['hosts', 'endpoints'].includes(kind);
  container.innerHTML = `
    <div class="paged-table-toolbar">
      <div class="paged-table-meta">${escapeHtml(String(payload.total_rows || 0))} ${escapeHtml(kind)} • page ${escapeHtml(String(payload.page || 1))} / ${escapeHtml(String(payload.total_pages || 1))}</div>
      <div class="paged-table-actions">
        ${canSearch ? `<form class="data-view-search-row" data-data-search-form="${escapeHtml(kind)}"><input class="zeek-search-input data-view-search" type="search" placeholder="Search ${escapeHtml(kind)} with * wildcard" value="${escapeHtml(uiState.query || payload.query || '')}" data-data-search="${escapeHtml(kind)}" /><button class="ghost-button" type="submit">Search</button></form>` : ''}
        ${canSearch ? `<span class="zeek-search-hint data-view-search-hint">Search runs when you press Search or Enter.</span>` : ''}
        <button class="ghost-button" type="button" data-reset-filters="${escapeHtml(kind)}">Reset</button>
        <button class="ghost-button" type="button" data-reset-columns="${escapeHtml(kind)}">Reset Columns</button>
        <button class="ghost-button" type="button" data-page-kind="${escapeHtml(kind)}" data-page-dir="prev" ${payload.has_prev ? '' : 'disabled'}>Prev</button>
        <button class="ghost-button" type="button" data-page-kind="${escapeHtml(kind)}" data-page-dir="next" ${payload.has_next ? '' : 'disabled'}>Next</button>
      </div>
    </div>
    <details class="column-picker">
      <summary>Columns (${columns.length}/${allColumns.length})</summary>
      <div class="column-chip-wrap">${columnControls}</div>
    </details>
    ${tableHtml}
  `;
  container.querySelectorAll('[data-page-dir]').forEach((button) => {
    button.addEventListener('click', async () => {
      const dir = button.getAttribute('data-page-dir');
      const nextPage = dir === 'next' ? (payload.page || 1) + 1 : (payload.page || 1) - 1;
      if (kind === 'conversations') {
        await fetchConversationPage(nextPage);
      } else if (kind === 'endpoints') {
        await fetchEndpointPage(nextPage);
      } else {
        await fetchHostPage(nextPage);
      }
    });
  });
  container.querySelectorAll('[data-data-column]').forEach((checkbox) => {
    checkbox.addEventListener('change', () => {
      const selected = Array.from(container.querySelectorAll('[data-data-column]:checked')).map((el) => el.value);
      dataViewUiState[kind] = { ...(dataViewUiState[kind] || {}), columns: selected.length ? selected : (payload.default_columns || allColumns) };
      renderPaginatedTable(container, payload, kind);
    });
  });
  container.querySelector('[data-reset-columns]')?.addEventListener('click', () => {
    dataViewUiState[kind] = { ...(dataViewUiState[kind] || {}), columns: payload.default_columns || allColumns };
    renderPaginatedTable(container, payload, kind);
  });
  container.querySelector('[data-reset-filters]')?.addEventListener('click', async () => {
    dataViewUiState[kind] = { ...(dataViewUiState[kind] || {}), query: '', sortBy: payload.default_columns?.[1] || payload.sort_by || '', sortDir: 'desc', columns: payload.default_columns || allColumns };
    if (kind === 'conversations') await fetchConversationPage(1);
    else if (kind === 'endpoints') await fetchEndpointPage(1);
    else await fetchHostPage(1);
  });
  const searchInput = container.querySelector('[data-data-search]');
  const runDataSearch = async (value) => {
    dataViewUiState[kind] = { ...(dataViewUiState[kind] || {}), query: value || '' };
    if (kind === 'endpoints') await fetchEndpointPage(1);
    else await fetchHostPage(1);
  };
  container.querySelector('[data-data-search-form]')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    await runDataSearch(searchInput?.value || '');
  });
  container.querySelectorAll('th').forEach((th, index) => {
    const column = columns[index];
    if (!column) return;
    th.classList.add('sortable-th');
    th.addEventListener('click', async () => {
      const currentSortBy = dataViewUiState[kind]?.sortBy || payload.sort_by;
      const currentDir = dataViewUiState[kind]?.sortDir || payload.sort_dir || 'desc';
      const nextDir = currentSortBy === column && currentDir === 'desc' ? 'asc' : 'desc';
      dataViewUiState[kind] = { ...(dataViewUiState[kind] || {}), sortBy: column, sortDir: nextDir };
      if (kind === 'conversations') await fetchConversationPage(1);
      else if (kind === 'endpoints') await fetchEndpointPage(1);
      else await fetchHostPage(1);
    });
  });
}

function renderEventTimeline(rows) {
  if (!timelineTable) return;
  timelineState.rows = rows || [];
  const pageSize = timelineState.pageSize || 8;
  const totalPages = Math.max(1, Math.ceil((timelineState.rows.length || 0) / pageSize));
  timelineState.page = Math.min(Math.max(1, timelineState.page || 1), totalPages);
  const start = (timelineState.page - 1) * pageSize;
  const pageRows = timelineState.rows.slice(start, start + pageSize);
  if (!pageRows.length) {
    timelineTable.innerHTML = '<div class="empty-state">No event clusters to show yet.</div>';
    return;
  }
  const body = pageRows.map((row, index) => `
    <tr>
      <td>${escapeHtml(row.time_window || '')}</td>
      <td>${escapeHtml(row.event_type || '')}</td>
      <td>${escapeHtml(row.focus || '')}</td>
      <td>${escapeHtml(row.summary || '')}</td>
      <td>${escapeHtml(row.why || '')}</td>
      <td><button class="pivot-chip" type="button" data-timeline-pivot="${index}">${escapeHtml(row.pivot_label || 'Open log')}</button></td>
    </tr>
  `).join('');
  timelineTable.innerHTML = `
    <div class="paged-table-toolbar">
      <div class="paged-table-meta">${escapeHtml(String(timelineState.rows.length || 0))} events • page ${escapeHtml(String(timelineState.page))} / ${escapeHtml(String(totalPages))}</div>
      <div class="paged-table-actions">
        <button class="ghost-button" type="button" data-timeline-page="prev" ${timelineState.page > 1 ? '' : 'disabled'}>Prev</button>
        <button class="ghost-button" type="button" data-timeline-page="next" ${timelineState.page < totalPages ? '' : 'disabled'}>Next</button>
      </div>
    </div>
    <table class="data-table">
      <thead>
        <tr>
          <th>Time window</th>
          <th>Event type</th>
          <th>Focus</th>
          <th>Summary</th>
          <th>Why it matters</th>
          <th>Pivot</th>
        </tr>
      </thead>
      <tbody>${body}</tbody>
    </table>
  `;
  timelineTable.querySelectorAll('[data-timeline-pivot]').forEach((button) => {
    button.addEventListener('click', () => {
      const row = pageRows[Number(button.getAttribute('data-timeline-pivot'))];
      if (row?.pivot_tab) activateTab(row.pivot_tab);
    });
  });
  timelineTable.querySelectorAll('[data-timeline-page]').forEach((button) => {
    button.addEventListener('click', () => {
      timelineState.page += button.getAttribute('data-timeline-page') === 'next' ? 1 : -1;
      renderEventTimeline(timelineState.rows);
    });
  });
}

function renderTriageSummary(sections) {
  if (!triageSummaryContent) return;
  if (!sections || !sections.length) {
    triageSummaryContent.innerHTML = '<div class="empty-state">No triage summary available yet.</div>';
    return;
  }
  triageSummaryContent.innerHTML = sections.map((section) => {
    const pivotButtons = (section.pivots || []).map((pivot) => `
      <button class="pivot-chip" type="button" data-pivot-tab="${escapeHtml(pivot.tab || '')}">${escapeHtml(pivot.label || pivot.tab || 'Pivot')}</button>
    `).join('');
    const pivotRow = pivotButtons ? `<div class="pivot-row">${pivotButtons}</div>` : '';
    if (section.kind === 'facts') {
      const items = (section.items || []).map((item) => `
        <div class="triage-fact">
          <span>${escapeHtml(item.label || '')}</span>
          <strong>${escapeHtml(item.value || 'n/a')}</strong>
        </div>
      `).join('');
      return `<section class="triage-card"><h3>${escapeHtml(section.title || 'Section')}</h3>${pivotRow}<div class="triage-facts">${items}</div></section>`;
    }
    if (section.kind === 'table') {
      return `<section class="triage-card"><h3>${escapeHtml(section.title || 'Section')}</h3>${pivotRow}<div class="table-wrap">${renderNamedTable(section.rows || [], section.columns || [])}</div></section>`;
    }
    if (section.kind === 'attention') {
      const cards = (section.items || []).map((item) => `
        <div class="attention-item attention-${escapeHtml(item.status || 'low')}">
          <div class="attention-header">
            <strong>${escapeHtml(item.title || 'Interesting signal')}</strong>
            <span class="attention-pill">${escapeHtml(item.status || 'low')}</span>
          </div>
          <div class="attention-detail">${escapeHtml(item.detail || '')}</div>
          <div class="attention-why">${escapeHtml(item.why || '')}</div>
          <div class="pivot-row"><button class="pivot-chip" type="button" data-pivot-tab="${escapeHtml(item.pivot_tab || '')}">${escapeHtml(item.pivot_label || 'Pivot')}</button></div>
        </div>
      `).join('') || '<div class="empty-state">No strong interesting signals yet.</div>';
      return `<section class="triage-card"><h3>${escapeHtml(section.title || 'Section')}</h3>${pivotRow}<div class="attention-list">${cards}</div></section>`;
    }
    const lines = (section.items || []).map((line) => `<li>${escapeHtml(line)}</li>`).join('') || '<li>No data.</li>';
    return `<section class="triage-card"><h3>${escapeHtml(section.title || 'Section')}</h3>${pivotRow}<ul class="triage-lines">${lines}</ul></section>`;
  }).join('');
  triageSummaryContent.querySelectorAll('[data-pivot-tab]').forEach((button) => {
    button.addEventListener('click', () => activateTab(button.getAttribute('data-pivot-tab')));
  });
}

function extractAttentionItems(sections = []) {
  return sections
    .filter((section) => section.kind === 'attention')
    .flatMap((section) => section.items || []);
}

function extractFactItems(sections = []) {
  return sections
    .filter((section) => section.kind === 'facts')
    .flatMap((section) => section.items || []);
}

function collectSummaryTargets() {
  const candidates = [];
  const pushCandidate = (value, labelPrefix = 'Inspect') => {
    if (!value) return;
    const label = String(value).trim();
    if (!label) return;
    if (!candidates.some((item) => item.value === label)) {
      candidates.push({ value: label, label: `${labelPrefix} ${label}` });
    }
  };
  const pages = [endpointPageState, hostPageState];
  for (const page of pages) {
    for (const row of page?.rows || []) {
      pushCandidate(row.ip || row.host || row['id.orig_h'] || row['id.resp_h']);
      if (candidates.length >= 6) return candidates;
    }
  }
  return candidates;
}

function renderCaseSummary(data) {
  if (!summaryContent) return;
  if (!data) {
    summaryContent.innerHTML = '<div class="empty-state">Load a PCAP to see the case summary.</div>';
    return;
  }
  const parsed = data?.metadata?.parsed || {};
  const topProtocols = (data?.top_protocols || []).slice(0, 6);
  const attentionItems = extractAttentionItems(data?.triage_sections || []).slice(0, 4);
  const factItems = extractFactItems(data?.triage_sections || []).slice(0, 6);
  const hotspots = Object.entries(currentZeekSummary?.log_counts || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const targets = collectSummaryTargets();
  const timelineHighlights = (data?.event_timeline || []).slice(0, 4);
  const assessmentSummary = attentionItems.length
    ? attentionItems.map((item) => item.title || item.detail).filter(Boolean)
    : ['No standout attention items yet. Start with Evidence to review ranked leads.'];
  const factsHtml = factItems.length
    ? factItems.map((item) => `<span class="summary-pill"><strong>${escapeHtml(item.label || 'Fact')}</strong>${escapeHtml(item.value || 'n/a')}</span>`).join('')
    : '<span class="summary-pill"><strong>Status</strong>Loaded case summary only</span>';
  const attentionHtml = attentionItems.length
    ? attentionItems.map((item) => `<li><strong>${escapeHtml(item.title || 'Interesting signal')}</strong> — ${escapeHtml(item.detail || item.why || '')}</li>`).join('')
    : '<li>No immediate attention items were generated yet.</li>';
  const hotspotHtml = hotspots.length
    ? hotspots.map(([name, count]) => `<button class="summary-target" type="button" data-open-log="${escapeHtml(name)}">${escapeHtml(name)} (${escapeHtml(count)})</button>`).join('')
    : '<span class="summary-pill">No Zeek hotspots yet</span>';
  const targetsHtml = targets.length
    ? targets.map((target) => `<button class="summary-target" type="button" data-load-ip="${escapeHtml(target.value)}">${escapeHtml(target.value)}</button>`).join('')
    : '<span class="summary-pill">No candidate IPs identified yet</span>';
  const timelineHtml = timelineHighlights.length
    ? `<ul>${timelineHighlights.map((item) => `<li><strong>${escapeHtml(item.time_window || '')}</strong> — ${escapeHtml(item.summary || item.focus || '')}</li>`).join('')}</ul>`
    : '<p>No timeline highlights yet.</p>';
  summaryContent.innerHTML = `
    <div class="summary-stack">
      <div class="summary-hero">
        <section class="summary-card">
          <h3>Case Assessment</h3>
          <p>${escapeHtml(data?.pcap || currentPcap || 'No PCAP loaded')}</p>
          <div class="summary-statline">
            <span class="summary-pill"><strong>Packets</strong>${escapeHtml(parsed.number_of_packets || 'n/a')}</span>
            <span class="summary-pill"><strong>Duration</strong>${escapeHtml(parsed.capture_duration || 'n/a')}</span>
            <span class="summary-pill"><strong>Start</strong>${escapeHtml(parsed.earliest_packet_time || 'n/a')}</span>
            <span class="summary-pill"><strong>End</strong>${escapeHtml(parsed.latest_packet_time || 'n/a')}</span>
          </div>
          <ul>${assessmentSummary.map((line) => `<li>${escapeHtml(line)}</li>`).join('')}</ul>
        </section>
        <section class="summary-card">
          <h3>Activity Overview</h3>
          <p>Top protocols and capture shape at a glance.</p>
          <div class="summary-statline">${factsHtml}</div>
          <ul>${topProtocols.length ? topProtocols.map((line) => `<li>${escapeHtml(line)}</li>`).join('') : '<li>No protocol hierarchy available.</li>'}</ul>
        </section>
      </div>
      <div class="summary-split">
        <section class="summary-card">
          <h3>Immediate Attention</h3>
          <p>Best starting leads if you have not picked a host yet.</p>
          <ul>${attentionHtml}</ul>
        </section>
        <section class="summary-card">
          <h3>Evidence Hotspots</h3>
          <p>Logs and evidence sources most likely to matter.</p>
          <div class="hotspot-list">${hotspotHtml}</div>
        </section>
      </div>
      <div class="summary-split">
        <section class="summary-card">
          <h3>Suggested Investigation Targets</h3>
          <p>Click an IP to turn Summary into an entity-focused dossier.</p>
          <div class="summary-target-list">${targetsHtml}</div>
        </section>
        <section class="summary-card">
          <h3>Timeline Highlights</h3>
          <p>Recent cluster summaries from the current case view.</p>
          ${timelineHtml}
        </section>
      </div>
    </div>
  `;
  summaryContent.querySelectorAll('[data-open-log]').forEach((button) => {
    button.addEventListener('click', async () => {
      activateTab('logs');
      await openZeekLogViewer(button.getAttribute('data-open-log'));
    });
  });
  summaryContent.querySelectorAll('[data-load-ip]').forEach((button) => {
    button.addEventListener('click', async () => {
      const ip = button.getAttribute('data-load-ip');
      if (!ip || !currentPcap) return;
      setActivity(`Loading dossier for ${ip}`, ['Profile IP', 'Render dossier', 'Focus detail panel'], 0, true);
      const response = await fetch(`/api/ip-dossier?pcap=${encodeURIComponent(currentPcap || '')}&ip=${encodeURIComponent(ip)}`);
      const payload = await response.json();
      if (!response.ok) {
        clearActivity(`Could not load dossier for ${ip}`);
        appendMessage(payload.detail || `Could not load dossier for ${ip}.`, 'incoming', 'PIRE • now');
        return;
      }
      currentDossierSectionId = payload.sections?.[0]?.id || null;
      currentDossierLineIndex = null;
      setActivity(`Loading dossier for ${ip}`, ['Profile IP', 'Render dossier', 'Focus detail panel'], 1, true);
      renderIpDossier(payload);
      setActivity(`Loading dossier for ${ip}`, ['Profile IP', 'Render dossier', 'Focus detail panel'], 2, true);
      clearActivity(`Dossier ready for ${ip}`);
    });
  });
}

function renderSummaryView() {
  if (currentDossier) renderIpDossier(currentDossier);
  else renderCaseSummary(currentOverview);
}

function renderDetailPanel() {
  if (!detailContent) return;
  if (!currentDossier) {
    detailContent.innerHTML = '<div class="empty-state">Select an IP dossier item to see knowledge, suggested questions, and next pivots here.</div>';
    return;
  }
  const section = (currentDossier.sections || []).find((item) => item.id === currentDossierSectionId) || currentDossier.sections?.[0];
  if (!section) {
    detailContent.innerHTML = '<div class="empty-state">No dossier sections are available yet.</div>';
    return;
  }
  currentDossierSectionId = section.id;
  const relevantActions = (currentDossier.knowledge_actions || []).filter((item) => item.section_id === section.id);
  const latestAction = currentKnowledgeAction && currentKnowledgeAction.section_id === section.id
    ? currentKnowledgeAction
    : (relevantActions.length ? relevantActions[relevantActions.length - 1] : null);
  const reasons = (currentDossier.verdict?.reasons || []).map((item) => `<li>${escapeHtml(item)}</li>`).join('') || '<li>None yet.</li>';
  const benign = (currentDossier.verdict?.benign_signals || []).map((item) => `<li>${escapeHtml(item)}</li>`).join('') || '<li>None yet.</li>';
  const actionHtml = (() => {
    if (!latestAction) return '<p class="muted-line">No browser/API knowledge action generated yet for this dossier section.</p>';
    const payload = latestAction.payload || {};
    const queries = (payload.queries || []).map((item) => `<li>${escapeHtml(item)}</li>`).join('');
    const checklist = (payload.review_checklist || []).map((item) => `<li>${escapeHtml(item)}</li>`).join('');
    const targets = (payload.targets || []).map((item) => `<li><strong>${escapeHtml(item.name || '')}</strong>: ${escapeHtml(item.purpose || '')}</li>`).join('');
    return `
      <div class="detail-card">
        <div class="detail-card-header">
          <div>
            <h3>${escapeHtml(latestAction.title || 'Knowledge action')}</h3>
            <p>${escapeHtml(latestAction.summary || '')}</p>
          </div>
          <span class="detail-pill">${escapeHtml(latestAction.kind || 'action')}</span>
        </div>
        ${queries ? `<p><strong>Suggested browser queries</strong></p><ul>${queries}</ul>` : ''}
        ${checklist ? `<p><strong>Review checklist</strong></p><ul>${checklist}</ul>` : ''}
        ${targets ? `<p><strong>Suggested enrichment targets</strong></p><ul>${targets}</ul>` : ''}
      </div>
    `;
  })();
  detailContent.innerHTML = `
    <div class="detail-list">
      <section class="detail-card">
        <div class="detail-card-header">
          <div>
            <h3>${escapeHtml(currentDossier.ip)} • ${escapeHtml(section.label)}</h3>
            <p>${escapeHtml(section.summary || '')}</p>
          </div>
          <span class="detail-pill">${escapeHtml(section.status || 'review')}</span>
        </div>
        <p>${escapeHtml(section.detail || 'No detail yet.')}</p>
        <p><strong>Suggested question:</strong> ${escapeHtml(section.question || 'None yet.')}</p>
        <p><strong>Why ask:</strong> ${escapeHtml(section.why_ask || 'None yet.')}</p>
        <p><strong>Helpful answer:</strong> ${escapeHtml(section.helpful_answer_would || 'None yet.')}</p>
        <div class="pivot-row">
          <button class="pivot-chip" type="button" id="detail-ask-button">Add this as a saved question</button>
          <button class="pivot-chip" type="button" id="detail-open-chat-button">Ask in chat now</button>
          <button class="pivot-chip" type="button" id="detail-browser-action-button">Generate browser workflow</button>
          <button class="pivot-chip" type="button" id="detail-api-action-button">Generate API workflow</button>
        </div>
      </section>
      <div class="detail-signals">
        <section class="signal-box">
          <h4>Suspicious signals</h4>
          <ul>${reasons}</ul>
        </section>
        <section class="signal-box">
          <h4>Benign / explainable signals</h4>
          <ul>${benign}</ul>
        </section>
      </div>
      <section class="detail-card">
        <h3>Library context</h3>
        <p><strong>Protocol:</strong> ${escapeHtml(section.protocol_snippet || 'None yet.')}</p>
        <p><strong>Experience:</strong> ${escapeHtml(section.experience_snippet || 'None yet.')}</p>
      </section>
      ${actionHtml}
    </div>
  `;
  detailContent.querySelector('#detail-ask-button')?.addEventListener('click', async () => {
    setActivity(`Saving dossier question for ${currentDossier.ip}`, ['Build question', 'Save to case'], 0, true);
    const response = await fetch('/api/ip-dossier/select', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: currentDossier.ip, section_id: section.id, pcap: currentPcap })
    });
    const payload = await response.json();
    setActivity(`Saving dossier question for ${currentDossier.ip}`, ['Build question', 'Save to case'], 1, true);
    if (payload?.dossier) {
      currentDossier = payload.dossier;
      renderIpDossier(currentDossier);
      renderDetailPanel();
    }
    clearActivity(`Question saved for ${currentDossier.ip}`);
    appendMessage(response.ok ? `Saved dossier question for ${currentDossier.ip}: ${section.question}` : (payload.detail || 'Could not save dossier question.'), 'incoming', 'PIRE • now');
  });
  detailContent.querySelector('#detail-open-chat-button')?.addEventListener('click', async () => {
    if (section.question) await sendChat(section.question);
  });
  const generateAction = async (kind) => {
    setActivity(`Generating ${kind} workflow for ${currentDossier.ip}`, ['Read dossier context', 'Build workflow', 'Render action'], 0, true);
    const response = await fetch('/api/ip-dossier/knowledge-action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: currentDossier.ip, section_id: section.id, kind, line_index: currentDossierLineIndex, pcap: currentPcap })
    });
    const payload = await response.json();
    setActivity(`Generating ${kind} workflow for ${currentDossier.ip}`, ['Read dossier context', 'Build workflow', 'Render action'], 1, true);
    if (payload?.dossier) currentDossier = payload.dossier;
    currentKnowledgeAction = payload?.action || null;
    renderIpDossier(currentDossier);
    renderDetailPanel();
    setActivity(`Generating ${kind} workflow for ${currentDossier.ip}`, ['Read dossier context', 'Build workflow', 'Render action'], 2, true);
    clearActivity(response.ok ? `${kind.toUpperCase()} workflow ready` : `Could not generate ${kind} workflow`);
    if (!response.ok) appendMessage(payload.detail || `Could not generate ${kind} workflow.`, 'incoming', 'PIRE • now');
  };
  detailContent.querySelector('#detail-browser-action-button')?.addEventListener('click', async () => generateAction('browser'));
  detailContent.querySelector('#detail-api-action-button')?.addEventListener('click', async () => generateAction('api'));
}

function buildBehaviorSummary(dossier) {
  const lines = [];
  for (const section of dossier?.sections || []) {
    for (const line of section.key_lines || []) {
      if (line && !lines.includes(line)) lines.push(line);
      if (lines.length >= 6) return lines;
    }
  }
  if (!lines.length) {
    lines.push(dossier?.verdict?.summary || 'No behavior summary available yet.');
  }
  return lines.slice(0, 6);
}

function renderIpDossier(dossier) {
  currentDossier = dossier || null;
  if (!summaryContent) return;
  if (!dossier) {
    currentKnowledgeAction = null;
    renderCaseSummary(currentOverview);
    renderDetailPanel();
    return;
  }
  if (!currentDossierSectionId && dossier.sections?.length) currentDossierSectionId = dossier.sections[0].id;
  const behaviorLines = buildBehaviorSummary(dossier);
  const suspiciousLines = (dossier.verdict?.reasons || []).slice(0, 4);
  const summarySections = (dossier.sections || []).map((section) => `
    <section class="dossier-card">
      <div class="dossier-card-header">
        <div>
          <h3>${escapeHtml(section.label || 'Section')}</h3>
          <p>${escapeHtml(section.summary || '')}</p>
        </div>
        <button class="dossier-mark ${section.id === currentDossierSectionId ? 'active' : ''}" type="button" data-dossier-section="${escapeHtml(section.id)}">${escapeHtml(section.mark || '?')}</button>
      </div>
      <span class="dossier-status">${escapeHtml(section.status || 'review')}</span>
      <p>${escapeHtml(section.detail || '')}</p>
      ${(section.key_lines || []).length ? `<div class="dossier-key-lines">${(section.key_lines || []).map((line, index) => `
        <div class="dossier-line">
          <button class="dossier-line-mark ${section.id === currentDossierSectionId && currentDossierLineIndex === index ? 'active' : ''}" type="button" data-dossier-section="${escapeHtml(section.id)}" data-dossier-line="${index}">${escapeHtml(section.mark || '?')}</button>
          <div class="dossier-line-text">${escapeHtml(line)}</div>
        </div>
      `).join('')}</div>` : ''}
    </section>
  `).join('');
  summaryContent.innerHTML = `
    <div class="summary-stack">
      <div class="summary-hero">
        <section class="summary-card">
          <h3>Entity Focus</h3>
          <p>${escapeHtml(dossier.ip || '')}</p>
          <div class="summary-statline">
            <span class="summary-pill"><strong>Verdict</strong>${escapeHtml((dossier.verdict?.label || 'review').toUpperCase())}</span>
            <span class="summary-pill"><strong>Score</strong>${escapeHtml(dossier.verdict?.score || 0)}</span>
            <span class="summary-pill"><strong>Confidence</strong>${escapeHtml(dossier.verdict?.confidence || 'low')}</span>
          </div>
          <p>${escapeHtml(dossier.verdict?.summary || 'No verdict summary yet.')}</p>
        </section>
        <section class="summary-card">
          <h3>Behavior Summary</h3>
          <p>Collapsed highlights for this IP before drilling into section cards.</p>
          <ul>${behaviorLines.map((line) => `<li>${escapeHtml(line)}</li>`).join('')}</ul>
        </section>
      </div>
      <div class="summary-split">
        <section class="summary-card">
          <h3>Assessment</h3>
          <p>Why this IP is currently being treated as interesting.</p>
          <ul>${suspiciousLines.length ? suspiciousLines.map((line) => `<li>${escapeHtml(line)}</li>`).join('') : '<li>No suspicious signals collected yet.</li>'}</ul>
        </section>
        <section class="summary-card">
          <h3>Load Another IP</h3>
          <p>Enter an address to replace the current focus.</p>
          <div class="dossier-input-row">
            <input id="dossier-ip-input" type="text" value="${escapeHtml(dossier.ip || '')}" placeholder="10.99.32.151" />
            <button class="ghost-button" type="button" id="dossier-load-button">Load dossier</button>
            <button class="ghost-button" type="button" id="dossier-clear-button">Back to case</button>
          </div>
        </section>
      </div>
      <div class="summary-section-grid">
        ${summarySections}
      </div>
    </div>
  `;
  summaryContent.querySelector('#dossier-load-button')?.addEventListener('click', async () => {
    const ip = summaryContent.querySelector('#dossier-ip-input')?.value?.trim();
    if (!ip) return;
    setActivity(`Loading dossier for ${ip}`, ['Profile IP', 'Render dossier', 'Focus detail panel'], 0, true);
    const response = await fetch(`/api/ip-dossier?pcap=${encodeURIComponent(currentPcap || '')}&ip=${encodeURIComponent(ip)}`);
    const payload = await response.json();
    if (!response.ok) {
      clearActivity(`Could not load dossier for ${ip}`);
      appendMessage(payload.detail || `Could not load dossier for ${ip}.`, 'incoming', 'PIRE • now');
      return;
    }
    setActivity(`Loading dossier for ${ip}`, ['Profile IP', 'Render dossier', 'Focus detail panel'], 1, true);
    currentDossierSectionId = payload.sections?.[0]?.id || null;
    currentDossierLineIndex = null;
    renderIpDossier(payload);
    setActivity(`Loading dossier for ${ip}`, ['Profile IP', 'Render dossier', 'Focus detail panel'], 2, true);
    clearActivity(`Dossier ready for ${ip}`);
  });
  summaryContent.querySelector('#dossier-clear-button')?.addEventListener('click', () => {
    currentDossier = null;
    currentDossierSectionId = null;
    currentDossierLineIndex = null;
    currentKnowledgeAction = null;
    renderSummaryView();
    renderDetailPanel();
  });
  summaryContent.querySelectorAll('[data-dossier-section]').forEach((button) => {
    button.addEventListener('click', () => {
      currentDossierSectionId = button.getAttribute('data-dossier-section');
      const lineAttr = button.getAttribute('data-dossier-line');
      currentDossierLineIndex = lineAttr === null ? null : Number(lineAttr);
      currentKnowledgeAction = null;
      renderIpDossier(currentDossier);
      renderDetailPanel();
      setDetailMode('knowledge');
    });
  });
  renderDetailPanel();
}

function setEvidenceView(view = 'triage') {
  currentEvidenceView = view;
  document.querySelectorAll('[data-evidence-view]').forEach((item) => item.classList.toggle('active', item.getAttribute('data-evidence-view') === view));
  document.querySelectorAll('[data-evidence-panel]').forEach((panel) => panel.classList.toggle('active', panel.getAttribute('data-evidence-panel') === view));
}

function setLogView(view = 'zeek-summary') {
  currentLogView = view;
  document.querySelectorAll('[data-log-view]').forEach((item) => item.classList.toggle('active', item.getAttribute('data-log-view') === view));
  document.querySelectorAll('[data-log-panel]').forEach((panel) => panel.classList.toggle('active', panel.getAttribute('data-log-panel') === view));
}

function setKnowledgeView(view = 'queue') {
  if (view !== 'queue') clearSelectedKnowledgeCard('switched knowledge views');
  currentKnowledgeView = view;
  document.querySelectorAll('[data-knowledge-view]').forEach((item) => item.classList.toggle('active', item.getAttribute('data-knowledge-view') === view));
  document.querySelectorAll('[data-knowledge-panel]').forEach((panel) => panel.classList.toggle('active', panel.getAttribute('data-knowledge-panel') === view));
}

function normalizeTabTarget(target) {
  const mapping = {
    overview: { primary: 'summary' },
    'ip-dossier': { primary: 'summary' },
    triage: { primary: 'evidence', evidence: 'triage' },
    timeline: { primary: 'evidence', evidence: 'timeline' },
    protocols: { primary: 'evidence', evidence: 'protocols' },
    conversations: { primary: 'evidence', evidence: 'conversations' },
    endpoints: { primary: 'evidence', evidence: 'endpoints' },
    hosts: { primary: 'evidence', evidence: 'hosts' },
    'zeek-summary': { primary: 'logs', log: 'zeek-summary' },
    'zeek-conn': { primary: 'logs', log: 'zeek-conn' },
    'zeek-dns': { primary: 'logs', log: 'zeek-dns' },
    'zeek-http': { primary: 'logs', log: 'zeek-http' },
    'zeek-files': { primary: 'logs', log: 'zeek-files' },
    'zeek-ssl': { primary: 'logs', log: 'zeek-ssl' },
    'zeek-x509': { primary: 'logs', log: 'zeek-x509' },
    'zeek-smtp': { primary: 'logs', log: 'zeek-smtp' },
    'zeek-smb-files': { primary: 'logs', log: 'zeek-smb-files' },
    'zeek-smb-mapping': { primary: 'logs', log: 'zeek-smb-mapping' },
    'zeek-dce-rpc': { primary: 'logs', log: 'zeek-dce-rpc' },
    'zeek-notice': { primary: 'logs', log: 'zeek-notice' },
    'zeek-weird': { primary: 'logs', log: 'zeek-weird' },
    'zeek-viewer': { primary: 'logs', log: 'zeek-viewer' },
    knowledge: { primary: 'knowledge', knowledge: 'queue' },
    'knowledge-queue': { primary: 'knowledge', knowledge: 'queue' },
    'knowledge-tree': { primary: 'knowledge', knowledge: 'tree' },
    capinfos: { primary: 'capture-details' },
    metadata: { primary: 'capture-details' },
  };
  if (mapping[target]) return mapping[target];
  return { primary: target };
}

function activateTab(target) {
  if (!target) return;
  const normalized = normalizeTabTarget(target);
  if (normalized.primary !== 'knowledge') clearSelectedKnowledgeCard('switched tabs');
  document.querySelectorAll('[data-tab]').forEach((item) => item.classList.toggle('active', item.getAttribute('data-tab') === normalized.primary));
  document.querySelectorAll('[data-panel]').forEach((panel) => panel.classList.toggle('active', panel.getAttribute('data-panel') === normalized.primary));
  if (normalized.evidence) setEvidenceView(normalized.evidence);
  if (normalized.log) setLogView(normalized.log);
  if (normalized.knowledge) setKnowledgeView(normalized.knowledge);
}

function renderOverview(data) {
  currentOverview = data;
  timelineState.page = 1;
  renderSummaryView();
  renderEventTimeline(data?.event_timeline || []);
  protocolsContent.textContent = (data?.top_protocols || []).join('\n') || 'No protocol hierarchy available.';
  if (data?.conversations_page) {
    conversationPageState = data.conversations_page;
    renderPaginatedTable(conversationsContent, conversationPageState, 'conversations');
  } else {
    conversationsContent.textContent = data?.conversations_text || 'No conversation summary available.';
  }
  if (data?.endpoints_page) {
    endpointPageState = data.endpoints_page;
    renderPaginatedTable(endpointsContent, endpointPageState, 'endpoints');
  } else {
    endpointsContent.textContent = data?.endpoints_text || 'No endpoint summary available.';
  }
  if (data?.hosts_page) {
    hostPageState = data.hosts_page;
    renderPaginatedTable(hostsContent, hostPageState, 'hosts');
  } else {
    hostsContent.textContent = data?.hosts_text || 'No host resolution summary available.';
  }
  renderTriageSummary(data?.triage_sections || []);
  if (!currentDossier) renderSummaryView();
  if (data?.zeek_summary) renderZeekSummary(data.zeek_summary);
  capinfosContent.textContent = data?.capinfos_text || 'No capinfos text available.';
  metadataContent.textContent = JSON.stringify(data?.metadata || {}, null, 2);
}

function renderZeekSummary(data) {
  currentZeekSummary = data;
  if (!zeekSummaryContent) return;
  if (!data?.ready) {
    zeekSummaryContent.innerHTML = `<div class="overview-card"><span>Zeek</span><strong>${escapeHtml(data?.error || 'Zeek summary is not ready yet.')}</strong></div>`;
    Object.entries(zeekTableRegistry).forEach(([logName, config]) => {
      if (config?.element) config.element.innerHTML = `<div class="empty-state">Zeek ${escapeHtml(logName)} preview is not available.</div>`;
    });
    if (!currentDossier) renderSummaryView();
    return;
  }

  const serviceLines = (data?.top_services || []).map((item) => `${escapeHtml(item.name)} (${item.count})`).join('<br>') || 'None yet';
  const pairLines = (data?.top_pairs || []).map((item) => `${escapeHtml(item.pair)} (${item.count})`).join('<br>') || 'None yet';
  const externalLines = (data?.external_destinations || []).map((item) => `${escapeHtml(item.ip)} (${item.count})`).join('<br>') || 'None yet';
  const weirdLines = normalizeZeekRows('weird.log', data?.weird_preview || []).map((item) => `${escapeHtml(item.name || 'weird')} ${item.addl ? `— ${escapeHtml(item.addl)}` : ''}`).join('<br>') || 'None yet';
  const httpCoverageLines = (data?.http_coverage_gaps || []).map((item) => `${escapeHtml(item.summary || 'HTTP-like flow without http.log row')}${item.hints?.length ? ` — ${escapeHtml(item.hints.join(', '))}` : ''}`).join('<br>') || 'None detected';
  const httpFallbackLines = (data?.http_gap_packet_fallbacks || []).map((item) => {
    const parts = [];
    if (item.method || item.uri) parts.push(`${item.method || 'HTTP'} ${item.uri || ''}`.trim());
    if (item.host) parts.push(`host=${item.host}`);
    if (item.response_code) parts.push(`code=${item.response_code}`);
    if (item.content_type) parts.push(item.content_type);
    if (item.frames?.length) parts.push(`frames ${item.frames.join(',')}`);
    if (item.streams?.length) parts.push(`stream ${item.streams.join(',')}`);
    return `${escapeHtml(item.summary || 'Recovered packet hint')} — ${escapeHtml(parts.join(' • '))}`;
  }).join('<br>') || 'None recovered';
  const fileFallbackLines = (data?.file_packet_fallbacks || []).map((item) => {
    const parts = [];
    if (item.filename) parts.push(item.filename);
    if (item.mime_type) parts.push(`mime=${item.mime_type}`);
    if (item.uri) parts.push(`uri=${item.uri}`);
    if (item.host) parts.push(`host=${item.host}`);
    if (item.frames) parts.push(`frames ${item.frames}`);
    return escapeHtml(parts.join(' • ') || 'Recovered file artifact');
  }).join('<br>') || 'None recovered';
  const sslFallbackLines = (data?.ssl_packet_fallbacks || []).map((item) => {
    const parts = [];
    if (item.server_name) parts.push(item.server_name);
    if (item.version) parts.push(item.version);
    if (item.cipher) parts.push(item.cipher);
    if (item.handshake_type) parts.push(`handshake=${item.handshake_type}`);
    if (item.frame) parts.push(`frame ${item.frame}`);
    return escapeHtml(parts.join(' • ') || 'Recovered TLS handshake');
  }).join('<br>') || 'None recovered';
  const captureLossLine = Number.isFinite(data?.capture_loss_percent) ? `${Number(data.capture_loss_percent).toFixed(3)}%` : 'n/a';
  const logCounts = Object.entries(data?.log_counts || {})
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([name, count]) => `<button class="pivot-chip zeek-log-pill" type="button" data-log-open="${escapeHtml(name)}">${escapeHtml(name)} (${count})</button>`)
    .join('') || 'None yet';
  const dnsLines = (data?.top_dns_queries || []).map((item) => `${escapeHtml(item.query)} (${item.count})`).join('<br>') || 'None yet';
  const hostLines = (data?.top_http_hosts || []).map((item) => `${escapeHtml(item.host)} (${item.count})`).join('<br>') || 'None yet';
  const mimeLines = (data?.top_file_mime_types || []).map((item) => `<button class="pivot-chip zeek-log-pill" type="button" data-log-open="${escapeHtml(item.log_name || 'files.log')}" data-log-filter="${escapeHtml(item.mime_type)}">${escapeHtml(item.mime_type)} (${item.count}${item.log_name ? ` • ${escapeHtml(item.log_name)}` : ''})</button>`).join('') || 'None yet';

  zeekSummaryContent.innerHTML = `
    <div class="overview-card"><span>Zeek conn.log rows</span><strong>${escapeHtml(data?.conn_count || 0)}</strong></div>
    <div class="overview-card"><span>Generated logs</span><strong>${escapeHtml((data?.logs || []).length)}</strong></div>
    <div class="overview-card"><span>Top Services</span><strong>${serviceLines}</strong></div>
    <div class="overview-card"><span>Log Counts</span><strong>${logCounts}</strong></div>
    <div class="overview-card"><span>Top Pairs</span><strong>${pairLines}</strong></div>
    <div class="overview-card"><span>External Destinations</span><strong>${externalLines}</strong></div>
    <div class="overview-card"><span>Top DNS Queries</span><strong>${dnsLines}</strong></div>
    <div class="overview-card"><span>Top HTTP Hosts</span><strong>${hostLines}</strong></div>
    <div class="overview-card"><span>Top MIME Types</span><strong>${mimeLines}</strong></div>
    <div class="overview-card"><span>Capture Loss</span><strong>${escapeHtml(captureLossLine)}</strong></div>
    <div class="overview-card"><span>HTTP Coverage Gaps</span><strong>${httpCoverageLines}</strong></div>
    <div class="overview-card"><span>Recovered HTTP Fallbacks</span><strong>${httpFallbackLines}</strong></div>
    <div class="overview-card"><span>Recovered File Fallbacks</span><strong>${fileFallbackLines}</strong></div>
    <div class="overview-card"><span>Recovered TLS Fallbacks</span><strong>${sslFallbackLines}</strong></div>
    <div class="overview-card"><span>Weirds / Oddities</span><strong>${weirdLines}</strong></div>
  `;
  zeekSummaryContent.querySelectorAll('[data-pivot-tab]').forEach((button) => {
    button.addEventListener('click', () => activateTab(button.getAttribute('data-pivot-tab')));
  });
  zeekSummaryContent.querySelectorAll('[data-log-open]').forEach((button) => {
    button.addEventListener('click', () => openZeekLogViewer(button.getAttribute('data-log-open'), currentPcap, { query: button.getAttribute('data-log-filter') || '' }));
  });
  const previews = {
    'conn.log': data?.conn_preview || [],
    'dns.log': data?.dns_preview || [],
    'http.log': data?.http_preview || [],
    'files.log': data?.file_preview || [],
    'ssl.log': data?.ssl_preview || [],
    'x509.log': data?.x509_preview || [],
    'smtp.log': data?.smtp_preview || [],
    'smb_files.log': data?.smb_files_preview || [],
    'smb_mapping.log': data?.smb_mapping_preview || [],
    'dce_rpc.log': data?.dce_rpc_preview || [],
    'notice.log': data?.notice_preview || [],
    'weird.log': normalizeZeekRows('weird.log', data?.weird_preview || []),
  };
  Object.entries(previews).forEach(([logName, rows]) => {
    const existing = zeekLogState[logName] || {};
    zeekLogState[logName] = { rows, query: existing.query || '', selectedColumns: existing.selectedColumns || [], fields: existing.fields || [], fallbackUsed: false, sortDir: existing.sortDir || 'asc' };
    renderZeekLogTable(logName);
  });
  if (!currentDossier) renderSummaryView();
}

async function fetchZeekSummary(pcap = currentPcap) {
  if (!pcap) return;
  const response = await fetch(`/api/zeek/summary?pcap=${encodeURIComponent(pcap)}`);
  const data = await response.json();
  renderZeekSummary(data);
}

async function fetchZeekLog(name, targetEl, pcap = currentPcap) {
  if (!pcap || !targetEl) return;
  const existing = zeekLogState[name] || {};
  const query = existing.query || '';
  zeekLogState[name] = { ...existing, sortDir: existing.sortDir || 'asc', loading: true, progressLabel: query ? `Searching ${name} for ${query}` : `Refreshing ${name}` };
  renderZeekLogTable(name);
  try {
    const response = await fetch(`/api/zeek/log?pcap=${encodeURIComponent(pcap)}&name=${encodeURIComponent(name)}&limit=500&q=${encodeURIComponent(query)}`);
    const data = await response.json();
    zeekLogState[name] = { rows: normalizeZeekRows(name, data?.rows || []), query: existing.query || '', selectedColumns: existing.selectedColumns || [], fields: data?.fields || existing.fields || [], fallbackUsed: Boolean(data?.fallback_used), loading: false, progressLabel: '', sortDir: existing.sortDir || 'asc' };
  } catch (error) {
    zeekLogState[name] = { ...existing, loading: false, progressLabel: '' };
    throw error;
  }
  renderZeekLogTable(name);
}

async function openZeekLogViewer(logName, pcap = currentPcap, options = {}) {
  if (!logName) return;
  currentGenericZeekLog = logName;
  if (typeof options.query === 'string') {
    zeekLogState[logName] = { ...(zeekLogState[logName] || {}), query: options.query };
  }
  activateTab(zeekTableRegistry[logName]?.tab || 'zeek-viewer');
  const targetEl = zeekTableRegistry[logName]?.element || zeekGenericTable;
  await fetchZeekLog(logName, targetEl, pcap);
}

async function fetchConversationPage(page = 1, pcap = currentPcap) {
  if (!pcap || !conversationsContent) return;
  const state = dataViewUiState.conversations || {};
  const response = await fetch(`/api/view/conversations?pcap=${encodeURIComponent(pcap)}&page=${encodeURIComponent(page)}&page_size=25&sort_by=${encodeURIComponent(state.sortBy || 'connections')}&sort_dir=${encodeURIComponent(state.sortDir || 'desc')}&q=${encodeURIComponent(state.query || '')}`);
  const data = await response.json();
  conversationPageState = data;
  renderPaginatedTable(conversationsContent, conversationPageState, 'conversations');
}

async function fetchHostPage(page = 1, pcap = currentPcap) {
  if (!pcap || !hostsContent) return;
  const state = dataViewUiState.hosts || {};
  const response = await fetch(`/api/view/hosts?pcap=${encodeURIComponent(pcap)}&page=${encodeURIComponent(page)}&page_size=25&sort_by=${encodeURIComponent(state.sortBy || 'connections')}&sort_dir=${encodeURIComponent(state.sortDir || 'desc')}&q=${encodeURIComponent(state.query || '')}`);
  const data = await response.json();
  hostPageState = data;
  renderPaginatedTable(hostsContent, hostPageState, 'hosts');
}

async function fetchEndpointPage(page = 1, pcap = currentPcap) {
  if (!pcap || !endpointsContent) return;
  const state = dataViewUiState.endpoints || {};
  const response = await fetch(`/api/view/endpoints?pcap=${encodeURIComponent(pcap)}&page=${encodeURIComponent(page)}&page_size=25&sort_by=${encodeURIComponent(state.sortBy || 'Packets')}&sort_dir=${encodeURIComponent(state.sortDir || 'desc')}&q=${encodeURIComponent(state.query || '')}`);
  const data = await response.json();
  endpointPageState = data;
  renderPaginatedTable(endpointsContent, endpointPageState, 'endpoints');
}

function renderPcapList(pcaps, loaded) {
  knownPcaps = pcaps || [];
  pcapList.innerHTML = '';
  if (!pcaps.length) {
    pcapList.innerHTML = '<div class="pcap-empty">No captures uploaded yet.</div>';
    return;
  }
  for (const pcap of pcaps) {
    const isActive = pcap.relative_path === loaded;
    const isLoading = pcap.relative_path === loadingPcap;
    const row = document.createElement('div');
    row.className = 'pcap-row';
    const button = document.createElement('button');
    button.className = `pcap-item ${isActive ? 'active' : ''} ${isLoading ? 'loading' : ''}`.trim();
    button.disabled = Boolean(loadingPcap && !isActive);
    button.innerHTML = `
      <span class="pcap-name">${escapeHtml(pcap.relative_path)}</span>
      <span class="pcap-size">${Math.round((pcap.size_bytes / (1024 * 1024)) * 10) / 10} MB</span>
    `;
    button.addEventListener('click', async () => {
      if (loadingPcap || pcap.relative_path === currentPcap) return;
      await loadPcap(pcap.relative_path, true);
    });
    const downloadButton = document.createElement('button');
    downloadButton.className = 'pcap-action pcap-download';
    downloadButton.type = 'button';
    downloadButton.title = `Download ${pcap.relative_path}`;
    downloadButton.setAttribute('aria-label', `Download ${pcap.relative_path}`);
    downloadButton.textContent = '⬇';
    downloadButton.disabled = Boolean(loadingPcap);
    downloadButton.addEventListener('click', (event) => {
      event.stopPropagation();
      downloadPcapData(pcap.relative_path);
    });
    const deleteButton = document.createElement('button');
    deleteButton.className = 'pcap-action pcap-delete';
    deleteButton.type = 'button';
    deleteButton.title = `Delete ${pcap.relative_path}`;
    deleteButton.setAttribute('aria-label', `Delete ${pcap.relative_path}`);
    deleteButton.textContent = '🗑';
    deleteButton.disabled = Boolean(loadingPcap);
    deleteButton.addEventListener('click', async (event) => {
      event.stopPropagation();
      await deletePcapData(pcap.relative_path);
    });
    row.appendChild(button);
    row.appendChild(downloadButton);
    row.appendChild(deleteButton);
    pcapList.appendChild(row);
  }
}

function downloadPcapData(pcap) {
  if (!pcap) return;
  const url = `/api/pcap/download?pcap=${encodeURIComponent(pcap)}`;
  const link = document.createElement('a');
  link.href = url;
  link.download = pcap.split('/').pop() || 'capture.pcap';
  document.body.appendChild(link);
  link.click();
  link.remove();
}

async function deletePcapData(pcap) {
  if (!pcap) return;
  const confirmed = window.confirm(`Delete ${pcap} and its associated Zeek/runtime artifacts? Promoted library knowledge will be kept.`);
  if (!confirmed) return;
  const pending = appendPendingMessage(`Deleting ${pcap} and related runtime artifacts...`);
  setActivity(`Deleting ${pcap}`, ['Delete PCAP', 'Remove related artifacts', 'Refresh workspace'], 0, true);
  try {
    const response = await fetch('/api/pcap/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pcap, delete_exports: true }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `Delete failed for ${pcap}`);
    setActivity(`Deleting ${pcap}`, ['Delete PCAP', 'Remove related artifacts', 'Refresh workspace'], 1, true);
    await loadStatus(false);
    setActivity(`Deleting ${pcap}`, ['Delete PCAP', 'Remove related artifacts', 'Refresh workspace'], 2, true);
    resolvePendingMessage(pending, `Deleted ${pcap}. Freed ${formatBytes(data.bytes_freed)} across ${data.deleted_count || 0} artifacts.`, 'PIRE • cleanup');
  } catch (error) {
    console.error(error);
    resolvePendingMessage(pending, `PIRE could not delete ${pcap}: ${error.message}`, 'PIRE • cleanup');
  }
  clearActivity(currentPcap ? `Ready on ${currentPcap}` : 'Idle');
}

async function runCleanupAction(url, description, confirmText = null) {
  if (confirmText && !window.confirm(confirmText)) return;
  const pending = appendPendingMessage(`${description}...`);
  setActivity(description, ['Run cleanup', 'Refresh workspace'], 0, true);
  try {
    const response = await fetch(url, { method: 'POST' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `${description} failed`);
    setActivity(description, ['Run cleanup', 'Refresh workspace'], 1, true);
    await loadStatus(false, { skipOverview: !currentPcap });
    resolvePendingMessage(pending, `${description} complete. Freed ${formatBytes(data.bytes_freed)} across ${data.deleted_count || 0} artifacts.`, 'PIRE • cleanup');
  } catch (error) {
    console.error(error);
    resolvePendingMessage(pending, `${description} failed: ${error.message}`, 'PIRE • cleanup');
  }
  clearActivity(currentPcap ? `Ready on ${currentPcap}` : 'Idle');
}

function renderMetadataSummary(metadata, loadedName, pcapCount, activeCaseId = null) {
  const parsed = metadata?.parsed || {};
  metaSummary.innerHTML = `
    <div><span>Status</span><strong>${loadedName ? 'Loaded' : 'Awaiting PCAP'}</strong></div>
    <div><span>Loaded PCAP</span><strong>${escapeHtml(loadedName || 'None')}</strong></div>
    <div><span>Active Case</span><strong>${escapeHtml(activeCaseId || 'None')}</strong></div>
    <div><span>Known Captures</span><strong>${pcapCount}</strong></div>
    <div><span>Packets</span><strong>${escapeHtml(parsed.number_of_packets || 'n/a')}</strong></div>
    <div><span>Duration</span><strong>${escapeHtml(parsed.capture_duration || 'n/a')}</strong></div>
    <div><span>Encapsulation</span><strong>${escapeHtml(parsed.file_encapsulation || 'n/a')}</strong></div>
  `;
  if (deleteCaseButton) deleteCaseButton.classList.toggle('hidden', !activeCaseId);
}

async function fetchOverview(pcap = currentPcap) {
  if (!pcap) return;
  setActivity(`Refreshing overview for ${pcap}`, ['Load overview', 'Render tabs', 'Refresh Zeek previews'], 0, true);
  const response = await fetch(`/api/overview?pcap=${encodeURIComponent(pcap)}`);
  const data = await response.json();
  setActivity(`Refreshing overview for ${pcap}`, ['Load overview', 'Render tabs', 'Refresh Zeek previews'], 1, true);
  renderOverview(data);
  setActivity(`Refreshing overview for ${pcap}`, ['Load overview', 'Render tabs', 'Refresh Zeek previews'], 2, true);
  refreshZeekTables(pcap);
  clearActivity(`Overview ready for ${pcap}`);
}

function refreshZeekTables(pcap = currentPcap) {
  fetchZeekLog('conn.log', zeekConnTable, pcap).catch((error) => console.error(error));
  fetchZeekLog('dns.log', zeekDnsTable, pcap).catch((error) => console.error(error));
  fetchZeekLog('http.log', zeekHttpTable, pcap).catch((error) => console.error(error));
  fetchZeekLog('files.log', zeekFilesTable, pcap).catch((error) => console.error(error));
  fetchZeekLog('ssl.log', zeekSslTable, pcap).catch((error) => console.error(error));
  fetchZeekLog('x509.log', zeekX509Table, pcap).catch((error) => console.error(error));
  fetchZeekLog('smtp.log', zeekSmtpTable, pcap).catch((error) => console.error(error));
  fetchZeekLog('smb_files.log', zeekSmbFilesTable, pcap).catch((error) => console.error(error));
  fetchZeekLog('smb_mapping.log', zeekSmbMappingTable, pcap).catch((error) => console.error(error));
  fetchZeekLog('dce_rpc.log', zeekDceRpcTable, pcap).catch((error) => console.error(error));
  fetchZeekLog('notice.log', zeekNoticeTable, pcap).catch((error) => console.error(error));
  fetchZeekLog('weird.log', zeekWeirdTable, pcap).catch((error) => console.error(error));
}

async function loadStatus(seedChat = false, options = {}) {
  const { skipOverview = false } = options;
  setActivity('Checking PIRE status', ['Read status', 'Render capture list', 'Refresh active view'], 0, true);
  const response = await fetch('/api/status');
  const data = await response.json();
  currentPcap = data.loaded_pcap || null;
  openclawState = data.openclaw || null;
  renderMetadataSummary(data.latest_metadata || null, currentPcap, data.pcap_count, data.active_case_id || null);
  renderPcapList(data.pcaps || [], currentPcap);
  renderStorageSummary(data.storage || null);
  setActivity('Checking PIRE status', ['Read status', 'Render capture list', 'Refresh active view'], 1, true);
  const ocState = openclawState?.enabled ? `OpenClaw: ${openclawState.model}` : 'OpenClaw: not configured';
  statusRight.textContent = `PCAP: ${currentPcap || 'none'} • Case: ${data.active_case_id || 'none'} • ${ocState}`;
  if (currentPcap) {
    if (data.zeek) {
      renderZeekSummary(data.zeek);
    } else {
      try {
        await fetchZeekSummary(currentPcap);
      } catch (error) {
        console.error(error);
      }
    }
    if (!skipOverview) {
      try {
        await fetchOverview(currentPcap);
      } catch (error) {
        console.error(error);
        appendMessage(`PIRE could not render the full overview for ${currentPcap}, but you can still load another capture from the sidebar.`, 'incoming', 'PIRE • now');
      }
    }
    try {
      await fetchKnowledge(currentPcap);
    } catch (error) {
      console.error(error);
    }
    if (seedChat && !chatScroll.children.length) {
      if (openclawState?.enabled) {
        appendMessage('OpenClaw PIRE mode is ready. Ask your investigation question here; OpenClaw should carry the workflow while PIRE provides evidence and pivots.', 'incoming', 'OpenClaw • now');
      } else {
        appendMessage(`PIRE now expects an OpenClaw backend for investigation turns. Missing: ${(openclawState?.missing || []).join(', ') || 'configuration'}.`, 'incoming', 'PIRE • config');
      }
    }
  }
  if (!currentPcap) {
    renderKnowledgePanel({ queue: [], tree: currentKnowledge?.tree || [] });
  }
  clearActivity(currentPcap ? `Ready on ${currentPcap}` : 'Idle');
}

async function deleteCurrentCase() {
  const caseLabel = statusRight?.textContent?.match(/Case: ([^•]+)/)?.[1]?.trim() || 'the current case';
  const confirmed = window.confirm(`Delete ${caseLabel}? Promoted knowledge will stay, but case-specific state, saved answers, queue leftovers, and case-bound knowledge objects will be removed. If this is the active case, the current PCAP will also be unloaded so the case does not immediately reappear.`);
  if (!confirmed) return;
  setActivity(`Deleting ${caseLabel}`, ['Remove case state', 'Purge case leftovers', 'Refresh workspace'], 0, true);
  const response = await fetch('/api/case/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ unload_if_active: true }),
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.detail || 'Unable to delete current case');
  currentPcap = payload.unloaded_pcap ? null : currentPcap;
  currentDossier = null;
  currentDossierSectionId = null;
  currentSelectedKnowledgeItemId = null;
  renderIpDossier(null);
  setActivity(`Deleting ${caseLabel}`, ['Remove case state', 'Purge case leftovers', 'Refresh workspace'], 1, true);
  await loadStatus(false, { skipOverview: false });
  setActivity(`Deleting ${caseLabel}`, ['Remove case state', 'Purge case leftovers', 'Refresh workspace'], 2, true);
  appendMessage(`Deleted case ${payload.case_id}. Promoted knowledge was preserved.${payload.unloaded_pcap ? ' The active PCAP was unloaded to prevent immediate case recreation.' : ''}`, 'incoming', 'PIRE • case');
  clearActivity('Case deleted');
}

async function loadPcap(pcap, announce = false) {
  const pending = announce ? appendPendingMessage(`Loading ${pcap}...`) : null;
  setActivity(`Loading ${pcap}`, ['Open case', 'Build overview', 'Refresh logs'], 0, true);
  loadingPcap = pcap;
  currentDossier = null;
  currentDossierSectionId = null;
  renderIpDossier(null);
  renderPcapList(knownPcaps, currentPcap);
  statusRight.textContent = `PCAP: ${pcap} • loading...`;
  try {
    const response = await fetch('/api/load', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pcap })
    });
    const data = await response.json();
    if (!response.ok) {
      resolvePendingMessage(pending, data.detail || `Failed to load ${pcap}.`, 'PIRE • now');
      return;
    }
    currentPcap = data.loaded;
    if (data.overview) {
      setActivity(`Loading ${pcap}`, ['Open case', 'Build overview', 'Refresh logs'], 1, true);
      renderOverview(data.overview);
      refreshZeekTables(currentPcap);
    }
    await loadStatus(false, { skipOverview: true });
    setActivity(`Loading ${pcap}`, ['Open case', 'Build overview', 'Refresh logs'], 2, true);
    if (announce) {
      resolvePendingMessage(pending, `Loaded ${currentPcap}. The overview, protocol, conversations, endpoints, hosts, capinfos, and metadata tabs are refreshed.`, 'PIRE • now');
    }
  } catch (error) {
    console.error(error);
    resolvePendingMessage(pending, `Failed to load ${pcap}.`, 'PIRE • error');
  } finally {
    loadingPcap = null;
    try {
      await loadStatus(false, { skipOverview: true });
    } catch (error) {
      console.error(error);
    }
    clearActivity(currentPcap ? `Ready on ${currentPcap}` : 'Idle');
  }
}

async function sendChat(message, options = {}) {
  const attachments = options.attachments || [];
  appendMessage(options.displayText || message);
  const pending = appendPendingMessage('OpenClaw is loading the current PIRE case...');

  if (openclawState && !openclawState.enabled) {
    resolvePendingMessage(pending, `PIRE now depends on an OpenClaw backend for investigation turns. Missing: ${(openclawState.missing || []).join(', ') || 'configuration'}.`, 'PIRE • config');
    return;
  }

  const progressFrames = [
    'OpenClaw is loading the current PIRE case...',
    'OpenClaw is checking protocol and experiential knowledge...',
    'OpenClaw is gathering packet evidence from PIRE...',
    'OpenClaw is building the next investigation move...'
  ];
  const progressSteps = ['Load case', 'Check knowledge', 'Gather evidence', 'Build next move'];
  setActivity('Investigating question', progressSteps, 0, true);
  let progressIndex = 0;
  const progressTimer = window.setInterval(() => {
    progressIndex = Math.min(progressIndex + 1, progressFrames.length - 1);
    updatePendingMessage(pending, progressFrames[progressIndex], 'PIRE • working');
    setActivity('Investigating question', progressSteps, progressIndex, true);
  }, 700);

  try {
    const response = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message,
        pcap: currentPcap,
        selected_knowledge: getSelectedKnowledgeContext(),
        attachments: attachments.map((item) => ({
          kind: item.kind || 'image',
          name: item.name,
          mime_type: item.mimeType,
          data_url: item.dataUrl,
        })),
      })
    });
    const payload = await response.json();
    window.clearInterval(progressTimer);
    if (!response.ok) {
      clearActivity('Investigation failed');
      resolvePendingMessage(pending, payload.detail || 'Something went wrong.');
      return;
    }
    const traceHtml = payload.investigation_trace?.length
      ? `<details class="trace-details"><summary>Investigation trace</summary><ul>${payload.investigation_trace.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul></details>`
      : '';
    if (pending) {
      pending.dataset.pending = 'false';
      pending.classList.remove('pending');
      const stampEl = pending.querySelector('.stamp');
      const bubbleEl = pending.querySelector('.bubble');
      if (stampEl) stampEl.textContent = 'PIRE • now';
      if (bubbleEl) bubbleEl.innerHTML = `<div class="answer-body"><p>${replyHtml(payload.reply || '')}</p></div>${traceHtml}`;
    }
    if (payload.dossier) {
      currentDossierSectionId = payload.dossier.sections?.[0]?.id || currentDossierSectionId;
      renderIpDossier(payload.dossier);
      activateTab('ip-dossier');
      setDetailMode('knowledge');
    }
    if (payload.overview) renderOverview(payload.overview);
    if (payload.rows) timelineTable.innerHTML = renderTable(payload.rows);
    if (payload.case?.case_id) {
      statusRight.textContent = `PCAP: ${currentPcap || 'none'} • Case: ${payload.case.case_id}`;
    }
    clearActivity(payload.focus_ip ? `Dossier ready for ${payload.focus_ip}` : 'Investigation complete');
  } catch (error) {
    window.clearInterval(progressTimer);
    console.error(error);
    clearActivity('Investigation failed');
    resolvePendingMessage(pending, 'The investigation request failed before PIRE could finish.', 'PIRE • error');
  }
}

toggle.addEventListener('click', () => {
  sidebar.classList.toggle('collapsed');
  toggle.textContent = sidebar.classList.contains('collapsed') ? '❯' : '❮';
  updateSidebarLayout();
});

refreshButton.addEventListener('click', () => loadStatus());

deleteExportsButton?.addEventListener('click', async () => {
  await runCleanupAction('/api/cleanup/exports', 'Delete all exports', 'Delete all exported packet slices?');
});

pruneCacheButton?.addEventListener('click', async () => {
  await runCleanupAction('/api/cleanup/zeek-cache', 'Prune orphan Zeek caches');
});

deleteCaseButton?.addEventListener('click', async () => {
  try {
    await deleteCurrentCase();
  } catch (error) {
    console.error(error);
    clearActivity('Case deletion failed');
    appendMessage(`Case deletion failed: ${error.message}`, 'incoming', 'PIRE • case');
  }
});

uploadInput.addEventListener('change', async (event) => {
  const [file] = event.target.files;
  if (!file) return;
  const formData = new FormData();
  formData.append('file', file);
  appendMessage(`Uploading ${file.name} to PIRE...`);
  const response = await fetch('/api/upload', { method: 'POST', body: formData });
  const data = await response.json();
  if (!response.ok) {
    appendMessage(data.detail || 'Upload failed.', 'incoming', 'PIRE • now');
    return;
  }
  currentPcap = data.metadata?.relative_path || data.filename;
  currentDossier = null;
  currentDossierSectionId = null;
  renderOverview(data.overview);
  appendMessage(`Upload saved and ingested: ${data.filename}`, 'incoming', 'PIRE • now');
  await loadStatus(true);
  event.target.value = '';
});

chatForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const value = chatInput.value.trim();
  const attachments = [...chatAttachments];
  if (!value && !attachments.length) return;
  const message = value || defaultImageOnlyPrompt();
  const displayText = value || `Shared ${attachments.length} pasted screenshot${attachments.length === 1 ? '' : 's'}.`;
  chatInput.value = '';
  clearChatAttachments();
  await sendChat(message, { attachments, displayText });
});

chatInput.addEventListener('paste', async (event) => {
  try {
    await handleChatPaste(event);
  } catch (error) {
    console.error(error);
    appendMessage(`Could not attach pasted image: ${error.message}`, 'incoming', 'PIRE • paste');
  }
});

document.querySelectorAll('[data-prompt]').forEach((button) => {
  button.addEventListener('click', async () => {
    const prompt = button.getAttribute('data-prompt');
    if (prompt) await sendChat(prompt);
  });
});

document.querySelectorAll('[data-tab]').forEach((button) => {
  button.addEventListener('click', () => {
    const target = button.getAttribute('data-tab');
    activateTab(target);
  });
});

document.querySelectorAll('[data-evidence-view]').forEach((button) => {
  button.addEventListener('click', () => setEvidenceView(button.getAttribute('data-evidence-view')));
});

document.querySelectorAll('[data-log-view]').forEach((button) => {
  button.addEventListener('click', () => setLogView(button.getAttribute('data-log-view')));
});

document.querySelectorAll('[data-knowledge-view]').forEach((button) => {
  button.addEventListener('click', () => setKnowledgeView(button.getAttribute('data-knowledge-view')));
});

knowledgeQueueContent?.addEventListener('click', async (event) => {
  const tagButton = event.target.closest('.knowledge-tag');
  if (tagButton) {
    tagButton.classList.toggle('selected');
    return;
  }
  const actionButton = event.target.closest('.knowledge-action');
  if (actionButton) {
    const card = actionButton.closest('.knowledge-card');
    try {
      await submitKnowledgeAction(card, actionButton.dataset.knowledgeAction || 'promoted');
    } catch (error) {
      console.error(error);
      appendMessage(`Knowledge update failed: ${error.message}`, 'incoming', 'PIRE • knowledge');
    }
    return;
  }
  const card = event.target.closest('.knowledge-card');
  if (!card) return;
  const interactive = event.target.closest('textarea, button, a, input, select, label');
  if (interactive) return;
  setSelectedKnowledgeCard(card.dataset.itemId || '');
});

knowledgeTreeContent?.addEventListener('click', async (event) => {
  const fileButton = event.target.closest('.knowledge-file-link');
  if (!fileButton) return;
  try {
    await openKnowledgeNote(fileButton.dataset.notePath || '');
  } catch (error) {
    console.error(error);
    appendMessage(`Could not open saved knowledge note: ${error.message}`, 'incoming', 'PIRE • knowledge');
  }
});

knowledgeNoteText?.addEventListener('input', () => {
  if (!currentKnowledgeNote || !knowledgeNoteText) return;
  setKnowledgeSaveDirty(knowledgeNoteText.value !== currentKnowledgeNote.original);
});

knowledgeNoteClose?.addEventListener('click', () => {
  closeKnowledgeNote();
});

knowledgeNoteSave?.addEventListener('click', async () => {
  try {
    await saveKnowledgeNote();
  } catch (error) {
    console.error(error);
    appendMessage(`Could not save knowledge note: ${error.message}`, 'incoming', 'PIRE • knowledge');
  }
});

knowledgeNoteDelete?.addEventListener('click', async () => {
  try {
    await deleteKnowledgeNote();
  } catch (error) {
    console.error(error);
    appendMessage(`Could not delete knowledge note: ${error.message}`, 'incoming', 'PIRE • knowledge');
  }
});

applyPresetButton?.addEventListener('click', () => {
  applyPreset(presetSelect?.value);
});

saveThemeButton?.addEventListener('click', () => {
  if (paletteEditor?.classList.contains('open')) readPaletteEditor();
  saveTheme();
});

toggleEditorButton?.addEventListener('click', () => {
  paletteEditor?.classList.toggle('open');
  if (toggleEditorButton) {
    toggleEditorButton.textContent = paletteEditor?.classList.contains('open') ? 'Hide manual colors' : 'Show manual colors';
  }
});

paletteGrid?.addEventListener('input', () => {
  readPaletteEditor();
});

loadStatus(true).catch((error) => {
  console.error(error);
  appendMessage('Unable to load PIRE status.', 'incoming', 'PIRE • now');
});

updateSidebarLayout();
setEvidenceView(currentEvidenceView);
setLogView(currentLogView);
setKnowledgeView(currentKnowledgeView);
initThemes();
setDetailMode('knowledge');
renderIpDossier(null);
