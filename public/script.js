const PRODUCT_PRICES = { course: 89, signals: 75, chartbot: 30 };
let selectedProduct = 'course';
let currentUser = null;

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
async function api(url, options = {}) {
  const response = await fetch(url, { credentials: 'same-origin', ...options, headers: { ...(options.body instanceof FormData ? {} : { 'content-type': 'application/json' }), ...(options.headers || {}) } });
  let data = {}; try { data = await response.json(); } catch {}
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}
function setMessage(el, message, error = false) { if (!el) return; el.textContent = message; el.dataset.error = error ? 'true' : 'false'; }

const authModal = $('#authModal');
const authForm = $('#authForm');
const authMessage = $('#authMessage');
const authModeButtons = $$('[data-auth-mode]');
let authMode = 'register';
function setAuthMode(mode) {
  authMode = mode;
  const reg = mode === 'register';
  $('#authTitle').textContent = reg ? 'Enter your workspace.' : 'Welcome back, trader.';
  $('#authEyebrow').textContent = reg ? 'Your learning account' : 'Learner sign in';
  $('#authSubmit').innerHTML = `${reg ? 'Create my account' : 'Open my library'} <span aria-hidden="true">&#8594;</span>`;
  $('#fullNameGroup').hidden = !reg;
  $('#authPassword').autocomplete = reg ? 'new-password' : 'current-password';
  $('#passwordHint').textContent = reg ? 'At least 10 characters.' : 'Use the password you created.';
  authModeButtons.forEach(b => b.classList.toggle('active', b.dataset.authMode === mode));
  setMessage(authMessage, '');
}
function openAuthModal(mode = 'register') {
  setAuthMode(mode); authModal.hidden = false; document.body.classList.add('modal-open');
  $('[data-close-auth]').hidden = Boolean(!currentUser); $('#authUsername').focus();
}
function closeAuthModal() { if (currentUser) { authModal.hidden = true; document.body.classList.remove('modal-open'); document.body.classList.remove('auth-required'); } }
async function refreshMe() {
  try { const data = await api('/api/me'); currentUser = data.user; window.entitlements = data.entitlements || []; }
  catch { currentUser = null; window.entitlements = []; }
  refreshAccountActions(); refreshChartbotAccess();
  if (currentUser) document.body.classList.remove('auth-required');
}
function refreshAccountActions() {
  const account = $('#accountButton'), logout = $('#logoutButton');
  if (account) account.hidden = Boolean(currentUser); if (logout) logout.hidden = !currentUser;
}
function hasAccess(product) {
  return (window.entitlements || []).some(e => e.product === product && (!e.expires_at || new Date(e.expires_at) > new Date()));
}
async function logout() { try { await api('/api/auth/logout', { method: 'POST', body: '{}' }); } catch {} currentUser = null; window.entitlements = []; refreshAccountActions(); openAuthModal('login'); }

$$('[data-open-auth]').forEach(b => b.addEventListener('click', () => openAuthModal('register')));
$$('[data-close-auth]').forEach(b => b.addEventListener('click', closeAuthModal));
authModeButtons.forEach(b => b.addEventListener('click', () => setAuthMode(b.dataset.authMode)));
$('#logoutButton')?.addEventListener('click', logout);
authModal?.addEventListener('click', e => { if (e.target === authModal && currentUser) closeAuthModal(); });

authForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const username = $('#authUsername').value.trim().toLowerCase();
  const password = $('#authPassword').value;
  const name = $('#fullName').value.trim();
  if (authMode === 'register' && name.length < 2) return setMessage(authMessage, 'Enter your full name.', true);
  if (!/^[a-z0-9_.-]{3,32}$/.test(username)) return setMessage(authMessage, 'Username: 3–32 characters using letters, numbers, dot, dash or underscore.', true);
  if (password.length < 10) return setMessage(authMessage, 'Password must contain at least 10 characters.', true);
  try {
    const data = await api(authMode === 'register' ? '/api/auth/register' : '/api/auth/login', { method: 'POST', body: JSON.stringify(authMode === 'register' ? { name, username, password } : { username, password }) });
    currentUser = data.user; await refreshMe(); closeAuthModal();
  } catch (error) { setMessage(authMessage, error.message, true); }
});

const paymentModal = $('#paymentModal');
const paymentMessage = $('#paymentMessage');
const paymentAmount = $('#paymentAmount');
const transactionHash = $('#transactionHash');
const paymentChoices = $$('[data-payment-product]');
function selectPaymentProduct(product) {
  selectedProduct = PRODUCT_PRICES[product] ? product : 'course';
  paymentChoices.forEach(c => c.classList.toggle('active', c.dataset.paymentProduct === selectedProduct));
  if (paymentAmount) paymentAmount.value = '';
  if (transactionHash) transactionHash.value = '';
  $('#unlockLinks')?.setAttribute('hidden', '');
  setMessage(paymentMessage, `Send exactly ${PRODUCT_PRICES[selectedProduct]} USDT on TRON TRC-20.`);
}
function openPaymentModal(product = 'course') {
  if (!currentUser) return openAuthModal('login');
  selectPaymentProduct(product); paymentModal.hidden = false; document.body.classList.add('modal-open');
  $('#walletAddress').textContent = window.PAYMENT_ADDRESS || 'Configure TRC20_WALLET_ADDRESS on the server';
  const address = $('#walletAddress').textContent;
  $('#paymentQr').src = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(address)}`;
  $('#explorerLink').href = 'https://tronscan.org/#/address/' + encodeURIComponent(address);
}
function closePaymentModal() { paymentModal.hidden = true; document.body.classList.remove('modal-open'); }
$$('[data-open-payment]').forEach(b => b.addEventListener('click', () => openPaymentModal(b.dataset.paymentProduct || 'course')));
$$('[data-close-payment]').forEach(b => b.addEventListener('click', closePaymentModal));
paymentChoices.forEach(c => c.addEventListener('click', () => selectPaymentProduct(c.dataset.paymentProduct)));
paymentModal?.addEventListener('click', e => { if (e.target === paymentModal) closePaymentModal(); });
$('#copyAddress')?.addEventListener('click', async () => { try { await navigator.clipboard.writeText($('#walletAddress').textContent); $('#copyAddress').textContent='Copied'; setTimeout(()=>$('#copyAddress').textContent='Copy',1500); } catch { setMessage(paymentMessage,'Copy failed. Copy the address manually.',true); } });
$('#submitPayment')?.addEventListener('click', async () => {
  const amount = Number(paymentAmount.value); const txHash = transactionHash.value.trim();
  if (amount !== PRODUCT_PRICES[selectedProduct]) return setMessage(paymentMessage, `Enter exactly ${PRODUCT_PRICES[selectedProduct]} USDT.`, true);
  if (!/^[a-fA-F0-9]{20,200}$/.test(txHash)) return setMessage(paymentMessage, 'Enter a valid-looking transaction hash (hex characters only).', true);
  try { await api('/api/payments', { method:'POST', body: JSON.stringify({ product:selectedProduct, amount, txHash }) }); setMessage(paymentMessage, 'Submitted. Access stays locked until an admin confirms the payment.'); await refreshMe(); refreshChartbotAccess(); }
  catch (e) { setMessage(paymentMessage, e.message, true); }
});

const chartImages = $('#chartImages'), chartPreviewList = $('#chartPreviewList'), chartPreviewWrap = $('#chartPreviewWrap'), analyzeChart = $('#analyzeChart'), analysisMessage = $('#analysisMessage');
const maxChartImages = 3, maxChartBytes = 4 * 1024 * 1024;
let selectedCharts = [], previewUrls = [];
function refreshChartbotAccess() {
  const subscribe = $('#chartbotSubscribe'), status = $('#chartbotStatus'); if (!subscribe || !status) return;
  const active = hasAccess('chartbot'); subscribe.hidden = active; status.hidden = active ? true : false;
  if (active) { status.hidden = false; status.innerHTML = '<span class="status-dot"></span><span>Chart Bot subscription active · 20 analyses / 24h</span>'; }
}
function clearCharts() {
  selectedCharts = [];
  previewUrls.forEach(url => URL.revokeObjectURL(url));
  previewUrls = [];
  if (chartImages) chartImages.value = '';
  chartPreviewList?.replaceChildren();
  if (chartPreviewWrap) chartPreviewWrap.hidden = true;
  if (analyzeChart) analyzeChart.disabled = true;
}
chartImages?.addEventListener('change', () => {
  const files = [...(chartImages.files || [])];
  if (!files.length) return;
  const totalBytes = files.reduce((total, file) => total + file.size, 0);
  if (files.length > maxChartImages) { clearCharts(); return setMessage(analysisMessage, 'Choose no more than three images.', true); }
  if (files.some(file => !['image/png', 'image/jpeg', 'image/webp'].includes(file.type))) { clearCharts(); return setMessage(analysisMessage, 'Choose PNG, JPG or WEBP images only.', true); }
  if (totalBytes > maxChartBytes) { clearCharts(); return setMessage(analysisMessage, 'The combined image size must be 4 MB or less.', true); }
  clearCharts();
  selectedCharts = files;
  files.forEach(file => {
    const card = document.createElement('div'); card.className = 'chart-preview-item';
    const image = document.createElement('img'); image.alt = `Chart preview: ${file.name}`;
    const url = URL.createObjectURL(file); previewUrls.push(url); image.src = url;
    const name = document.createElement('span'); name.className = 'chart-preview-name'; name.textContent = file.name;
    card.append(image, name); chartPreviewList.append(card);
  });
  chartPreviewWrap.hidden = false;
  analyzeChart.disabled = !hasAccess('chartbot');
  setMessage(analysisMessage, hasAccess('chartbot') ? `${files.length} chart image${files.length === 1 ? '' : 's'} ready. They will be analyzed together.` : 'Subscribe and wait for payment approval before analysis.');
});
$('#removeCharts')?.addEventListener('click', () => { clearCharts(); setMessage(analysisMessage, 'Images removed.'); });
analyzeChart?.addEventListener('click', async () => {
  if (!selectedCharts.length) return;
  if (!currentUser) return openAuthModal('login');
  if (!hasAccess('chartbot')) return openPaymentModal('chartbot');
  const form = new FormData(); selectedCharts.forEach(file => form.append('charts', file));
  analyzeChart.disabled = true; setMessage(analysisMessage, 'Analyzing all chart images…');
  try { const data = await api('/api/chart/analyze', { method: 'POST', body: form }); renderAnalysis(data.result); }
  catch (e) { setMessage(analysisMessage, e.message, true); }
  finally { analyzeChart.disabled = !selectedCharts.length || !hasAccess('chartbot'); }
});
function renderAnalysis(result) {
  const fields = [['Read from each image', 'imageRead'], ['Timeframes', 'timeframes'], ['Market structure', 'structure'], ['Liquidity', 'liquidity'], ['Order blocks', 'orderBlocks'], ['Fair value gaps', 'fairValueGaps'], ['Support and resistance', 'supportResistance'], ['Price action', 'priceAction']];
  const fieldMarkup = fields.map(([label, key]) => `<p class="muted analysis-detail"><strong>${label}:</strong> ${escapeHtml(formatAnalysisValue(result[key]))}</p>`).join('');
  const scenarioFields = [['Entry zone', 'entryZone'], ['Confirmation', 'confirmation'], ['Stop loss', 'stopLoss'], ['Target 1', 'target1'], ['Target 2', 'target2'], ['Invalidation', 'invalidation'], ['Risk/reward', 'riskReward']];
  const scenarios = Array.isArray(result.entryScenarios) ? result.entryScenarios : [];
  const scenarioMarkup = scenarios.length ? scenarios.map((scenario, index) => `<article class="analysis-scenario"><h4>${escapeHtml(scenario.direction || `Scenario ${index + 1}`)}</h4>${scenarioFields.map(([label, key]) => `<p><strong>${label}:</strong> ${escapeHtml(formatAnalysisValue(scenario[key]))}</p>`).join('')}</article>`).join('') : '<p class="muted">No clear conditional entry scenario from these images.</p>';
  const old = $('#analysisResult'); if (old) old.remove();
  const box = document.createElement('div'); box.id = 'analysisResult'; box.className = 'dashboard-card analysis-result';
  box.innerHTML = `<p class="card-label">AI chart review</p><h3>${escapeHtml(result.marketBias || 'Market bias unclear')}</h3><div class="analysis-details">${fieldMarkup}</div><h4>Conditional entry scenarios</h4><div class="analysis-scenarios">${scenarioMarkup}</div><p class="muted analysis-detail"><strong>No-trade condition:</strong> ${escapeHtml(formatAnalysisValue(result.noTradeCondition))}</p><p class="muted analysis-detail"><strong>Confidence:</strong> ${escapeHtml(formatAnalysisValue(result.confidence))}</p><p class="muted analysis-detail"><strong>Notes:</strong> ${escapeHtml(formatAnalysisValue(result.notes))}</p><p class="tiny-note">Educational analysis only, not financial advice. Levels may be unclear in the uploaded images.</p>`;
  $('.chartbot-panel')?.appendChild(box); setMessage(analysisMessage, 'Analysis complete.');
}
function formatAnalysisValue(value) {
  if (value === null || value === undefined || value === '') return 'Not clear from the images';
  if (Array.isArray(value)) return value.map(formatAnalysisValue).join('\n');
  if (typeof value === 'object') return Object.entries(value).map(([key, item]) => `${key}: ${formatAnalysisValue(item)}`).join('\n');
  return String(value);
}
function escapeHtml(value) { return String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }

(async () => { try { const config = await api('/api/config'); window.PAYMENT_ADDRESS = config.paymentAddress; } catch {} await refreshMe(); if (!currentUser) openAuthModal('register'); else closeAuthModal(); })();
