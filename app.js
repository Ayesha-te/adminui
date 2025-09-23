(function(){
  const $ = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));
  // Determine and normalize API base. Priority: localStorage -> ?apiBase= -> same-origin /api
  function normalizeApiBase(v){
    if(!v) return '';
    let base = String(v).trim();
    base = base.replace(/\/+$/,'');
    // If it doesn't include '/api' segment, append it
    if(!/\/api$/.test(base)) base = base + '/api';
    return base;
  }
  const defaultApiBaseRaw =
    (typeof localStorage !== 'undefined' && localStorage.getItem('adminApiBase')) ||
    new URLSearchParams(location.search).get('apiBase') ||
    new URL('/api', location.origin).toString().replace(/\/$/, '');
  const defaultApiBase = normalizeApiBase(defaultApiBaseRaw);
  // Initialize state with tokens from localStorage if available
  const state = {
    apiBase: defaultApiBase,
    access: (typeof localStorage !== 'undefined' && localStorage.getItem('admin_access')) || null,
    refresh: (typeof localStorage !== 'undefined' && localStorage.getItem('admin_refresh')) || null,
  };

  const toast = (msg) => {
    const el = $('#toast');
    el.textContent = msg;
    el.style.display = 'block';
    setTimeout(()=>{ el.style.display = 'none'; }, 2000);
  };

  // Render current API base (no longer shown in UI)
  function showApiBase(){}

  async function detectApiBase(){
    // Prioritize production backend, then local development
    const productionBackend = 'https://ref-backend-8arb.onrender.com/api';
    const candidates = [
      productionBackend,  // Production backend (Render)
      'http://127.0.0.1:8000/api',  // Local Django server
      'http://localhost:8000/api',   // Alternative local address
      location.origin.replace(/:\d+$/, '') + ':8000/api',  // Dynamic local Django
      new URL('/api', location.origin).toString().replace(/\/$/, '')
    ];
    for(const base of candidates){
      try{
        const r = await fetch(`${base}/auth/token/`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username:'__probe__', password:'__probe__' })
        });
        // 400/401 are acceptable -> endpoint exists
        if([400,401].includes(r.status)){
          return base;
        }
      }catch(_){ /* ignore */ }
    }
    return candidates[0];
  }

  // Initialize API base automatically without UI controls
  (async ()=>{
    // Clear cached API base to force re-detection
    try{ localStorage.removeItem('adminApiBase'); }catch(_){ }
    
    // Try production backend first
    const productionBase = 'https://ref-backend-8arb.onrender.com/api';
    try {
      const testResponse = await fetch(`${productionBase}/auth/token/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: '__probe__', password: '__probe__' })
      });
      if ([400, 401].includes(testResponse.status)) {
        state.apiBase = productionBase;
        try{ localStorage.setItem('adminApiBase', productionBase); }catch(_){ }
        console.log('Admin UI connected to PRODUCTION backend:', productionBase);
        showApiBase();
        return;
      }
    } catch (e) {
      console.log('Production backend not available, trying local development...');
    }
    
    // Fallback to local development server
    const localBase = 'http://127.0.0.1:8000/api';
    try {
      const testResponse = await fetch(`${localBase}/auth/token/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: '__probe__', password: '__probe__' })
      });
      if ([400, 401].includes(testResponse.status)) {
        state.apiBase = localBase;
        try{ localStorage.setItem('adminApiBase', localBase); }catch(_){ }
        console.log('Admin UI connected to LOCAL server:', localBase);
        showApiBase();
        return;
      }
    } catch (e) {
      console.log('Local server not available, using auto-detection...');
    }
    
    const base = normalizeApiBase(await detectApiBase());
    try{ localStorage.setItem('adminApiBase', base); }catch(_){ }
    state.apiBase = base; showApiBase();
    console.log('Admin UI connected to:', base);
  })();

  const setStatus = (msg) => $('#status').textContent = msg || '';

  function authHeaders(headers={}){
    if(state.access){ headers['Authorization'] = `Bearer ${state.access}`; }
    return headers;
  }

  const get = async (url) => {
    setStatus('Loading...');
    const res = await fetch(url, { headers: authHeaders(), credentials: 'omit' });
    setStatus('');
    if (res.status === 401 && state.refresh) {
      // attempt refresh and retry once
      await refreshToken();
      const retry = await fetch(url, { headers: authHeaders(), credentials: 'omit' });
      if(!retry.ok) throw new Error(await retry.text());
      return retry.json();
    }
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  };

  const post = async (url, body) => {
    setStatus('Working...');
    const res = await fetch(url, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      credentials: 'omit',
      body: JSON.stringify(body||{})
    });
    setStatus('');
    if (res.status === 401 && state.refresh) {
      await refreshToken();
      const retry = await fetch(url, {
        method: 'POST',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        credentials: 'omit',
        body: JSON.stringify(body||{})
      });
      if(!retry.ok) throw new Error(await retry.text());
      return retry.json().catch(()=>({ ok:true }));
    }
    if (!res.ok) throw new Error(await res.text());
    return res.json().catch(()=>({ ok:true }));
  };

  const patch = async (url, body) => {
    setStatus('Working...');
    const res = await fetch(url, {
      method: 'PATCH',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      credentials: 'omit',
      body: JSON.stringify(body||{})
    });
    setStatus('');
    if (res.status === 401 && state.refresh) {
      await refreshToken();
      const retry = await fetch(url, {
        method: 'PATCH',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        credentials: 'omit',
        body: JSON.stringify(body||{})
      });
      if(!retry.ok) throw new Error(await retry.text());
      return retry.json().catch(()=>({ ok:true }));
    }
    if (!res.ok) throw new Error(await res.text());
    return res.json().catch(()=>({ ok:true }));
  };

  async function login(username, password){
    const res = await fetch(`${state.apiBase}/auth/token/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    if(!res.ok){
      let detail = 'Login failed';
      try { const data = await res.json(); detail = data?.detail || detail; } catch(_){ try{ detail = await res.text() || detail; }catch(__){}
      }
      throw new Error(`[${res.status}] ${detail}`);
    }
    const data = await res.json();
    state.access = data.access; state.refresh = data.refresh;
    try {
      localStorage.setItem('admin_access', state.access || '');
      localStorage.setItem('admin_refresh', state.refresh || '');
    } catch {}
    toast('Logged in');
  }

  async function refreshToken(){
    if(!state.refresh) return;
    const data = await fetch(`${state.apiBase}/auth/token/refresh/`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh: state.refresh })
    }).then(r=>{ if(!r.ok) throw new Error('Refresh failed'); return r.json(); });
    state.access = data.access;
    if (data.refresh) { state.refresh = data.refresh; }
    try {
      localStorage.setItem('admin_access', state.access || '');
      if (state.refresh) localStorage.setItem('admin_refresh', state.refresh);
    } catch {}
  }

  function logout(){
    state.access = null; state.refresh = null;
    try { localStorage.removeItem('admin_access'); localStorage.removeItem('admin_refresh'); } catch {}
    toast('Logged out');
  }

  // Navigation
  $$('.nav-btn').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const id = btn.dataset.section;
      $('#sectionTitle').textContent = btn.textContent; // fix: use single element selector
      $$('.section').forEach(s => s.classList.remove('active'));
      $('#'+id).classList.add('active');
      // Auto-load when switching sections (only if logged in when admin endpoints)
      if(id==='users'){ loadUsers(); }
      if(id==='dashboard'){ loadDashboard(); }
      if(id==='deposits'){ if(state.access) loadDeposits(); else setStatus('Login required'); }
      if(id==='withdrawals'){ if(state.access) loadWithdrawals(); else setStatus('Login required'); }
      if(id==='referrals'){ if(state.access) loadReferrals(); else setStatus('Login required'); }
      if(id==='proofs'){ if(state.access) loadProofs(); else setStatus('Login required'); }
      if(id==='system'){ if(state.access) loadSystem(); else setStatus('Login required'); }
      if(id==='globalpool'){ if(state.access) loadGlobalPool(); else setStatus('Login required'); }
      if(id==='systemoverview'){ if(state.access) loadSystemOverview(); else setStatus('Login required'); }
      if(id==='products'){ if(state.access) loadProducts(); else setStatus('Login required'); }
      if(id==='orders'){ if(state.access) loadOrders(); else setStatus('Login required'); }
    });
  });

  // Login bindings
  $('#loginBtn').addEventListener('click', async ()=>{
    try{
      const u = $('#loginUsername').value.trim();
      const p = $('#loginPassword').value;
      if(!u||!p){ toast('Enter username and password'); return; }
      await login(u,p);
      // On login, refresh all sections
      loadDashboard(); loadUsers(); loadPendingUsers(); loadDeposits(); loadWithdrawals(); loadReferrals(); loadProofs(); loadProducts(); loadGlobalPool(); loadSystemOverview();
    }catch(e){ console.error(e); toast(String(e?.message || e || 'Login failed')); }
  });
  $('#logoutBtn').addEventListener('click', ()=>{ logout(); });

  // Dashboard stats loaders
  async function loadDashboard(){
    try {
      const [pendingUsers, pendingDeposits, pendingWithdrawals, referralSummary] = await Promise.all([
        get(`${state.apiBase}/accounts/admin/pending-users/`),
        get(`${state.apiBase}/wallets/admin/deposits/pending/`),
        get(`${state.apiBase}/withdrawals/admin/pending/`),
        get(`${state.apiBase}/referrals/admin/summary/`)
      ]);
      $('#statPendingUsers').textContent = pendingUsers?.length ?? '0';
      $('#statPendingDeposits').textContent = pendingDeposits?.length ?? '0';
      $('#statPendingWithdrawals').textContent = pendingWithdrawals?.length ?? '0';
      const totalRefs = referralSummary?.total ?? (referralSummary?.total_referrals ?? '0');
      $('#statTotalReferrals').textContent = totalRefs;
    } catch (e) {
      console.error(e);
      toast('Failed to load dashboard');
    }
  }

  // Users full list with search/filter/pagination
  const usersState = { page: 1, pageSize: 20, q: '', isApproved: 'true', isActive: '', isStaff: '', djFrom: '', djTo: '', orderBy: 'id' };

  async function loadUsers(){
    const tbody = $('#usersTbody');
    tbody.innerHTML = '<tr><td colspan="16" class="muted">Loading...</td></tr>';
    try{
      const params = new URLSearchParams({
        page: String(usersState.page),
        page_size: String(usersState.pageSize),
      });
      if (usersState.q) params.set('q', usersState.q);
      if (usersState.isApproved !== '') params.set('is_approved', usersState.isApproved);
      if (usersState.isActive !== '') params.set('is_active', usersState.isActive);
      if (usersState.isStaff !== '') params.set('is_staff', usersState.isStaff);
      if (usersState.djFrom) params.set('date_joined_from', usersState.djFrom);
      if (usersState.djTo) params.set('date_joined_to', usersState.djTo);
      if (usersState.orderBy) params.set('order_by', usersState.orderBy);
      const data = await get(`${state.apiBase}/accounts/admin/users/?${params.toString()}`);
      const rows = data.results || [];
      if(!rows.length){
        tbody.innerHTML = '<tr><td colspan="16" class="muted">No users found</td></tr>';
      } else {
        tbody.innerHTML = '';
        rows.forEach(u=>{
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td>${escapeHtml(u.username || '-')}</td>
            <td>${escapeHtml(u.email || '-')}</td>
            <td>${escapeHtml(u.first_name || '')}</td>
            <td>${escapeHtml(u.last_name || '')}</td>
            <td>${u.is_active ? 'Yes' : 'No'}</td>
            <td>${u.is_staff ? 'Yes' : 'No'}</td>
            <td>${u.is_approved ? 'Yes' : 'No'}</td>
            <td>${Number(u.rewards_usd||0).toFixed(2)}</td>
            <td>${Number(u.passive_income_usd||0).toFixed(2)}</td>
            <td>${Number(u.current_balance_usd||0).toFixed(2)}</td>
            <td>${Number(u.referrals_count||0)}</td>
            <td>${escapeHtml(u.bank_name || '-')}</td>
            <td>${escapeHtml(u.account_name || '-')}</td>
            <td>${u.date_joined ? new Date(u.date_joined).toLocaleString() : '-'}</td>
            <td>${u.last_login ? new Date(u.last_login).toLocaleString() : '-'}</td>
            <td>
              ${!u.is_approved ? `<button class="btn secondary" data-action="reject" data-id="${u.id}">Reject</button>` : ''}
              ${u.is_active ? `<button class="btn secondary" data-action="deactivate" data-id="${u.id}">Deactivate</button>` : `<button class="btn ok" data-action="activate" data-id="${u.id}">Activate</button>`}
            </td>
          `;
          tbody.appendChild(tr);
        });
      }
      // pagination info
      const total = data.count || 0;
      const totalPages = Math.max(1, Math.ceil(total / usersState.pageSize));
      $('#usersPageInfo').textContent = `Page ${usersState.page} of ${totalPages} (${total} users)`;
      $('#usersPrev').disabled = usersState.page <= 1;
      $('#usersNext').disabled = usersState.page >= totalPages;
    }catch(e){
      console.error(e); tbody.innerHTML = '<tr><td colspan="16" class="muted">Failed to load</td></tr>';
    }
  }

  // Sort by clicking table headers with data-sort
  document.querySelectorAll('thead th[data-sort]').forEach(th=>{
    th.style.cursor = 'pointer';
    th.addEventListener('click', ()=>{
      const key = th.getAttribute('data-sort');
      usersState.orderBy = (usersState.orderBy === key) ? ('-'+key) : key;
      usersState.page = 1;
      loadUsers();
    });
  });

  function applyUsersFilterFrom(primary){
    const qEl = primary ? $('#usersSearch') : $('#usersSearch2');
    const apprEl = primary ? $('#usersApproved') : $('#usersApproved2');
    usersState.q = (qEl?.value || '').trim();
    usersState.isApproved = apprEl?.value ?? '';
    usersState.isActive = $('#usersActive')?.value ?? '';
    usersState.isStaff = $('#usersStaff')?.value ?? '';
    usersState.djFrom = $('#dateJoinedFrom')?.value ?? '';
    usersState.djTo = $('#dateJoinedTo')?.value ?? '';
    usersState.page = 1;
    loadUsers();
  }
  $('#applyUsersFilter').addEventListener('click', ()=>applyUsersFilterFrom(true));
  $('#applyUsersFilter2').addEventListener('click', ()=>applyUsersFilterFrom(false));
  $('#usersPrev').addEventListener('click', ()=>{ if(usersState.page>1){ usersState.page--; loadUsers(); }});
  $('#usersNext').addEventListener('click', ()=>{ usersState.page++; loadUsers(); });

  $('#refreshUsers').addEventListener('click', ()=>{ loadUsers(); loadPendingUsers(); });

  // User actions for main users table
  $('#usersTbody').addEventListener('click', async (e)=>{
    const btn = e.target.closest('button');
    if(!btn) return;
    const id = btn.dataset.id;
    const action = btn.dataset.action;
    try{
      if(action === 'reject'){
        await post(`${state.apiBase}/accounts/admin/reject/${id}/`);
        toast('User rejected');
      } else if(action === 'activate'){
        await post(`${state.apiBase}/accounts/admin/activate/${id}/`);
        toast('User activated');
      } else if(action === 'deactivate'){
        await post(`${state.apiBase}/accounts/admin/deactivate/${id}/`);
        toast('User deactivated');
      }
      await loadUsers();
      await loadDashboard();
    }catch(err){ console.error(err); toast('Action failed'); }
  });

  // Users (pending) list and actions
  async function loadPendingUsers(){
    const tbody = $('#pendingUsersTbody');
    tbody.innerHTML = '<tr><td colspan="4" class="muted">Loading...</td></tr>';
    try{
      const rows = await get(`${state.apiBase}/accounts/admin/pending-users/`);
      if(!rows.length){
        tbody.innerHTML = '<tr><td colspan="4" class="muted">No pending users</td></tr>';
        return;
      }
      tbody.innerHTML = '';
      rows.forEach(u=>{
        const tr = document.createElement('tr');
        const proofLink = u.signup_proof_url ? `<a href="${u.signup_proof_url}" target="_blank">View</a>` : '-';
        tr.innerHTML = `
          <td>${escapeHtml(u.username || '-')}
            <div class="muted small">${escapeHtml(u.first_name || '')} ${escapeHtml(u.last_name || '')}</div>
          </td>
          <td>${escapeHtml(u.email || '-')}</td>
          <td>${escapeHtml(u.signup_tx_id || '-')}</td>
          <td>${proofLink}</td>
          <td>${u.submitted_at ? new Date(u.submitted_at).toLocaleString() : '-'}</td>
          <td>
            <button class="btn ok" data-action="approve" data-id="${u.id}">Approve</button>
            <button class="btn secondary" data-action="reject" data-id="${u.id}">Reject</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }catch(e){
      console.error(e); tbody.innerHTML = '<tr><td colspan="4" class="muted">Failed to load</td></tr>';
    }
  }

  $('#pendingUsersTbody').addEventListener('click', async (e)=>{
    const btn = e.target.closest('button');
    if(!btn) return;
    const id = btn.dataset.id;
    try{
      if(btn.dataset.action==='approve'){
        await post(`${state.apiBase}/accounts/admin/approve/${id}/`);
        toast('User approved');
      }else if(btn.dataset.action==='reject'){
        await post(`${state.apiBase}/accounts/admin/reject/${id}/`);
        toast('User rejected');
      }
      await loadPendingUsers();
      await loadDashboard();
    }catch(err){ console.error(err); toast('Action failed'); }
  });

  // Withdrawals
  async function loadWithdrawals(){
    const tbody = $('#withdrawalsTbody');
    tbody.innerHTML = '<tr><td colspan="9" class="muted">Loading...</td></tr>';
    try{
      const rows = await get(`${state.apiBase}/withdrawals/admin/pending/`);
      if(!rows.length){ 
        tbody.innerHTML = '<tr><td colspan="9" class="muted">No pending withdrawals</td></tr>'; 
        return; 
      }
      tbody.innerHTML = '';
      rows.forEach(w=>{
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${w.id}</td>
          <td>${escapeHtml(w.user?.username || w.username || '-')}</td>
          <td>${escapeHtml(w.user?.email || w.email || '-')}</td>
          <td>${escapeHtml(w.tx_id || '-')}</td>
          <td>${escapeHtml(w.bank_name || '-')}</td>
          <td>${escapeHtml(w.account_name || '-')}</td>
          <td>${Number(w.amount_usd||0).toFixed(2)}</td>
          <td>${w.created_at ? new Date(w.created_at).toLocaleString() : '-'}</td>
          <td>
            <button class="btn ok" data-action="approve" data-id="${w.id}">Approve</button>
            <button class="btn" data-action="paid" data-id="${w.id}">Mark Paid</button>
            <button class="btn secondary" data-action="reject" data-id="${w.id}">Reject</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }catch(e){ 
      console.error(e); 
      tbody.innerHTML = '<tr><td colspan="9" class="muted">Failed to load</td></tr>'; 
    }
  }

  $('#withdrawalsTbody').addEventListener('click', async (e)=>{
    const btn = e.target.closest('button'); 
    if(!btn) return; 
    const id = btn.dataset.id;
    const action = btn.dataset.action;
    try{
      let backendAction = action === 'approve' ? 'APPROVE' : action === 'reject' ? 'REJECT' : action === 'paid' ? 'PAID' : action;
      await post(`${state.apiBase}/withdrawals/admin/action/${id}/`, { action: backendAction });
      toast('Withdrawal updated');
      await loadWithdrawals();
      await loadDashboard();
    }catch(err){ console.error(err); toast('Action failed'); }
  });

  // Deposits
  async function loadDeposits(){
    const tbody = $('#depositsTbody');
    tbody.innerHTML = '<tr><td colspan="6" class="muted">Loading...</td></tr>';
    try{
      const rows = await get(`${state.apiBase}/wallets/admin/deposits/pending/`);
      if(!rows.length){ tbody.innerHTML = '<tr><td colspan="6" class="muted">No pending</td></tr>'; return; }
      tbody.innerHTML = '';
      rows.forEach(d=>{
        const tr = document.createElement('tr');
        const proofUrl = d.proof_image_url || (d.proof_image ? `${location.origin}/media/${d.proof_image}` : null);
        tr.innerHTML = `
          <td>${d.id}</td>
          <td>${escapeHtml(d.user?.username || '-')}</td>
          <td>${escapeHtml(d.user?.email || '-')}</td>
          <td>${escapeHtml(d.tx_id || '-')}</td>
          <td>${escapeHtml(d.bank_name || '-')}</td>
          <td>${escapeHtml(d.account_name || '-')}</td>
          <td>${proofUrl ? `<a href="${proofUrl}" target="_blank">View</a>` : '-'}</td>
          <td>${Number(d.amount_usd||0).toFixed(2)}</td>
          <td>${escapeHtml(d.created_at || '-')}</td>
          <td>
            <button class="btn ok" data-action="approve" data-id="${d.id}">Approve</button>
            <button class="btn" data-action="credit" data-id="${d.id}">Credit</button>
            <button class="btn secondary" data-action="reject" data-id="${d.id}">Reject</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }catch(e){ console.error(e); tbody.innerHTML = '<tr><td colspan="6" class="muted">Failed to load</td></tr>'; }
  }

  $('#depositsTbody').addEventListener('click', async (e)=>{
    const btn = e.target.closest('button'); if(!btn) return; const id = btn.dataset.id;
    const action = btn.dataset.action;
      try{
        let backendAction = action === 'approve' ? 'APPROVE' : action === 'reject' ? 'REJECT' : action === 'credit' ? 'CREDIT' : action;
        await post(`${state.apiBase}/wallets/admin/deposits/action/${id}/`, { action: backendAction });
        toast('Deposit updated');
        await loadDeposits();
        await loadDashboard();
        await loadGlobalPool(); // Reload global pool balance after deposit action
      }catch(err){ console.error(err); toast('Action failed'); }
  });

  // Products
  async function loadProducts(){
    const tbody = $('#productsTbody');
    if(!tbody) return;
    tbody.innerHTML = '<tr><td colspan="5" class="muted">Loading...</td></tr>';
    try{
      const rows = await get(`${state.apiBase}/marketplace/admin/products/`);
      if(!rows.length){ tbody.innerHTML = '<tr><td colspan="5" class="muted">No products</td></tr>'; return; }
      tbody.innerHTML = '';
      rows.forEach(p=>{
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${escapeHtml(p.title)}</td>
          <td>${Number(p.price_usd||0).toFixed(2)}</td>
          <td>${escapeHtml(p.description||'')}</td>
          <td>${p.is_active ? 'Yes' : 'No'}</td>
          <td>
            <button class="btn" data-action="toggle" data-id="${p.id}">${p.is_active?'Disable':'Enable'}</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }catch(e){ console.error(e); tbody.innerHTML = '<tr><td colspan="5" class="muted">Failed to load</td></tr>'; }
  }

  // Orders
  async function loadOrders(){
    const tbody = $('#ordersTbody');
    if(!tbody) return;
    tbody.innerHTML = '<tr><td colspan="10" class="muted">Loading...</td></tr>';
    try{
      const statusSel = $('#ordersFilterStatus');
      const statusVal = statusSel ? statusSel.value : '';
      const url = statusVal ? `${state.apiBase}/marketplace/admin/orders/?status=${encodeURIComponent(statusVal)}` : `${state.apiBase}/marketplace/admin/orders/`;
      const rows = await get(url);
      if(!rows.length){ tbody.innerHTML = '<tr><td colspan="10" class="muted">No orders</td></tr>'; return; }
      tbody.innerHTML = '';
      rows.forEach(o=>{
        const tr = document.createElement('tr');
        const proofUrl = o.proof_image_url || (o.proof_image ? `${location.origin}/media/${o.proof_image}` : null);
        tr.innerHTML = `
          <td>${o.id}</td>
          <td>${escapeHtml(o.product_title || '-')}</td>
          <td>${escapeHtml(o.buyer_username || '-')}</td>
          <td>${escapeHtml([o.guest_name, o.guest_email, o.guest_phone].filter(Boolean).join(' / ') || '-')}</td>
          <td>${escapeHtml(o.tx_id || '-')}</td>
          <td>${Number(o.total_usd||0).toFixed(2)}</td>
          <td>${escapeHtml(o.status || '-')}</td>
          <td>${proofUrl ? `<a href="${proofUrl}" target="_blank">View</a>` : '-'}</td>
          <td>${o.created_at ? new Date(o.created_at).toLocaleString() : '-'}</td>
          <td>
            <select data-action="set-status" data-id="${o.id}">
              ${['PENDING','PAID','CANCELLED'].map(s=>`<option value="${s}" ${o.status===s?'selected':''}>${s}</option>`).join('')}
            </select>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }catch(e){ console.error(e); tbody.innerHTML = '<tr><td colspan="10" class="muted">Failed to load</td></tr>'; }
  }

  $('#addProductBtn')?.addEventListener('click', async (e)=>{
    e.preventDefault();
    e.stopPropagation();
    const btn = e.currentTarget;
    if(btn.disabled) return;
    btn.disabled = true;
    try{
      const title = ($('#newProductName')?.value||'').trim();
      const price = Number($('#newProductPrice')?.value||'');
      const description = ($('#newProductDesc')?.value||'').trim();
      const imageFile = $('#newProductImage')?.files?.[0] || null;
      if(!title){ toast('Title is required'); return; }
      if(!description){ toast('Description is required'); return; }
      if(!(price>0)){ toast('Valid price (USD) is required'); return; }
      const fd = new FormData();
      fd.append('title', title);
      fd.append('price_usd', String(price));
      fd.append('description', description);
      if(imageFile){ fd.append('image', imageFile); }
      setStatus('Working...');
      const res = await fetch(`${state.apiBase}/marketplace/admin/products/`, {
        method: 'POST',
        headers: authHeaders(), // do NOT set Content-Type for FormData
        body: fd,
        credentials: 'omit'
      });
      setStatus('');
      if(!res.ok){ throw new Error(await res.text()); }
      toast('Product added');
      $('#newProductName').value=''; $('#newProductPrice').value=''; $('#newProductDesc').value=''; if($('#newProductImage')) $('#newProductImage').value='';
      await loadProducts();
    }catch(e){ console.error(e); toast('Add failed'); }
    finally{ btn.disabled = false; }
  });

  document.querySelector('#productsTbody')?.addEventListener('click', async (e)=>{
    const btn = e.target.closest('button[data-action="toggle"]');
    if(!btn) return;
    btn.disabled = true;
    try{
      await patch(`${state.apiBase}/marketplace/admin/products/${btn.dataset.id}/toggle/`, {});
      toast('Product status updated');
      await loadProducts();
    }catch(err){ console.error(err); toast('Toggle failed'); }
    finally{ btn.disabled = false; }
  });

  // Orders handlers
  document.querySelector('#ordersTbody')?.addEventListener('change', async (e)=>{
    const sel = e.target.closest('select[data-action="set-status"]');
    if(!sel) return;
    const id = sel.dataset.id;
    const status = sel.value;
    try{
      await patch(`${state.apiBase}/marketplace/admin/orders/${id}/status/`, { status });
      toast('Order updated');
    }catch(err){ console.error(err); toast('Update failed'); }
  });
  $('#refreshOrders')?.addEventListener('click', loadOrders);
  $('#ordersFilterStatus')?.addEventListener('change', loadOrders);

  // Withdrawals
  async function loadWithdrawals(){
    const tbody = $('#withdrawalsTbody');
    tbody.innerHTML = '<tr><td colspan="8" class="muted">Loading...</td></tr>';
    try{
      const rows = await get(`${state.apiBase}/withdrawals/admin/pending/`);
      if(!rows.length){ tbody.innerHTML = '<tr><td colspan="8" class="muted">No pending</td></tr>'; return; }
      tbody.innerHTML = '';
      rows.forEach(w=>{
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${w.id}</td>
          <td>${escapeHtml(w.user?.username || '-')}</td>
          <td>${escapeHtml(w.user?.email || '-')}</td>
          <td>${escapeHtml(w.tx_id || '-')}</td>
          <td>${escapeHtml(w.bank_name || '-')}</td>
          <td>${escapeHtml(w.account_name || '-')}</td>
          <td>${Number(w.amount_usd||0).toFixed(2)}</td>
          <td>${escapeHtml(w.created_at || '-')}</td>
          <td>
            <button class="btn ok" data-action="approve" data-id="${w.id}">Approve</button>
            <button class="btn secondary" data-action="reject" data-id="${w.id}">Reject</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }catch(e){ console.error(e); tbody.innerHTML = '<tr><td colspan="8" class="muted">Failed to load</td></tr>'; }
  }

  $('#withdrawalsTbody').addEventListener('click', async (e)=>{
    const btn = e.target.closest('button'); if(!btn) return; const id = btn.dataset.id;
    const action = btn.dataset.action;
    try{
      await post(`${state.apiBase}/withdrawals/admin/action/${id}/`, { action });
      toast('Withdrawal updated');
      await loadWithdrawals();
      await loadDashboard();
    }catch(err){ console.error(err); toast('Action failed'); }
  });

  // System overview
  async function loadSystem(){
    const wrap = $('#systemContent');
    if(!wrap) return;
    wrap.innerHTML = '<div class="muted">Loading...</div>';
    try{
      const data = await get(`${state.apiBase}/earnings/admin/system-overview/`);
      wrap.innerHTML = `
        <div class="cards">
          <div class="card"><h3>Passive Mode</h3><div class="stat">${String(data.PASSIVE_MODE)}</div></div>
          <div class="card"><h3>User Wallet Share</h3><div class="stat">${Number(data.USER_WALLET_SHARE*100).toFixed(0)}%</div></div>
          <div class="card"><h3>Withdraw Tax</h3><div class="stat">${Number(data.WITHDRAW_TAX*100).toFixed(0)}%</div></div>
          <div class="card"><h3>Global Pool Cut</h3><div class="stat">${Number(data.GLOBAL_POOL_CUT*100).toFixed(0)}%</div></div>
        </div>
        <div class="card" style="margin-top:16px">
          <h3>Referral Tiers</h3>
          <pre style="white-space:pre-wrap">${escapeHtml(JSON.stringify(data.REFERRAL_TIERS, null, 2))}</pre>
        </div>
      `;
    }catch(e){ console.error(e); wrap.innerHTML = '<div class="muted">Failed to load</div>'; }
  }

  // Referrals summary
  async function loadReferrals(){
    const wrap = $('#referralSummaryCards');
    wrap.innerHTML = '<div class="muted">Loading...</div>';
    try{
      const data = await get(`${state.apiBase}/referrals/admin/summary/`);
      wrap.innerHTML = '';
      const makeCard = (title, val) => {
        const el = document.createElement('div');
        el.className = 'card';
        el.innerHTML = `<h3>${title}</h3><div class="stat">${val}</div>`;
        wrap.appendChild(el);
      };
      makeCard('Total Referrals', data?.total ?? data?.total_referrals ?? '—');
      if (data?.level1_count !== undefined) makeCard('Direct (L1)', data.level1_count);
      if (data?.level2_count !== undefined) makeCard('Indirect (L2)', data.level2_count);
    }catch(e){ console.error(e); wrap.innerHTML = '<div class="muted">Failed to load</div>'; }
  }

  // Signup proofs
  async function loadProofs(){
    const tbody = $('#proofsTbody');
    tbody.innerHTML = '<tr><td colspan="6" class="muted">Loading...</td></tr>';
    try{
      const rows = await get(`${state.apiBase}/accounts/admin/pending-signup-proofs/`);
      if(!rows.length){ tbody.innerHTML = '<tr><td colspan="6" class="muted">No pending</td></tr>'; return; }
      tbody.innerHTML = '';
      rows.forEach(p=>{
        const tr = document.createElement('tr');
        const fileUrl = p.file?.startsWith('http') ? p.file : `${location.origin}/media/${p.file}`;
        tr.innerHTML = `
          <td>${p.id}</td>
          <td>${escapeHtml(p.user?.username || '-')}</td>
          <td>${escapeHtml(p.user?.email || '-')}</td>
          <td><a href="${fileUrl}" target="_blank">View</a></td>
          <td>${escapeHtml(p.created_at || '-')}</td>
          <td>
            <button class="btn ok" data-action="approve" data-id="${p.id}">Approve</button>
            <button class="btn secondary" data-action="reject" data-id="${p.id}">Reject</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }catch(e){ console.error(e); tbody.innerHTML = '<tr><td colspan="6" class="muted">Failed to load</td></tr>'; }
  }

  $('#proofsTbody').addEventListener('click', async (e)=>{
    const btn = e.target.closest('button'); if(!btn) return; const id = btn.dataset.id;
    const action = btn.dataset.action;
    try{
      await post(`${state.apiBase}/accounts/admin/signup-proof/action/${id}/`, { action });
      toast('Signup proof updated');
      await loadProofs();
      await loadDashboard();
    }catch(err){ console.error(err); toast('Action failed'); }
  });

  // Helpers
  function escapeHtml(str){
    return String(str==null?'':str)
      .replaceAll('&','&amp;')
      .replaceAll('<','&lt;')
      .replaceAll('>','&gt;')
      .replaceAll('"','&quot;')
      .replaceAll("'",'&#39;');
  }

  // Global Pool
  async function loadGlobalPool(){
    try{
      const data = await get(`${state.apiBase}/earnings/admin/global-pool/`);
      $('#globalPayoutDay').textContent = data.payout_day || 'Monday';
      $('#globalPoolBalance').textContent = `$${Number(data.pool_balance_usd || 0).toFixed(2)} USD`;
      $('#globalPayoutAmount').textContent = data.last_payout?.amount_usd ? `$${Number(data.last_payout.amount_usd).toFixed(2)} USD` : '—';
      const tbody = $('#globalPoolUsersTbody');
      const rows = data.per_user_passive || [];
      tbody.innerHTML = rows.length ? '' : '<tr><td colspan="2" class="muted">No data</td></tr>';
      rows.forEach(r=>{
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${escapeHtml(r.username)}</td><td>$${Number(r.total_passive_usd||0).toFixed(2)} USD</td>`;
        tbody.appendChild(tr);
      });
    }catch(e){ console.error(e); toast('Failed to load global pool'); }
  }

  // System Overview
  async function loadSystemOverview(){
    try{
      const data = await get(`${state.apiBase}/earnings/admin/system-overview/`);
      // Just display this data; it's mostly static config values
      console.log('System Overview:', data);
    }catch(e){ console.error(e); toast('Failed to load system overview'); }
  }



  // Bind refresh buttons
  $('#refreshUsers').addEventListener('click', loadPendingUsers);
  $('#refreshDeposits').addEventListener('click', loadDeposits);
  $('#refreshWithdrawals').addEventListener('click', loadWithdrawals);
  $('#refreshReferrals').addEventListener('click', loadReferrals);
  $('#refreshProofs').addEventListener('click', loadProofs);

  // Initial loads
  loadDashboard();
  loadPendingUsers();
  loadDeposits();
  loadWithdrawals();
  loadReferrals();
  loadProofs();
  loadGlobalPool();
})();