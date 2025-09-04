(function(){
  const $ = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));
  // Determine API base. Priority: localStorage -> ?apiBase= -> environment (localhost for dev) -> production URL
  const defaultApiBase =
    (typeof localStorage !== 'undefined' && localStorage.getItem('adminApiBase')) ||
    new URLSearchParams(location.search).get('apiBase') ||
    'https://ref-backend-8arb.onrender.com/api';
  const state = { apiBase: defaultApiBase, access: null, refresh: null };

  const toast = (msg) => {
    const el = $('#toast');
    el.textContent = msg;
    el.style.display = 'block';
    setTimeout(()=>{ el.style.display = 'none'; }, 2000);
  };

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
    toast('Logged in');
  }

  async function refreshToken(){
    if(!state.refresh) return;
    const data = await fetch(`${state.apiBase}/auth/token/refresh/`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh: state.refresh })
    }).then(r=>{ if(!r.ok) throw new Error('Refresh failed'); return r.json(); });
    state.access = data.access;
  }

  function logout(){ state.access = null; state.refresh = null; toast('Logged out'); }

  // Navigation
  $$('.nav-btn').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const id = btn.dataset.section;
      $('#sectionTitle').textContent = btn.textContent; // fix: use single element selector
      $$('.section').forEach(s => s.classList.remove('active'));
      $('#'+id).classList.add('active');
      // Auto-load when switching sections
      if(id==='users'){ loadUsers(); }
      if(id==='dashboard'){ loadDashboard(); }
      if(id==='deposits'){ loadDeposits(); }
      if(id==='withdrawals'){ loadWithdrawals(); }
      if(id==='referrals'){ loadReferrals(); }
      if(id==='proofs'){ loadProofs(); }
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
      loadDashboard(); loadUsers(); loadPendingUsers(); loadDeposits(); loadWithdrawals(); loadReferrals(); loadProofs();
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
    tbody.innerHTML = '<tr><td colspan="12" class="muted">Loading...</td></tr>';
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
        tbody.innerHTML = '<tr><td colspan="12" class="muted">No users found</td></tr>';
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
            <td>${Number(u.referrals_count||0)}</td>
            <td>${escapeHtml(u.bank_name || '-')}</td>
            <td>${escapeHtml(u.account_name || '-')}</td>
            <td>${u.date_joined ? new Date(u.date_joined).toLocaleString() : '-'}</td>
            <td>${u.last_login ? new Date(u.last_login).toLocaleString() : '-'}</td>
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
      console.error(e); tbody.innerHTML = '<tr><td colspan="12" class="muted">Failed to load</td></tr>';
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
      await post(`${state.apiBase}/wallets/admin/deposits/action/${id}/`, { action });
      toast('Deposit updated');
      await loadDeposits();
      await loadDashboard();
    }catch(err){ console.error(err); toast('Action failed'); }
  });

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
})();