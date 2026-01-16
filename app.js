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
    new URLSearchParams(location.search).get('apiBase') ||
    new URL('/api', location.origin).toString().replace(/\/$/, '');
  const defaultApiBase = normalizeApiBase(defaultApiBaseRaw);
  
  // Clear any conflicting localStorage that might cause issues
  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem('adminApiBase');
    localStorage.setItem('adminApiBase', defaultApiBase);
  }
  
  // Add immediate auto-login for production
  window.quickLogin = async function() {
    console.log('🚀 Manual login trigger...');
    try {
      await login('Ahmad', '12345');
      console.log('✅ Manual login successful');
      toast('✅ Logged in successfully!');
      // Reload the dashboard
      setTimeout(() => {
        if (typeof loadAllDashboardData === 'function') {
          loadAllDashboardData();
        }
      }, 500);
    } catch (error) {
      console.log('❌ Manual login failed:', error.message);
      toast('❌ Login failed: ' + error.message);
    }
  };

  // Add debugging function
  window.debugAuth = function() {
    console.log('🔍 Authentication Debug:');
    console.log('- API Base:', state.apiBase);
    console.log('- Access Token:', state.access ? `${state.access.substring(0, 30)}...` : 'null');
    console.log('- Refresh Token:', state.refresh ? `${state.refresh.substring(0, 30)}...` : 'null');
    console.log('- localStorage access:', localStorage.getItem('admin_access') ? 'exists' : 'missing');
    console.log('- localStorage refresh:', localStorage.getItem('admin_refresh') ? 'exists' : 'missing');
  };

  console.log('🎮 Debug Commands Available:');
  console.log('- quickLogin() - Manual login with Ahmad/12345');
  console.log('- debugAuth() - Show current auth state');

  console.log('🔧 DEBUG: Forced API base to:', defaultApiBase);
  // Initialize state with tokens from localStorage if available
  const state = {
    apiBase: defaultApiBase,
    // support both admin_access (existing) and token (common JWT key)
    access: (typeof localStorage !== 'undefined' && (localStorage.getItem('admin_access') || localStorage.getItem('token'))) || null,
    refresh: (typeof localStorage !== 'undefined' && localStorage.getItem('admin_refresh')) || null,
    conversionRate: 280,
  };

  // If axios is present on the page (some integrations), set default Authorization
  try {
    if (window.axios && typeof window.axios === 'function') {
      const tokenForAxios = localStorage.getItem('token') || localStorage.getItem('admin_access');
      if (tokenForAxios) window.axios.defaults.headers.common['Authorization'] = `Bearer ${tokenForAxios}`;
    }
  } catch (e) { /* ignore */ }

  const toast = (msg) => {
    const el = $('#toast');
    el.textContent = msg;
    el.style.display = 'block';
    setTimeout(()=>{ el.style.display = 'none'; }, 2000);
  };

  const formatUsdToPkr = (usd) => {
    const pkr = Number(usd || 0) * state.conversionRate;
    return `${pkr.toFixed(2)} PKR`;
  };

  const formatPkr = (pkr) => {
    return `${Number(pkr || 0).toFixed(2)} PKR`;
  };

  // Render current API base (no longer shown in UI)
  function showApiBase(){}

  async function detectApiBase(){
    // Prioritize production backend, then local development
    const productionBackend = 'https://experienced-bobine-aamzaabdul-1b0916a2.koyeb.app/api';
    const candidates = [
      productionBackend,  // Production backend (Render)
      'http://192.168.100.141:8000/api',  // Network IP
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

  // Helper function to perform authentication check
  const performAuthCheck = () => {
    console.log('🔍 Checking authentication state...');
    console.log('🔍 Access token exists:', !!state.access);
    console.log('🔍 Refresh token exists:', !!state.refresh);
    
    if (state.access || state.refresh) {
      console.log('✅ Found stored tokens, validating...');
      setTimeout(() => validateStoredTokens(), 100);
    } else {
      console.log('❌ No stored tokens found, attempting auto-login...');
      setTimeout(async () => {
        try {
          // Auto-login with Ahmad/12345 for production
          await login('Ahmad', '12345');
          console.log('✅ Auto-login successful');
          toast('✅ Auto-login successful!');
          // Load dashboard after successful login
          setTimeout(() => {
            if (typeof loadAllDashboardData === 'function') {
              loadAllDashboardData();
            }
          }, 500);
        } catch (error) {
          console.log('❌ Auto-login failed:', error.message);
          setAuthStatus(false, 'Auto-login failed - use quickLogin()');
          toast('❌ Auto-login failed. Try: quickLogin()');
        }
      }, 100);
    }
  };

  // Initialize API base automatically without UI controls
  (async ()=>{
    // Clear cached API base to force re-detection
    try{ localStorage.removeItem('adminApiBase'); }catch(_){ }
    
    // Try production backend first
    const productionBase = 'https://experienced-bobine-aamzaabdul-1b0916a2.koyeb.app/api';
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

    // Fallback: try production
    console.log('Testing production backend:', productionBase);
    try {
      const testResponse = await fetch(`${productionBase}/auth/token/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: '__probe__', password: '__probe__' })
      });
      console.log('Production backend response:', testResponse.status);
      if ([400, 401].includes(testResponse.status)) {
        state.apiBase = productionBase;
        try{ localStorage.setItem('adminApiBase', productionBase); }catch(_){ }
        console.log('✅ Admin UI connected to PRODUCTION backend:', productionBase);
        showApiBase();
        // Perform authentication check after API base is set
        performAuthCheck();
        return;
      }
    } catch (e) {
      console.error('❌ Production backend connection failed:', e.message);
      if (isProduction) {
        setStatus('❌ Backend connection failed. CORS or network issue detected.');
        setAuthStatus(false, 'Backend unavailable');
        state.apiBase = productionBase;
        try{ localStorage.setItem('adminApiBase', productionBase); }catch(_){ }
        showApiBase();
        // Still try authentication check even if backend connection failed
        performAuthCheck();
        return;
      }
      console.log('Production backend not available.');
    }
    
    // If we reach here, no backend was detected - still try authentication
    performAuthCheck();
  })();

  const setStatus = (msg) => $('#status').textContent = msg || '';
  
  const handleApiError = (error, context = '') => {
    console.error(`❌ API Error in ${context}:`, error.message);
    
    let displayMsg = error.message;
    if (displayMsg.length > 100) {
      displayMsg = displayMsg.substring(0, 100) + '...';
    }
    
    toast(`❌ ${displayMsg}`);
    
    if (error.message.includes('Authentication failed') || error.message.includes('session may have expired')) {
      console.warn('🔄 Attempting token refresh due to authentication error...');
      setTimeout(() => {
        if (typeof validateStoredTokens === 'function') {
          validateStoredTokens();
        }
      }, 500);
    }
  };
  
  const setAuthStatus = (isAuthenticated, message = '') => {
    const authStatusEl = $('#authStatus');
    const loginBtn = $('#loginBtn');
    const loginForm = $('#loginForm');
    
    if (authStatusEl) {
      if (isAuthenticated) {
        authStatusEl.textContent = message || 'Authenticated ✓';
        authStatusEl.style.color = '#28a745';
      } else {
        authStatusEl.textContent = message || 'Not Authenticated';
        authStatusEl.style.color = '#dc3545';
      }
    }
    
    if (loginBtn) {
      loginBtn.textContent = isAuthenticated ? 'Logout' : 'Login';
    }
    
    if (loginForm) {
      loginForm.style.display = 'none';
    }
  };

  // Helper function to safely parse JSON responses
  const parseJsonSafely = async (response) => {
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      try {
        return await response.json();
      } catch (e) {
        throw new Error('Invalid JSON response from server');
      }
    } else {
      // If it's not JSON, get the text and throw an error
      const text = await response.text();
      console.error('Server returned non-JSON response:');
      console.error('URL:', response.url);
      console.error('Status:', response.status);
      console.error('Content-Type:', contentType);
      console.error('Response text (first 500 chars):', text.substring(0, 500));

      if (text.includes('<!DOCTYPE') || text.includes('<html>')) {
        let errorMsg = 'Server returned HTML error page.';
        if (response.status === 401 || response.status === 403) {
          errorMsg = 'Authentication failed. Your session may have expired. Please login again.';
        } else if (response.status === 404) {
          errorMsg = 'API endpoint not found. Please check the server configuration.';
        } else if (response.status === 500) {
          errorMsg = 'Server error (500). The backend may be experiencing issues.';
        } else if (response.status === 502 || response.status === 503) {
          errorMsg = 'Server temporarily unavailable. Please try again in a moment.';
        } else {
          errorMsg = `Server error (HTTP ${response.status}). This usually indicates an authentication or server issue.`;
        }
        throw new Error(errorMsg);
      }
      throw new Error(`Expected JSON response but got: ${contentType || 'unknown content type'} (HTTP ${response.status})`);
    }
  };

  function authHeaders(headers={}){
    if(state.access){ headers['Authorization'] = `Bearer ${state.access}`; }
    return headers;
  }

  const get = async (url) => {
    console.log('🌐 GET request to:', url);
    console.log('🔍 Current API base:', state.apiBase);
    console.log('🔍 Current access token:', state.access ? `${state.access.substring(0, 20)}...` : 'null');
    
    setStatus('Loading...');
    const headers = authHeaders();
    console.log('🔍 Request headers:', headers);
    
    // Use credentials: 'include' for session-based auth (no token), otherwise omit for JWT
    const creds = state.access ? 'omit' : 'include';
    const res = await fetch(url, { 
      headers,
      credentials: creds,
      method: 'GET'
    });
    
    console.log('📡 Response status:', res.status);
    console.log('📡 Response headers:', Object.fromEntries(res.headers.entries()));
    console.log('📡 Content-Type:', res.headers.get('content-type'));
    
    setStatus('');
    if (res.status === 401 && state.refresh) {
      console.log('🔄 Attempting token refresh...');
      // attempt refresh and retry once
      const refreshSuccess = await refreshToken();
      if (refreshSuccess) {
        console.log('✅ Token refresh successful, retrying request...');
        const retryHeaders = authHeaders();
        const retryCreds = state.access ? 'omit' : 'include';
        const retry = await fetch(url, { 
          headers: retryHeaders, 
          credentials: retryCreds,
          method: 'GET'
        });
        if(!retry.ok) {
          console.error('❌ Retry failed with status:', retry.status);
          return await parseJsonSafely(retry);
        }
        return await parseJsonSafely(retry);
      } else {
        console.log('❌ Token refresh failed');
        throw new Error('Authentication failed. Please login again.');
      }
    }
    if (!res.ok) {
      console.error('❌ Request failed with status:', res.status);
      return await parseJsonSafely(res);
    }
    return await parseJsonSafely(res);
  };

  const post = async (url, body) => {
    setStatus('Working...');
    const creds = state.access ? 'omit' : 'include';
    const res = await fetch(url, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      credentials: creds,
      body: JSON.stringify(body||{})
    });
    setStatus('');
    console.log('📡 POST Response status:', res.status);
    console.log('📡 Content-Type:', res.headers.get('content-type'));
    
    if (res.status === 401 && state.refresh) {
      console.log('🔄 POST: Attempting token refresh...');
      const refreshSuccess = await refreshToken();
      if (refreshSuccess) {
        console.log('✅ POST: Token refresh successful, retrying...');
        const retryCreds = state.access ? 'omit' : 'include';
        const retry = await fetch(url, {
          method: 'POST',
          headers: authHeaders({ 'Content-Type': 'application/json' }),
          credentials: retryCreds,
          body: JSON.stringify(body||{})
        });
        if(!retry.ok) {
          console.error('❌ POST Retry failed with status:', retry.status);
          return await parseJsonSafely(retry);
        }
        return await parseJsonSafely(retry);
      } else {
        throw new Error('Authentication failed. Please login again.');
      }
    }
    if (!res.ok) {
      console.error('❌ POST failed with status:', res.status);
      return await parseJsonSafely(res);
    }
    return await parseJsonSafely(res);
  };

  const patch = async (url, body) => {
    setStatus('Working...');
    const creds = state.access ? 'omit' : 'include';
    const res = await fetch(url, {
      method: 'PATCH',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      credentials: creds,
      body: JSON.stringify(body||{})
    });
    setStatus('');
    console.log('📡 PATCH Response status:', res.status);
    console.log('📡 Content-Type:', res.headers.get('content-type'));
    
    if (res.status === 401 && state.refresh) {
      console.log('🔄 PATCH: Attempting token refresh...');
      const refreshSuccess = await refreshToken();
      if (refreshSuccess) {
        console.log('✅ PATCH: Token refresh successful, retrying...');
        const retryCreds = state.access ? 'omit' : 'include';
        const retry = await fetch(url, {
          method: 'PATCH',
          headers: authHeaders({ 'Content-Type': 'application/json' }),
          credentials: retryCreds,
          body: JSON.stringify(body||{})
        });
        if(!retry.ok) {
          console.error('❌ PATCH Retry failed with status:', retry.status);
          return await parseJsonSafely(retry);
        }
        return await parseJsonSafely(retry);
      } else {
        throw new Error('Authentication failed. Please login again.');
      }
    }
    if (!res.ok) {
      console.error('❌ PATCH failed with status:', res.status);
      return await parseJsonSafely(res);
    }
    return await parseJsonSafely(res);
  };

  async function login(username, password){
    console.log('Attempting login with:', username, 'to API:', state.apiBase);
    const res = await fetch(`${state.apiBase}/auth/token/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
      credentials: 'omit'
    });
    console.log('Login response status:', res.status);
    if(!res.ok){
      let detail = 'Login failed';
      try { 
        const data = await parseJsonSafely(res); 
        detail = data?.detail || detail; 
        console.log('Login error data:', data); 
      } catch(_){ 
        try{ 
          detail = await res.text() || detail; 
          console.log('Login error text:', detail); 
        }catch(__){} 
      }
      throw new Error(`[${res.status}] ${detail}`);
    }
    const data = await parseJsonSafely(res);
    state.access = data.access; state.refresh = data.refresh;
    try {
      // Persist tokens for both this admin UI and any other frontend code expecting 'token'
      if (state.access) {
        localStorage.setItem('admin_access', state.access);
        try{ localStorage.setItem('token', state.access); } catch(_){}
      } else {
        localStorage.removeItem('admin_access');
        try{ localStorage.removeItem('token'); } catch(_){}
      }
      if (state.refresh) {
        localStorage.setItem('admin_refresh', state.refresh);
      } else {
        localStorage.removeItem('admin_refresh');
      }
    } catch {}
    setAuthStatus(true, 'Logged in ✓');
    toast('Logged in');
  }

  async function refreshToken(){
    if(!state.refresh) {
      console.log('No refresh token available');
      return false;
    }
    
    try {
      const res = await fetch(`${state.apiBase}/auth/token/refresh/`, {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh: state.refresh }),
        credentials: 'omit'
      });
      
      if (!res.ok) {
        console.log('Token refresh failed:', res.status, res.statusText);
        // Clear invalid tokens
        logout();
        toast('Session expired. Please login again.');
        return false;
      }
      
      const data = await parseJsonSafely(res);
      state.access = data.access;
      if (data.refresh) { 
        state.refresh = data.refresh; 
      }
      
      try {
        localStorage.setItem('admin_access', state.access || '');
        if (state.refresh) localStorage.setItem('admin_refresh', state.refresh);
      } catch(e) {
        console.error('Failed to save tokens to localStorage:', e);
      }
      
      console.log('Token refreshed successfully');
      setAuthStatus(true, 'Token refreshed ✓');
      return true;
    } catch (error) {
      console.error('Token refresh error:', error);
      logout();
      toast('Session expired. Please login again.');
      return false;
    }
  }

  function logout(){
    state.access = null; state.refresh = null;
    try { localStorage.removeItem('admin_access'); localStorage.removeItem('admin_refresh'); } catch {}
    setAuthStatus(false, 'Logged out');
    toast('Logged out');
  }

  async function validateStoredTokens(){
    console.log('🔍 Validating stored tokens...');
    if(!state.access){
      console.log('❌ No access token stored');
      return false;
    }
    
    try {
      const res = await fetch(`${state.apiBase}/accounts/me/`, {
        method: 'GET',
        headers: authHeaders(),
        credentials: 'omit'
      });
      
      console.log('📡 Validation response status:', res.status);
      
      if(res.status === 401 && state.refresh){
        console.log('🔄 Access token expired, attempting refresh...');
        const refreshSuccess = await refreshToken();
        if(refreshSuccess){
          console.log('✅ Token refreshed successfully');
          setAuthStatus(true, 'Tokens refreshed ✓');
          return true;
        } else {
          console.log('❌ Token refresh failed');
          return false;
        }
      }
      
      if(res.ok){
        console.log('✅ Tokens are valid');
        setAuthStatus(true, 'Authenticated ✓');
        return true;
      } else {
        console.log('❌ Token validation failed:', res.status);
        logout();
        return false;
      }
    } catch(error){
      console.error('❌ Error validating tokens:', error);
      return false;
    }
  }

  // Navigation
  $$('.nav-btn').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const id = btn.dataset.section;
      const headerTitle = $('#sectionTitle') || $('#pageTitle');
      if (headerTitle) headerTitle.textContent = btn.textContent;
      $$('.section').forEach(s => s.classList.remove('active'));
      $('#'+id).classList.add('active');
      // Auto-load when switching sections (only if logged in when admin endpoints)
      if(id==='users'){ loadUsers(); loadPendingUsers(); }
      if(id==='dashboard'){ loadDashboard(); }
      if(id==='deposits'){ if(state.access) loadDeposits(); else setStatus('Login required'); }
      if(id==='withdrawals'){ if(state.access) loadWithdrawals(); else setStatus('Login required'); }
      if(id==='referrals'){ if(state.access) loadReferrals(); else setStatus('Login required'); }
      if(id==='proofs'){ if(state.access) loadProofs(); else setStatus('Login required'); }
      if(id==='system'){ if(state.access) loadSystem(); else setStatus('Login required'); }
      if(id==='globalpool'){ if(state.access) loadGlobalPool(); else setStatus('Login required'); }
      if(id==='systemoverview'){ if(state.access) loadSystemOverview(); else setStatus('Login required'); }
      if(id==='products'){ if(state.access) loadProductsAndCategories(); else setStatus('Login required'); }
      if(id==='orders'){ if(state.access) loadOrders(); else setStatus('Login required'); }
    });
  });

  // Login bindings
  const loginBtn = $('#loginBtn');
  const loginForm = $('#loginForm');
  const usernameInput = $('#loginUsername');
  const passwordInput = $('#loginPassword');
  
  if (loginBtn) {
    loginBtn.addEventListener('click', async ()=>{
      // Handle logout if already logged in
      if(loginBtn.textContent === 'Logout'){
        logout();
        loginBtn.textContent = 'Login';
        return;
      }
      
      // Check if trying to login with credentials
      const u = usernameInput ? usernameInput.value.trim() : '';
      const p = passwordInput ? passwordInput.value : '';
      
      if(u && p){
        // Perform login
        try{
          await login(u,p);
          usernameInput.value = '';
          passwordInput.value = '';
          loginBtn.textContent = 'Logout';
          loadAllDashboardData();
        }catch(e){ handleApiError(e, 'login'); }
      }
    });
  }
  
  // Handle Enter key in login inputs
  if (usernameInput) {
    usernameInput.addEventListener('keypress', (e) => {
      if(e.key === 'Enter' && passwordInput) passwordInput.focus();
    });
  }
  if (passwordInput) {
    passwordInput.addEventListener('keypress', (e) => {
      if(e.key === 'Enter' && loginBtn) loginBtn.click();
    });
  }

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
      handleApiError(e, 'dashboard');
    }
  }

  async function loadAllDashboardData(){
    console.log('📊 Loading all dashboard data...');
    try {
      setStatus('Loading dashboard...');
      await loadDashboard();
      setStatus('Dashboard loaded ✓');
    } catch (e) {
      console.error('Error loading dashboard:', e);
      handleApiError(e, 'loadAllDashboardData');
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
            <td>${formatPkr(u.rewards_pkr||0)}</td>
            <td>${formatPkr(u.passive_income_pkr||0)}</td>
            <td>${formatPkr(u.current_balance_pkr||0)}</td>
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
      const pageInfoEl = $('#usersPageInfo');
      const prevEl = $('#usersPrev');
      const nextEl = $('#usersNext');
      if (pageInfoEl) pageInfoEl.textContent = `Page ${usersState.page} of ${totalPages} (${total} users)`;
      if (prevEl) prevEl.disabled = usersState.page <= 1;
      if (nextEl) nextEl.disabled = usersState.page >= totalPages;
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
    console.log('User table click detected:', e.target);
    const btn = e.target.closest('button');
    if(!btn) return;
    const id = btn.dataset.id;
    const action = btn.dataset.action;
    console.log('User action:', action, 'ID:', id, 'API Base:', state.apiBase);
    try{
      if(action === 'reject'){
        console.log('Attempting to reject user:', id);
        const response = await post(`${state.apiBase}/accounts/admin/reject/${id}/`);
        console.log('Reject response:', response);
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
    }catch(err){ 
      console.error('User action error:', err); 
      toast('Action failed: ' + (err.message || 'Unknown error')); 
    }
  });

  // Users (pending) list and actions
  async function loadPendingUsers(){
    const tbody = $('#pendingUsersTbody');
    tbody.innerHTML = '<tr><td colspan="6" class="muted">Loading...</td></tr>';
    try{
      const rows = await get(`${state.apiBase}/accounts/admin/pending-users/`);
      if(!rows.length){
        tbody.innerHTML = '<tr><td colspan="6" class="muted">No pending users</td></tr>';
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
            <button class="btn ok" data-action="approve" data-proof-id="${u.signup_proof_id || ''}" data-id="${u.id}">Approve</button>
            <button class="btn secondary" data-action="reject" data-proof-id="${u.signup_proof_id || ''}" data-id="${u.id}">Reject</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }catch(e){
      console.error(e); tbody.innerHTML = '<tr><td colspan="4" class="muted">Failed to load</td></tr>';
    }
  }

  $('#pendingUsersTbody').addEventListener('click', async (e)=>{
    console.log('Pending users table click detected:', e.target);
    const btn = e.target.closest('button');
    if(!btn) return;
    const id = btn.dataset.id; // user id
    const proofId = btn.dataset.proofId; // signup proof id
    const action = btn.dataset.action;
    console.log('Pending user action:', action, 'UserID:', id, 'ProofID:', proofId, 'API Base:', state.apiBase);
    try{
      if(action === 'approve'){
        if (proofId) {
          console.log('Approving via signup-proof action for proof:', proofId);
          await post(`${state.apiBase}/accounts/admin/signup-proof/action/${proofId}/`, { action: 'APPROVE' });
        } else {
          console.log('No proofId available; falling back to user approve:', id);
          await post(`${state.apiBase}/accounts/admin/approve/${id}/`);
        }
        toast('User approved');
      } else if(action === 'reject'){
        if (proofId) {
          console.log('Rejecting via signup-proof action for proof:', proofId);
          await post(`${state.apiBase}/accounts/admin/signup-proof/action/${proofId}/`, { action: 'REJECT' });
        } else {
          console.log('No proofId available; falling back to user reject:', id);
          await post(`${state.apiBase}/accounts/admin/reject/${id}/`);
        }
        toast('User rejected');
      }
      await loadPendingUsers();
      await loadUsers();
      await loadDashboard();
    }catch(err){ 
      console.error('Pending user action error:', err); 
      toast('Action failed: ' + (err.message || 'Unknown error')); 
    }
  });

  // Withdrawals - function moved below to avoid duplicates

  // Deposits
  async function loadDeposits(){
    const tbody = $('#depositsTbody');
    tbody.innerHTML = '<tr><td colspan="6" class="muted">Loading...</td></tr>';
    try{
      console.log('🔄 Loading deposits from:', `${state.apiBase}/wallets/admin/deposits/pending/`);
      const rows = await get(`${state.apiBase}/wallets/admin/deposits/pending/`);
      console.log('✅ Deposits data loaded:', rows);
      if(!rows.length){ tbody.innerHTML = '<tr><td colspan="6" class="muted">No pending</td></tr>'; return; }
      tbody.innerHTML = '';
      rows.forEach(d=>{
        const tr = document.createElement('tr');
        const proofUrl = d.proof_image || null;
        tr.innerHTML = `
          <td>${d.id}</td>
          <td>${escapeHtml(d.user?.username || '-')}</td>
          <td>${escapeHtml(d.user?.email || '-')}</td>
          <td>${escapeHtml(d.tx_id || '-')}</td>
          <td>${escapeHtml(d.bank_name || '-')}</td>
          <td>${escapeHtml(d.account_name || '-')}</td>
          <td>${proofUrl ? `<a href="${proofUrl}" target="_blank">View</a>` : '-'}</td>
          <td>${formatUsdToPkr(d.amount_usd)}</td>
          <td>${escapeHtml(d.created_at || '-')}</td>
          <td>
            <button class="btn" data-action="credit" data-id="${d.id}">Credit</button>
            <button class="btn secondary" data-action="reject" data-id="${d.id}">Reject</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }catch(e){ 
      console.error('❌ loadDeposits error:', e); 
      handleApiError(e, 'deposits');
      let errorHtml = `<tr><td colspan="6" class="muted">❌ Failed to load</td></tr>`;
      if (e.message.includes('Authentication')) {
        errorHtml = `<tr><td colspan="6" class="muted">❌ Not authenticated - use quickLogin()</td></tr>`;
      } else if (e.message.includes('endpoint not found')) {
        errorHtml = `<tr><td colspan="6" class="muted">❌ API endpoint not found</td></tr>`;
      }
      tbody.innerHTML = errorHtml; 
    }
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
    tbody.innerHTML = '<tr><td colspan="7" class="muted">Loading...</td></tr>';
    try{
      const rows = await get(`${state.apiBase}/marketplace/admin/products/`);
      if(!rows.length){ tbody.innerHTML = '<tr><td colspan="7" class="muted">No products</td></tr>'; return; }
      tbody.innerHTML = '';
      rows.forEach(p=>{
        const tr = document.createElement('tr');
        const imgHtml = p.image ? `<img src="${p.image}" alt="${escapeHtml(p.title)}" style="height: 50px; width: 50px; object-fit: cover; border-radius: 4px;">` : '<span class="muted">—</span>';
        tr.innerHTML = `
          <td>${imgHtml}</td>
          <td>${escapeHtml(p.title)}</td>
          <td>${formatPkr(p.price_pkr)}</td>
          <td>${formatPkr(p.advance_payment_discount)}</td>
          <td>${formatPkr(p.delivery_charges)}</td>
          <td>${escapeHtml(p.description||'')}</td>
          <td>${p.is_active ? 'Yes' : 'No'}</td>
          <td>
            <button class="btn" data-action="toggle" data-id="${p.id}">${p.is_active?'Disable':'Enable'}</button>
            <button class="btn" data-action="edit" data-id="${p.id}">Edit</button>
            <button class="btn secondary" data-action="delete" data-id="${p.id}" style="background-color: #dc2626; color: white;">Delete</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }catch(e){ console.error(e); tbody.innerHTML = '<tr><td colspan="7" class="muted">Failed to load</td></tr>'; }
  }

  async function loadProductsAndCategories(){
    await Promise.all([loadProducts(), loadCategories()]);
  }

  // Categories (admin)
  async function loadCategories(){
    try{
      const rows = await get(`${state.apiBase}/marketplace/admin/categories/`);
      const sel = $('#newProductCategory');
      const tbody = $('#categoriesTbody');
      if(sel){
        // clear select but keep the empty option
        const existingEmpty = sel.querySelector('option[value=""]');
        sel.innerHTML = existingEmpty ? existingEmpty.outerHTML : '<option value="">No category</option>';
      }
      if(!rows || !rows.length){
        if(tbody) tbody.innerHTML = '<tr><td colspan="2" class="muted">No categories</td></tr>';
        return;
      }
      if(tbody) tbody.innerHTML = '';
      rows.forEach(c=>{
        if(sel){
          const opt = document.createElement('option'); opt.value = c.id; opt.textContent = c.name;
          sel.appendChild(opt);
        }
        if(tbody){
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${escapeHtml(c.name)}</td><td>${c.is_active? 'Yes' : 'No'}</td>`;
          tbody.appendChild(tr);
        }
      });
    }catch(e){ console.error('loadCategories error', e); if($('#categoriesTbody')) $('#categoriesTbody').innerHTML = '<tr><td colspan="2" class="muted">Failed to load</td></tr>'; }
  }

  // Add category
  $('#addCategoryBtn')?.addEventListener('click', async (e)=>{
    e.preventDefault(); e.stopPropagation();
    const btn = e.currentTarget; if(btn.disabled) return; btn.disabled = true;
    try{
      const name = ($('#newCategoryName')?.value||'').trim();
      const desc = ($('#newCategoryDesc')?.value||'').trim();
      if(!name){ toast('Category name required'); return; }
      await post(`${state.apiBase}/marketplace/admin/categories/`, { name, description: desc });
      toast('Category created');
      $('#newCategoryName').value=''; $('#newCategoryDesc').value='';
      await loadCategories();
      await loadProducts();
    }catch(err){ console.error('Add category failed', err); toast('Add category failed'); }
    finally{ btn.disabled = false; }
  });

  // Orders
  async function loadOrders(){
    const tbody = $('#ordersTbody');
    if(!tbody) return;
    tbody.innerHTML = '<tr><td colspan="11" class="muted">Loading...</td></tr>';
    try{
      const statusSel = $('#ordersFilterStatus');
      const statusVal = statusSel ? statusSel.value : '';
      const url = statusVal ? `${state.apiBase}/marketplace/admin/orders/?status=${encodeURIComponent(statusVal)}` : `${state.apiBase}/marketplace/admin/orders/`;
      const rows = await get(url);
      if(!rows.length){ tbody.innerHTML = '<tr><td colspan="11" class="muted">No orders</td></tr>'; return; }
      tbody.innerHTML = '';
      rows.forEach(o=>{
        const tr = document.createElement('tr');
        const proofUrl = o.proof_image || null;
        tr.innerHTML = `
          <td>${o.id}</td>
          <td>${escapeHtml(o.product_title || '-')}</td>
          <td>${escapeHtml(o.buyer_username || '-')}</td>
          <td>${escapeHtml([o.guest_name, o.guest_email, o.guest_phone].filter(Boolean).join(' / ') || '-')}</td>
          <td>${escapeHtml(o.guest_address || '-')}</td>
          <td>${escapeHtml(o.tx_id || '-')}</td>
          <td>${formatPkr(o.total_pkr)}</td>
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
    }catch(e){ console.error(e); tbody.innerHTML = '<tr><td colspan="11" class="muted">Failed to load</td></tr>'; }
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
      const advanceDiscount = Number($('#newProductAdvanceDiscount')?.value||'0');
      const deliveryCharges = Number($('#newProductDeliveryCharges')?.value||'0');
      const description = ($('#newProductDesc')?.value||'').trim();
      const imageFiles = $('#newProductImage')?.files || [];
      const videoFile = $('#newProductVideo')?.files?.[0] || null;
      if(!title){ toast('Title is required'); return; }
      if(!description){ toast('Description is required'); return; }
      if(!(price>0)){ toast('Valid price (PKR) is required'); return; }
  const fd = new FormData();
      fd.append('title', title);
      fd.append('price_pkr', String(price));
      fd.append('advance_payment_discount', String(advanceDiscount));
      fd.append('delivery_charges', String(deliveryCharges));
      fd.append('description', description);
  const categoryId = $('#newProductCategory')?.value || '';
  if(categoryId) fd.append('category', categoryId);
      
      // Use the first image as the main image (legacy support)
      if(imageFiles.length > 0){ 
        fd.append('image_file', imageFiles[0]); 
        // Also append all images to image_files for the gallery
        for(let i=0; i<imageFiles.length; i++) {
          fd.append('image_files', imageFiles[i]);
        }
      }
      
      if(videoFile){ fd.append('video_file', videoFile); }
      setStatus('Working...');
      const headers = { ...authHeaders({}) };
      delete headers['Content-Type'];
      const res = await fetch(`${state.apiBase}/marketplace/admin/products/`, {
        method: 'POST',
        headers: headers,
        body: fd,
        credentials: 'omit'
      });
      setStatus('');
      if(!res.ok){ throw new Error(await res.text()); }
      toast('Product added');
      $('#newProductName').value=''; $('#newProductPrice').value=''; $('#newProductAdvanceDiscount').value=''; $('#newProductDeliveryCharges').value=''; $('#newProductDesc').value=''; if($('#newProductImage')) $('#newProductImage').value='';
      if($('#newProductVideo')) $('#newProductVideo').value='';
  if($('#newProductCategory')) $('#newProductCategory').value = '';
      await loadProducts();
    }catch(e){ console.error(e); toast('Add failed'); }
    finally{ btn.disabled = false; }
  });

  document.querySelector('#productsTbody')?.addEventListener('click', async (e)=>{
    const toggleBtn = e.target.closest('button[data-action="toggle"]');
    const deleteBtn = e.target.closest('button[data-action="delete"]');
    const editBtn = e.target.closest('button[data-action="edit"]');
    
    if(toggleBtn){
      toggleBtn.disabled = true;
      try{
        await patch(`${state.apiBase}/marketplace/admin/products/${toggleBtn.dataset.id}/toggle/`, {});
        toast('Product status updated');
        await loadProducts();
      }catch(err){ console.error(err); toast('Toggle failed'); }
      finally{ toggleBtn.disabled = false; }
    }
    else if(deleteBtn){
      if(!confirm('Are you sure you want to delete this product? This action cannot be undone.')) return;
      deleteBtn.disabled = true;
      try{
        await fetch(`${state.apiBase}/marketplace/admin/products/${deleteBtn.dataset.id}/delete/`, {
          method: 'DELETE',
          headers: authHeaders({})
        });
        toast('Product deleted successfully');
        await loadProducts();
      }catch(err){ console.error(err); toast('Delete failed'); }
      finally{ deleteBtn.disabled = false; }
    }
    else if(editBtn){
      const productId = editBtn.dataset.id;
      const products = await get(`${state.apiBase}/marketplace/admin/products/`);
      const product = products.find(p => p.id == productId);
      if(!product) { toast('Product not found'); return; }
      
      const newTitle = prompt('Edit product title:', product.title);
      if(newTitle === null) return;
      
      const newPrice = prompt('Edit price (PKR):', product.price_pkr);
      if(newPrice === null) return;
      
      const newAdvDiscount = prompt('Edit advance payment discount (PKR):', product.advance_payment_discount);
      if(newAdvDiscount === null) return;

      const newDelivery = prompt('Edit delivery charges (PKR):', product.delivery_charges);
      if(newDelivery === null) return;
      
      const newDesc = prompt('Edit description:', product.description);
      if(newDesc === null) return;
      
      editBtn.disabled = true;
      try{
        await patch(`${state.apiBase}/marketplace/admin/products/${productId}/`, {
          title: newTitle.trim(),
          price_pkr: parseFloat(newPrice),
          advance_payment_discount: parseFloat(newAdvDiscount),
          delivery_charges: parseFloat(newDelivery),
          description: newDesc.trim()
        });
        toast('Product updated successfully');
        await loadProducts();
      }catch(err){ console.error(err); toast('Edit failed'); }
      finally{ editBtn.disabled = false; }
    }
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
    tbody.innerHTML = '<tr><td colspan="9" class="muted">Loading...</td></tr>';
    try{
      console.log('🔄 Loading withdrawals from:', `${state.apiBase}/withdrawals/admin/pending/`);
      const rows = await get(`${state.apiBase}/withdrawals/admin/pending/`);
      console.log('✅ Withdrawals data loaded:', rows);
      if(!rows.length){ 
        tbody.innerHTML = '<tr><td colspan="9" class="muted">No pending withdrawals</td></tr>'; 
        return; 
      }
      tbody.innerHTML = '';
      rows.forEach(w=>{
        console.log('Processing withdrawal:', w.id, 'TX ID:', w.tx_id);
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${w.id}</td>
          <td>${escapeHtml(w.username || '-')}</td>
          <td>${escapeHtml(w.email || '-')}</td>
          <td>${escapeHtml(w.tx_id || '-')}</td>
          <td>${escapeHtml(w.bank_name || '-')}</td>
          <td>${escapeHtml(w.account_name || '-')}</td>
          <td>${escapeHtml(w.account_number || '-')}</td>
          <td>${formatUsdToPkr(w.amount_usd||0)}</td>
          <td>${escapeHtml(w.created_at || '-')}</td>
          <td>
            <button class="btn ok" data-action="approve" data-id="${w.id}">Approve</button>
            <button class="btn" data-action="paid" data-id="${w.id}">Mark Paid</button>
            <button class="btn secondary" data-action="reject" data-id="${w.id}">Reject</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }catch(e){ 
      console.error('❌ loadWithdrawals error:', e); 
      handleApiError(e, 'withdrawals');
      let errorHtml = `<tr><td colspan="9" class="muted">❌ Failed to load</td></tr>`;
      if (e.message.includes('Authentication')) {
        errorHtml = `<tr><td colspan="9" class="muted">❌ Not authenticated - use quickLogin()</td></tr>`;
      } else if (e.message.includes('endpoint not found')) {
        errorHtml = `<tr><td colspan="9" class="muted">❌ API endpoint not found</td></tr>`;
      }
      tbody.innerHTML = errorHtml; 
    }
  }

  $('#withdrawalsTbody').addEventListener('click', async (e)=>{
    const btn = e.target.closest('button'); 
    if(!btn) return; 
    const id = btn.dataset.id;
    const action = btn.dataset.action;
    try{
      let backendAction = action === 'approve' ? 'APPROVE' : action === 'reject' ? 'REJECT' : action === 'paid' ? 'PAID' : action.toUpperCase();
      await post(`${state.apiBase}/withdrawals/admin/action/${id}/`, { action: backendAction });
      toast(`Withdrawal ${action}d successfully`);
      await loadWithdrawals();
      await loadDashboard();
    }catch(err){ 
      console.error('Withdrawal action error:', err); 
      toast(`Failed to ${action} withdrawal`); 
    }
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
      $('#globalPoolBalance').textContent = formatUsdToPkr(data.pool_balance_usd || 0);
      $('#globalPayoutAmount').textContent = data.last_payout?.amount_usd ? formatUsdToPkr(data.last_payout.amount_usd) : '—';
      const tbody = $('#globalPoolUsersTbody');
      const rows = data.per_user_passive || [];
      tbody.innerHTML = rows.length ? '' : '<tr><td colspan="2" class="muted">No data</td></tr>';
      rows.forEach(r=>{
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${escapeHtml(r.username)}</td><td>${formatPkr(r.total_passive_pkr||0)}</td>`;
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



  const approveUsersBtn = $('#approveUsersBtn');
  if (approveUsersBtn) {
    approveUsersBtn.addEventListener('click', () => {
      const usersBtn = $$('.nav-btn').find(b => b.dataset.section === 'users');
      if (usersBtn) usersBtn.click();
    });
  }

  // Bind refresh buttons
  $('#refreshDeposits').addEventListener('click', loadDeposits);
  $('#refreshWithdrawals').addEventListener('click', loadWithdrawals);
  $('#refreshReferrals').addEventListener('click', loadReferrals);
  $('#refreshProofs').addEventListener('click', loadProofs);

  // Initial loads - REMOVED: These will be called after authentication is confirmed
  // The authentication flow will trigger these loads after successful login/token validation
  
  // Auto-initialization: Try to use stored tokens or auto-login
  (async () => {
    console.log('🚀 Admin UI initializing...');
    try {
      if (state.access) {
        console.log('📌 Found stored access token, validating...');
        const isValid = await validateStoredTokens();
        if (isValid) {
          console.log('✅ Stored tokens are valid');
          updateLoginUI();
          setTimeout(() => loadAllDashboardData(), 500);
        } else {
          console.log('⚠️ Stored tokens invalid, attempting auto-login...');
          await login('Ahmad', '12345');
          updateLoginUI();
          setTimeout(() => loadAllDashboardData(), 500);
        }
      } else {
        console.log('❌ No stored tokens, attempting auto-login with default credentials...');
        try {
          await login('Ahmad', '12345');
          updateLoginUI();
          setTimeout(() => loadAllDashboardData(), 500);
        } catch (e) {
          console.log('⚠️ Auto-login failed, waiting for manual login:', e.message);
          setAuthStatus(false, 'Please login to continue');
        }
      }
    } catch (error) {
      console.error('❌ Initialization error:', error);
    }
  })();
  
  function updateLoginUI() {
    const loginBtn = $('#loginBtn');
    if (loginBtn) loginBtn.textContent = 'Logout';
  }
})();