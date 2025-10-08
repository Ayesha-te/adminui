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
    'https://ref-backend-fw8y.onrender.com/api'; // Force production backend
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
        if (typeof loadDashboard === 'function') loadDashboard();
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
    access: (typeof localStorage !== 'undefined' && localStorage.getItem('admin_access')) || null,
    refresh: (typeof localStorage !== 'undefined' && localStorage.getItem('admin_refresh')) || null,
  };

  const toast = (msg) => {
    const el = $('#toast');
    el.textContent = msg;
    el.style.display = 'block';
    setTimeout(()=>{ el.style.display = 'none'; }, 2000);
  };

  // Global functions for debugging
  window.setApiBase = function(url) {
    state.apiBase = normalizeApiBase(url);
    try{ localStorage.setItem('adminApiBase', state.apiBase); }catch(_){ }
    console.log('API Base manually set to:', state.apiBase);
    toast('API Base updated to: ' + state.apiBase);
  };

  // Convenience helpers for local/prod switching
  window.useLocalApi = function(port=8000){
    const base = `http://localhost:${port}/api`;
    window.setApiBase(base);
    return base;
  };
  window.useProdApi = function(){
    const base = 'https://ref-backend-fw8y.onrender.com/api';
    window.setApiBase(base);
    return base;
  };
  
  window.getApiBase = function() {
    console.log('Current API Base:', state.apiBase);
    return state.apiBase;
  };
  
  window.testApi = async function() {
    try {
      const response = await fetch(`${state.apiBase}/auth/token/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: '__probe__', password: '__probe__' })
      });
      console.log('API Test Result:', response.status, response.statusText, '->', state.apiBase);
      toast(`API ${response.status} @ ${state.apiBase}`);
      return response.status;
    } catch (e) {
      console.error('API Test Failed:', e);
      toast('API test failed');
      return false;
    }
  };

  // Quick UI bindings for switching API base
  document.addEventListener('DOMContentLoaded', ()=>{
    const toLocal = document.getElementById('switchToLocal');
    const toProd = document.getElementById('switchToProd');
    if (toLocal) toLocal.addEventListener('click', ()=>{ window.useLocalApi(); window.testApi(); });
    if (toProd) toProd.addEventListener('click', ()=>{ window.useProdApi(); window.testApi(); });
  });

  console.log('Admin UI Debug Commands:');
  console.log('- setApiBase("http://192.168.100.141:8000/api") - Set API base manually');
  console.log('- getApiBase() - Get current API base');
  console.log('- testApi() - Test API connection');

  // Render current API base (no longer shown in UI)
  function showApiBase(){}

  async function detectApiBase(){
    // Prioritize production backend, then local development
    const productionBackend = 'https://ref-backend-fw8y.onrender.com/api';
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

  // Initialize API base automatically without UI controls
  (async ()=>{
    // Respect stored API base if present (do not override every load)
    let storedBase = null;
    try { storedBase = localStorage.getItem('adminApiBase'); } catch(_){ }
    if (storedBase) {
      state.apiBase = normalizeApiBase(storedBase);
      console.log('Using stored API base:', state.apiBase);
      showApiBase();
      // Validate tokens shortly after
      setTimeout(async ()=>{ if (state.access || state.refresh) await validateStoredTokens(); }, 500);
      return;
    }

    // Check if we're running in production (Vercel) - don't try localhost
    const isProduction = window.location.hostname.includes('vercel.app') || 
                        window.location.hostname.includes('netlify.app') ||
                        window.location.protocol === 'https:';
    
    // Try local development first when not production
    const productionBase = 'https://ref-backend-fw8y.onrender.com/api';

    if (!isProduction) {
      const localCandidates = [
        'http://127.0.0.1:8000/api',
        'http://localhost:8000/api',
        location.origin.replace(/:\d+$/, '') + ':8000/api'
      ];
      for (const localBase of localCandidates) {
        try {
          console.log('Testing local backend:', localBase);
          const testResponse = await fetch(`${localBase}/auth/token/`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: '__probe__', password: '__probe__' })
          });
          if ([400, 401].includes(testResponse.status)) {
            state.apiBase = localBase;
            try{ localStorage.setItem('adminApiBase', localBase); }catch(_){ }
            console.log('✅ Admin UI connected to LOCAL backend:', localBase);
            showApiBase();
            return;
          }
        } catch (e) {
          console.log(`Local server ${localBase} not available:`, e.message);
        }
      }
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
        return;
      }
      console.log('Production backend not available.');
    }
    

    
    // Immediate authentication check
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
            if (typeof loadDashboard === 'function') loadDashboard();
          }, 500);
        } catch (error) {
          console.log('❌ Auto-login failed:', error.message);
          setAuthStatus(false, 'Auto-login failed - use quickLogin()');
          toast('❌ Auto-login failed. Try: quickLogin()');
        }
      }, 100);
    }
  })();

  const setStatus = (msg) => $('#status').textContent = msg || '';
  
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
      if (text.includes('<!DOCTYPE') || text.includes('<html>')) {
        throw new Error('Server returned HTML instead of JSON. This usually indicates an authentication or server error.');
      }
      throw new Error(`Expected JSON response but got: ${contentType || 'unknown content type'}`);
    }
  };

  function authHeaders(headers={}){
    // Ensure we always start with proper headers
    const baseHeaders = {
      'Content-Type': 'application/json',
      ...headers
    };
    
    if(state.access && state.access.trim()){ 
      baseHeaders['Authorization'] = `Bearer ${state.access}`;
      console.log('🔑 Adding Authorization header with token:', state.access.substring(0, 20) + '...');
      console.log('🔍 Full headers being sent:', baseHeaders);
    } else {
      console.log('❌ No access token available for Authorization header');
      console.log('🔍 Token in state:', state.access ? 'exists' : 'missing');
      console.log('🔍 Token in localStorage:', localStorage.getItem('admin_access') ? 'exists' : 'missing');
    }
    return baseHeaders;
  }

  const get = async (url) => {
    console.log('🌐 GET request to:', url);
    console.log('🔍 Current API base:', state.apiBase);
    console.log('🔍 Current access token:', state.access ? `${state.access.substring(0, 20)}...` : 'null');
    
    setStatus('Loading...');
    const headers = authHeaders();
    console.log('🔍 Request headers:', headers);
    
    const res = await fetch(url, { 
      headers,
      credentials: 'omit',
      method: 'GET'
    });
    
    console.log('📡 Response status:', res.status);
    console.log('📡 Response headers:', Object.fromEntries(res.headers.entries()));
    
    setStatus('');
    if (res.status === 401 && state.refresh) {
      console.log('🔄 Attempting token refresh...');
      // attempt refresh and retry once
      const refreshSuccess = await refreshToken();
      if (refreshSuccess) {
        console.log('✅ Token refresh successful, retrying request...');
        const retryHeaders = authHeaders();
        const retry = await fetch(url, { 
          headers: retryHeaders, 
          credentials: 'omit',
          method: 'GET'
        });
        if(!retry.ok) {
          const errorText = await retry.text();
          throw new Error(`HTTP ${retry.status}: ${errorText}`);
        }
        return await parseJsonSafely(retry);
      } else {
        console.log('❌ Token refresh failed');
        throw new Error('Authentication failed. Please login again.');
      }
    }
    if (!res.ok) {
      const errorText = await res.text();
      console.log('❌ Request failed:', res.status, errorText);
      throw new Error(`HTTP ${res.status}: ${errorText}`);
    }
    return await parseJsonSafely(res);
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
      const refreshSuccess = await refreshToken();
      if (refreshSuccess) {
        const retry = await fetch(url, {
          method: 'POST',
          headers: authHeaders({ 'Content-Type': 'application/json' }),
          credentials: 'omit',
          body: JSON.stringify(body||{})
        });
        if(!retry.ok) {
          const errorText = await retry.text();
          throw new Error(`HTTP ${retry.status}: ${errorText}`);
        }
        return await parseJsonSafely(retry);
      } else {
        throw new Error('Authentication failed. Please login again.');
      }
    }
    if (!res.ok) {
      const errorText = await res.text();
      throw new Error(`HTTP ${res.status}: ${errorText}`);
    }
    return await parseJsonSafely(res);
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
      const refreshSuccess = await refreshToken();
      if (refreshSuccess) {
        const retry = await fetch(url, {
          method: 'PATCH',
          headers: authHeaders({ 'Content-Type': 'application/json' }),
          credentials: 'omit',
          body: JSON.stringify(body||{})
        });
        if(!retry.ok) {
          const errorText = await retry.text();
          throw new Error(`HTTP ${retry.status}: ${errorText}`);
        }
        return await parseJsonSafely(retry);
      } else {
        throw new Error('Authentication failed. Please login again.');
      }
    }
    if (!res.ok) {
      const errorText = await res.text();
      throw new Error(`HTTP ${res.status}: ${errorText}`);
    }
    return await parseJsonSafely(res);
  };

  async function login(username, password){
    console.log('Attempting login with:', username, 'to API:', state.apiBase);
    const res = await fetch(`${state.apiBase}/auth/token/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
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
      localStorage.setItem('admin_access', state.access || '');
      localStorage.setItem('admin_refresh', state.refresh || '');
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
        body: JSON.stringify({ refresh: state.refresh })
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

  // Validate stored tokens on app load
  async function validateStoredTokens() {
    if (!state.access) return false;
    
    try {
      // Test the access token with a simple API call
      const res = await fetch(`${state.apiBase}/accounts/admin/users/?page=1&page_size=1`, {
        headers: authHeaders(),
        credentials: 'omit'
      });
      
      if (res.ok) {
        console.log('Stored access token is valid');
        setAuthStatus(true, 'Token validated ✓');
        return true;
      } else if (res.status === 401 && state.refresh) {
        console.log('Access token expired, attempting refresh...');
        setAuthStatus(false, 'Token expired, refreshing...');
        return await refreshToken();
      } else {
        console.log('Token validation failed, clearing tokens');
        setAuthStatus(false, 'Token invalid');
        logout();
        return false;
      }
    } catch (error) {
      console.error('Token validation error:', error);
      setAuthStatus(false, 'Connection error');
      logout();
      return false;
    }
  }

  // Debug helper function - call from browser console
  window.debugAuth = function() {
    console.log('=== AUTHENTICATION DEBUG INFO ===');
    console.log('API Base:', state.apiBase);
    console.log('Access Token:', state.access ? state.access.substring(0, 50) + '...' : 'None');
    console.log('Refresh Token:', state.refresh ? state.refresh.substring(0, 50) + '...' : 'None');
    console.log('LocalStorage Access:', localStorage.getItem('admin_access') ? 'Present' : 'Missing');
    console.log('LocalStorage Refresh:', localStorage.getItem('admin_refresh') ? 'Present' : 'Missing');
    
    // Test a simple API call
    if (state.access) {
      console.log('Testing API call...');
      fetch(`${state.apiBase}/accounts/admin/users/?page=1&page_size=1`, {
        headers: authHeaders(),
        credentials: 'omit'
      }).then(res => {
        console.log('Test API Response Status:', res.status);
        if (res.status === 401) {
          console.log('❌ 401 Unauthorized - Token is invalid or expired');
        } else if (res.status === 403) {
          console.log('❌ 403 Forbidden - User lacks admin permissions');
        } else if (res.ok) {
          console.log('✅ API call successful - Authentication working');
        } else {
          console.log('⚠️ Unexpected status:', res.status);
        }
      }).catch(err => {
        console.log('❌ Network error:', err.message);
      });
    } else {
      console.log('❌ No access token available');
    }
    console.log('=====================================');
  };

  // Enhanced error handling for API responses
  function handleApiError(error, url) {
    console.error('API Error:', error);
    
    // Check for HTML response errors (the main issue we're fixing)
    if (error.message.includes('Server returned HTML instead of JSON')) {
      setAuthStatus(false, 'Auth failed');
      toast('❌ Authentication error. Please login again.');
      setStatus('Server returned HTML error page - likely authentication issue');
      logout();
      return;
    }
    
    // Check for HTTP 401 errors
    if (error.message.includes('HTTP 401')) {
      setAuthStatus(false, 'Unauthorized');
      toast('❌ Unauthorized. Please login again.');
      setStatus('401 Unauthorized - invalid or missing credentials');
      logout();
      return;
    }
    
    // Check for CORS errors
    if (error.message.includes('Failed to fetch') || error.name === 'TypeError') {
      setAuthStatus(false, 'Connection failed');
      toast('❌ Connection failed. Check if backend is running and CORS is configured.');
      setStatus('CORS or network error - check backend configuration');
      return;
    }
    
    if (error.message.includes('Authentication failed')) {
      setAuthStatus(false, 'Auth failed');
      toast('Please login again');
      return;
    }
    
    // Check for specific admin permission errors
    if (url.includes('/admin/') && error.message.includes('permission')) {
      toast('Admin access required. Check your user role.');
      setAuthStatus(false, 'No admin access');
      return;
    }
    
    // Check for token-related errors
    if (error.message.includes('Invalid token') || error.message.includes('Token has expired')) {
      setAuthStatus(false, 'Token invalid');
      toast('Session expired. Please login again.');
      logout();
      return;
    }
    
    // Generic error handling
    toast(`Error: ${error.message}`);
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
  const loginBtn = $('#loginBtn');
  const loginForm = $('#loginForm');
  const usernameInput = $('#username');
  const passwordInput = $('#password');
  const doLoginBtn = $('#doLogin');
  
  if (loginBtn) {
    loginBtn.addEventListener('click', ()=>{
      // Handle logout if already logged in
      if(loginBtn.textContent === 'Logout'){
        logout();
        loginBtn.textContent = 'Login';
        if (loginForm) loginForm.style.display = 'none';
        return;
      }
      
      // Show/hide login form
      if(loginForm){
        if(loginForm.style.display === 'none'){
          loginForm.style.display = 'flex';
          loginBtn.textContent = 'Cancel';
          if (usernameInput) usernameInput.focus();
        } else {
          loginForm.style.display = 'none';
          loginBtn.textContent = 'Login';
        }
      }
    });
  }
  
  if (doLoginBtn) {
    doLoginBtn.addEventListener('click', async ()=>{
      try{
        const u = usernameInput ? usernameInput.value.trim() : '';
        const p = passwordInput ? passwordInput.value : '';
        if(!u||!p){ toast('Enter username and password'); return; }
        await login(u,p);
        if (loginForm) loginForm.style.display = 'none';
        if (loginBtn) loginBtn.textContent = 'Logout';
        // On login, refresh all sections
        loadDashboard(); loadUsers(); loadPendingUsers(); loadDeposits(); loadWithdrawals(); loadReferrals(); loadProofs(); loadProducts(); loadGlobalPool(); loadSystemOverview();
      }catch(e){ handleApiError(e, 'login'); }
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
      if(e.key === 'Enter' && doLoginBtn) doLoginBtn.click();
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
          const response = await post(`${state.apiBase}/accounts/admin/reject/${id}/`);
          console.log('Reject response (fallback):', response);
        }
        toast('User rejected');
      }
      await loadPendingUsers();
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
    tbody.innerHTML = '<tr><td colspan="9" class="muted">Loading...</td></tr>';
    try{
      const rows = await get(`${state.apiBase}/withdrawals/admin/pending/`);
      console.log('Withdrawals data loaded:', rows);
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
          <td>$${Number(w.amount_usd||0).toFixed(2)}</td>
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
      console.error('loadWithdrawals error:', e); 
      handleApiError(e, `${state.apiBase}/withdrawals/admin/pending/`);
      tbody.innerHTML = '<tr><td colspan="9" class="muted">❌ Failed to load - Check connection</td></tr>'; 
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