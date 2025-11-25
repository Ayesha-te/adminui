# Testing the Admin Panel Authentication Fix

## Quick Test (Recommended)

### Option 1: Open Directly in Browser
1. Navigate to the adminui folder
2. Right-click `index.html` → Open with → Your browser
3. Open DevTools (F12) → Console tab
4. Watch for these logs:
   ```
   🔍 Checking authentication state...
   ❌ No stored tokens found, attempting auto-login...
   ✅ Auto-login successful
   📊 Loading all dashboard data...
   ✅ Dashboard data loading initiated
   ```
5. Check Network tab - should see successful API calls (200 status)
6. No 401 errors should appear

### Option 2: Use Local Server (Better for CORS)
```powershell
# Navigate to adminui folder
Set-Location "c:\Users\Ayesha Jahangir\Downloads\nexocart-redline-dash\ref_backend\adminui"

# Option A: Python (if installed)
python -m http.server 3000

# Option B: Node.js (if installed)
npx http-server -p 3000

# Option C: PHP (if installed)
php -S localhost:3000
```

Then open: http://localhost:3000

## Detailed Testing Steps

### 1. Test Auto-Login
1. Clear browser localStorage: `localStorage.clear()`
2. Refresh page
3. Should see auto-login attempt in console
4. Dashboard should load automatically

### 2. Test Token Validation
1. Login successfully (auto or manual)
2. Refresh page
3. Should see "Found stored tokens, validating..."
4. Dashboard should load without new login

### 3. Test Manual Login
1. Open browser console
2. Run: `quickLogin()`
3. Should see success message
4. Dashboard should load

### 4. Test API Calls
1. Click different sections (Users, Deposits, Withdrawals, etc.)
2. Each should load data without 401 errors
3. Check Network tab for Authorization headers

### 5. Test Token Refresh
1. Wait for token to expire (30 minutes) OR
2. Manually expire token: `state.access = 'invalid_token'`
3. Click any section
4. Should automatically refresh token and retry

## Expected Console Output

### Successful Flow
```
🔧 DEBUG: Forced API base to: https://ref-backend-fw8y.onrender.com/api
Using stored API base: https://ref-backend-fw8y.onrender.com/api
🔍 Checking authentication state...
🔍 Access token exists: false
🔍 Refresh token exists: false
❌ No stored tokens found, attempting auto-login...
🚀 Logging in as: Ahmad
✅ Auto-login successful
✅ Auto-login successful!
📊 Loading all dashboard data...
🔑 Adding Authorization header with token: eyJ0eXAiOiJKV1QiLCJh...
✅ Dashboard data loading initiated
```

### Failed Authentication (Should Not Happen)
```
❌ Auto-login failed: HTTP 401: {"detail":"Invalid credentials"}
```

## Troubleshooting

### Issue: Still Getting 401 Errors
**Solution:**
1. Check if backend is running: https://ref-backend-fw8y.onrender.com/api/
2. Run `debugAuth()` in console to check token state
3. Try manual login: `quickLogin()`
4. Check Network tab for Authorization header in requests

### Issue: Auto-Login Fails
**Solution:**
1. Verify credentials are correct (Ahmad/12345)
2. Check backend user exists and is_staff=True
3. Check CORS configuration on backend
4. Try manual API test: `testApi()`

### Issue: CORS Errors
**Solution:**
1. Use local server instead of file:// protocol
2. Check backend CORS_ALLOWED_ORIGINS includes your origin
3. Verify backend is accessible

### Issue: No Logs Appearing
**Solution:**
1. Make sure DevTools Console is open
2. Check Console filter settings (should show all logs)
3. Refresh page with DevTools open

## Debug Commands

Run these in browser console:

```javascript
// Check authentication state
debugAuth()

// Manual login
quickLogin()

// Check API base
getApiBase()

// Test API connection
testApi()

// Switch to local backend (if running)
useLocalApi(8000)

// Switch to production backend
useProdApi()

// Clear tokens and retry
localStorage.clear()
location.reload()
```

## Success Criteria

✅ No 401 errors in console or Network tab
✅ Auto-login succeeds automatically
✅ All dashboard sections load data
✅ Authorization headers present in all admin API calls
✅ Token refresh works on expiration
✅ Manual login works via quickLogin()

## Common Issues Fixed

### Before Fix
- ❌ 401 errors on all admin endpoints
- ❌ Authentication check never ran
- ❌ Dashboard sections showed "Failed to load"
- ❌ No Authorization headers in requests

### After Fix
- ✅ Auto-login runs on page load
- ✅ Tokens validated before API calls
- ✅ Dashboard loads automatically
- ✅ Authorization headers included in all requests

## Backend Verification

If you have access to backend logs, verify:
1. Login requests succeed: `POST /api/auth/token/`
2. Admin endpoints return 200: `GET /api/accounts/admin/pending-users/`
3. Authorization headers are received
4. User has `is_staff=True` and `is_active=True`

## Next Steps After Testing

1. ✅ Verify fix works locally
2. ✅ Test on deployed admin UI (Vercel)
3. ✅ Monitor for any remaining 401 errors
4. ✅ Consider removing auto-login for production
5. ✅ Add proper login UI if needed