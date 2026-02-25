/* ── MayaTrail Authentication Module ── */

(function() {
  'use strict';

  const AUTH_KEY = 'mayatrail_auth';
  const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

  // Demo credentials
  const DEMO_USERS = [
    { username: 'admin@mayatrail.tech', password: 'mayatrail', name: 'Ayush Pathak', initials: 'AP' },
    { username: 'admin', password: 'admin', name: 'Admin User', initials: 'AU' },
    { username: 'demo', password: 'demo', name: 'Demo User', initials: 'DU' }
  ];

  function getSession() {
    try {
      var data = localStorage.getItem(AUTH_KEY);
      if (!data) return null;
      var session = JSON.parse(data);
      if (Date.now() > session.expires) {
        localStorage.removeItem(AUTH_KEY);
        return null;
      }
      return session;
    } catch (e) {
      return null;
    }
  }

  function createSession(user) {
    var session = {
      username: user.username,
      name: user.name,
      initials: user.initials,
      loginTime: Date.now(),
      expires: Date.now() + SESSION_DURATION,
      method: user.method || 'credentials'
    };
    localStorage.setItem(AUTH_KEY, JSON.stringify(session));
    return session;
  }

  function checkAuth() {
    var session = getSession();
    // If on login page and already authenticated, redirect to app
    if (window.location.pathname.indexOf('login.html') !== -1 ||
        window.location.pathname.endsWith('/')) {
      if (session) {
        window.location.href = 'app.html';
        return true;
      }
      return false;
    }
    // If on app page and not authenticated, redirect to login
    if (!session) {
      window.location.href = 'login.html';
      return false;
    }
    return true;
  }

  var REGISTERED_KEY = 'mayatrail_users';

  function getRegisteredUsers() {
    try {
      var data = localStorage.getItem(REGISTERED_KEY);
      return data ? JSON.parse(data) : [];
    } catch (e) {
      return [];
    }
  }

  function saveRegisteredUsers(users) {
    localStorage.setItem(REGISTERED_KEY, JSON.stringify(users));
  }

  function generateInitials(name) {
    var parts = name.trim().split(/\s+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    }
    return name.substring(0, 2).toUpperCase();
  }

  function signup(name, email, password) {
    name = name.trim();
    email = email.trim().toLowerCase();

    if (!name || !email || !password) {
      return { success: false, error: 'All fields are required' };
    }
    if (password.length < 6) {
      return { success: false, error: 'Password must be at least 6 characters' };
    }

    // Check against demo users
    for (var i = 0; i < DEMO_USERS.length; i++) {
      if (DEMO_USERS[i].username === email) {
        return { success: false, error: 'An account with this email already exists' };
      }
    }

    // Check against registered users
    var registered = getRegisteredUsers();
    for (var j = 0; j < registered.length; j++) {
      if (registered[j].username === email) {
        return { success: false, error: 'An account with this email already exists' };
      }
    }

    var user = {
      username: email,
      password: password,
      name: name,
      initials: generateInitials(name)
    };

    registered.push(user);
    saveRegisteredUsers(registered);

    // Auto-login after signup
    user.method = 'credentials';
    createSession(user);
    return { success: true };
  }

  function login(username, password) {
    var user = null;
    // Check demo users
    for (var i = 0; i < DEMO_USERS.length; i++) {
      if (DEMO_USERS[i].username === username && DEMO_USERS[i].password === password) {
        user = DEMO_USERS[i];
        break;
      }
    }
    // Check registered users
    if (!user) {
      var registered = getRegisteredUsers();
      for (var j = 0; j < registered.length; j++) {
        if (registered[j].username === username && registered[j].password === password) {
          user = registered[j];
          break;
        }
      }
    }
    if (!user) {
      return { success: false, error: 'Invalid username or password' };
    }
    user.method = 'credentials';
    createSession(user);
    return { success: true };
  }

  function googleSSO() {
    // Mock Google SSO - in production this would redirect to Google OAuth
    var user = {
      username: 'admin@mayatrail.tech',
      name: 'Ayush Pathak',
      initials: 'AP',
      method: 'google_sso'
    };
    createSession(user);
    return { success: true };
  }

  function logout() {
    localStorage.removeItem(AUTH_KEY);
    window.location.href = 'login.html';
  }

  // Expose to global scope
  window.MayaTrailAuth = {
    checkAuth: checkAuth,
    login: login,
    signup: signup,
    googleSSO: googleSSO,
    logout: logout,
    getSession: getSession
  };
})();

/* ── Login Page Handlers ── */
function handleLogin(event) {
  event.preventDefault();
  var username = document.getElementById('username').value.trim();
  var password = document.getElementById('password').value;
  var errorEl = document.getElementById('loginError');
  var btn = document.getElementById('loginBtn');

  // Clear previous error
  errorEl.classList.remove('visible');
  errorEl.textContent = '';

  if (!username || !password) {
    errorEl.textContent = 'Please enter both username and password';
    errorEl.classList.add('visible');
    return false;
  }

  // Show loading
  btn.classList.add('loading');
  btn.disabled = true;

  // Simulate network delay
  setTimeout(function() {
    var result = window.MayaTrailAuth.login(username, password);
    if (result.success) {
      window.location.href = 'app.html';
    } else {
      errorEl.textContent = result.error;
      errorEl.classList.add('visible');
      btn.classList.remove('loading');
      btn.disabled = false;
    }
  }, 800);

  return false;
}

function handleSignup(event) {
  event.preventDefault();
  var name = document.getElementById('signupName').value.trim();
  var email = document.getElementById('signupEmail').value.trim();
  var password = document.getElementById('signupPassword').value;
  var confirm = document.getElementById('signupConfirm').value;
  var errorEl = document.getElementById('signupError');
  var btn = document.getElementById('signupBtn');

  errorEl.classList.remove('visible');
  errorEl.textContent = '';

  if (!name || !email || !password || !confirm) {
    errorEl.textContent = 'Please fill in all fields';
    errorEl.classList.add('visible');
    return false;
  }

  if (password !== confirm) {
    errorEl.textContent = 'Passwords do not match';
    errorEl.classList.add('visible');
    return false;
  }

  btn.classList.add('loading');
  btn.disabled = true;

  setTimeout(function() {
    var result = window.MayaTrailAuth.signup(name, email, password);
    if (result.success) {
      window.location.href = 'app.html';
    } else {
      errorEl.textContent = result.error;
      errorEl.classList.add('visible');
      btn.classList.remove('loading');
      btn.disabled = false;
    }
  }, 800);

  return false;
}

function switchAuthTab(tab) {
  var signinTab = document.getElementById('tabSignin');
  var signupTab = document.getElementById('tabSignup');
  var loginForm = document.getElementById('loginForm');
  var signupForm = document.getElementById('signupForm');

  if (tab === 'signup') {
    signinTab.classList.remove('active');
    signupTab.classList.add('active');
    loginForm.style.display = 'none';
    signupForm.style.display = 'flex';
  } else {
    signupTab.classList.remove('active');
    signinTab.classList.add('active');
    signupForm.style.display = 'none';
    loginForm.style.display = 'flex';
  }

  // Clear errors on tab switch
  var loginErr = document.getElementById('loginError');
  var signupErr = document.getElementById('signupError');
  if (loginErr) { loginErr.classList.remove('visible'); loginErr.textContent = ''; }
  if (signupErr) { signupErr.classList.remove('visible'); signupErr.textContent = ''; }
}

function handleGoogleSSO() {
  var result = window.MayaTrailAuth.googleSSO();
  if (result.success) {
    window.location.href = 'app.html';
  }
}
