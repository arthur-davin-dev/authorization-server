// Keep the SPA, login session and callback on one browser origin. In particular,
// localhost and 127.0.0.1 have separate sessionStorage and cookies.
const authorizationServer = window.location.origin;
const clientId = "authorization-spa";
const redirectUri = `${window.location.origin}/`;
const scopes = "openid profile api.read";

const result = document.querySelector("#result");
const loginButton = document.querySelector("#login");
const logoutButton = document.querySelector("#logout");
const badVerifierCheckbox = document.querySelector("#bad-verifier");

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function randomUrlSafeValue(byteLength) {
  const value = crypto.getRandomValues(new Uint8Array(byteLength));
  return base64Url(value);
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64Url(new Uint8Array(digest));
}

async function beginLogin() {
  const verifier = randomUrlSafeValue(32);
  const challenge = await sha256Base64Url(verifier);
  const state = randomUrlSafeValue(24);
  sessionStorage.setItem("pkce_verifier", verifier);
  sessionStorage.setItem("oauth_state", state);
  sessionStorage.setItem("pkce_bad_verifier", badVerifierCheckbox.checked ? "true" : "false");

  const authorizationUrl = new URL("/oauth2/authorize", authorizationServer);
  authorizationUrl.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });
  window.location.assign(authorizationUrl);
}

async function exchangeCode() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  if (!code) {
    return;
  }
  const returnedState = params.get("state");
  const expectedState = sessionStorage.getItem("oauth_state");
  const verifier = sessionStorage.getItem("pkce_verifier");
  if (!returnedState || returnedState !== expectedState || !verifier) {
    window.history.replaceState({}, document.title, "/");
    throw new Error(
      "OAuth callback could not find the state and PKCE verifier for this browser origin. " +
      "Open the SPA and start login from the same address (for example, always use " +
      "http://127.0.0.1:9000 or always use http://localhost:9000)."
    );
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code,
    code_verifier: sessionStorage.getItem("pkce_bad_verifier") === "true" ? `${verifier}x` : verifier
  });
  const tokenResponse = await fetch(`${authorizationServer}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const tokenData = await tokenResponse.json();
  if (!tokenResponse.ok) {
    throw new Error(`Token exchange failed (${tokenResponse.status}): ${JSON.stringify(tokenData)}`);
  }
  sessionStorage.removeItem("pkce_verifier");
  sessionStorage.removeItem("oauth_state");
  sessionStorage.removeItem("pkce_bad_verifier");
  window.history.replaceState({}, document.title, "/");

  const claims = JSON.parse(atob(tokenData.access_token.split(".")[1].replaceAll("-", "+").replaceAll("_", "/")));
  const privateResponse = await fetch(`${authorizationServer}/api/private/hello`, {
    headers: { Authorization: `Bearer ${tokenData.access_token}` }
  });
  const scopedResponse = await fetch(`${authorizationServer}/api/scoped/hello`, {
    headers: { Authorization: `Bearer ${tokenData.access_token}` }
  });
  const adminResponse = await fetch(`${authorizationServer}/api/admin/hello`, {
    headers: { Authorization: `Bearer ${tokenData.access_token}` }
  });
  const privateBody = await privateResponse.json();
  const scopedBody = await scopedResponse.json();
  result.textContent = JSON.stringify({
    token_type: tokenData.token_type,
    expires_in: tokenData.expires_in,
    jwt_claims: { sub: claims.sub, iss: claims.iss, scope: claims.scope, roles: claims.roles, exp: claims.exp },
    private_api: { status: privateResponse.status, body: privateBody },
    scope_api: { status: scopedResponse.status, body: scopedBody },
    admin_api_status_for_regular_user: adminResponse.status
  }, null, 2);
  loginButton.hidden = true;
  logoutButton.hidden = false;
}

loginButton.addEventListener("click", () => beginLogin().catch(error => {
  result.textContent = error.message;
}));
logoutButton.addEventListener("click", () => {
  sessionStorage.clear();
  window.location.assign("/");
});

exchangeCode().catch(error => {
  result.textContent = error.message;
});
