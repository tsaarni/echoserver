// Generate PKCE code verifier.
function generateCodeVerifier() {
  const array = new Uint8Array(64);
  window.crypto.getRandomValues(array);
  return base64URLEncode(array);
}

// Generate PKCE code challenge.
async function generateCodeChallenge(codeVerifier) {
  const buffer = new TextEncoder().encode(codeVerifier);
  const hash = await window.crypto.subtle.digest('SHA-256', buffer);
  return base64URLEncode(hash);
}

// URL-safe base64 URL encode.
function base64URLEncode(input) {
  let buffer;
  if (typeof input === 'string') {
    buffer = new TextEncoder().encode(input);
  } else {
    buffer = input;
  }
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export { generateCodeVerifier, generateCodeChallenge };
