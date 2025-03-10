async function generateDpopProof(httpMethod, httpUrl, keyPair) {
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const jwtHeader = {
    alg: 'ES256',
    typ: 'dpop+jwt',
    jwk: publicKeyJwk,
  };

  const jwtPayload = {
    jti: crypto.randomUUID(),
    htm: httpMethod,
    htu: httpUrl,
    iat: Math.floor(Date.now() / 1000),
  };

  const jwtHeaderBase64 = base64URLEncode(JSON.stringify(jwtHeader));
  const jwtPayloadBase64 = base64URLEncode(JSON.stringify(jwtPayload));
  const jwtUnsigned = `${jwtHeaderBase64}.${jwtPayloadBase64}`;

  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    keyPair.privateKey,
    new TextEncoder().encode(jwtUnsigned)
  );

  const jwtSignatureBase64 = base64URLEncode(signature);
  return `${jwtUnsigned}.${jwtSignatureBase64}`;
}

async function getKeyPair() {
  if (localStorage.getItem('dpop-key-pair')) {
    const exportedKeyPair = JSON.parse(localStorage.getItem('dpop-key-pair'));
    return importKeyPair(exportedKeyPair);
  }

  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify']
  );

  const exportedKeyPair = await exportKeyPair(keyPair);
  localStorage.setItem('dpop-key-pair', JSON.stringify(exportedKeyPair));
  return keyPair;
}

async function exportKeyPair(keyPair) {
  const exportedKeyPair = {
    publicKey: await crypto.subtle.exportKey('jwk', keyPair.publicKey),
    privateKey: await crypto.subtle.exportKey('jwk', keyPair.privateKey),
    algorithm: keyPair.publicKey.algorithm,
    usages: {
      publicKey: keyPair.publicKey.usages,
      privateKey: keyPair.privateKey.usages,
    },
  };
  return exportedKeyPair;
}

async function importKeyPair(exportedKeyPair) {
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    exportedKeyPair.publicKey,
    exportedKeyPair.algorithm,
    true,
    exportedKeyPair.usages.publicKey
  );
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    exportedKeyPair.privateKey,
    exportedKeyPair.algorithm,
    true,
    exportedKeyPair.usages.privateKey
  );
  return { publicKey, privateKey };
}

function dpopStringify(dpop) {
  const parts = dpop.split('.');
  const header = JSON.parse(atob(parts[0]));
  const payload = JSON.parse(atob(parts[1]));
  return `${JSON.stringify(header, null, 2)}\n${JSON.stringify(payload, null, 2)}`;
}

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

export { generateDpopProof, getKeyPair, dpopStringify };
