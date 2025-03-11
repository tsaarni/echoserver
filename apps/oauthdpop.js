async function generateKeyPair() {
  return await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    false, // non-exportable
    ['sign', 'verify']
  );
}
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

export { generateKeyPair, generateDpopProof, dpopStringify };
