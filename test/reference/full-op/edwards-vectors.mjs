// Regenerate public interoperability fixtures with the pinned jose dependency.
// Private signing keys are ephemeral and are never written to the fixture.
import { generateKeyPair, exportJWK, SignJWT, jwtVerify } from 'jose';
const now = 1800000000;
const vectors = [];
for (const alg of ['Ed25519', 'EdDSA']) {
  const { privateKey, publicKey } = await generateKeyPair(alg);
  const jwk = { ...await exportJWK(publicKey), kid: `fixture-${alg}`, alg, use: 'sig' };
  const token = await new SignJWT({ iss: 'support', aud: 'https://op.example.test',
    iat: now, nbf: now - 1, exp: now + 300, jti: `fixture-${alg}`,
    scope: 'openid', login_hint: 'customer@example.test' })
    .setProtectedHeader({ alg, kid: jwk.kid }).sign(privateKey);
  await jwtVerify(token, publicKey, { algorithms: [alg], issuer: 'support',
    audience: 'https://op.example.test', currentDate: new Date(now * 1000) });
  vectors.push({ alg, jwk, token });
}
console.log(JSON.stringify({ generator: 'jose via pinned full-op/package-lock.json', now, vectors }, null, 2));
