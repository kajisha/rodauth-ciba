// Real TLS receiver; temporary test CA is trusted only by the child test process.
import assert from 'node:assert/strict';
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import { Provider, errors } from 'oidc-provider';

if (!process.env.CIBA_TEST_TLS_DIRECTORY) {
  const directory = mkdtempSync(join(tmpdir(), 'ciba-ping-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem'),
      '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { stdio: 'pipe' });
    const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], { stdio: 'inherit',
      env: { ...process.env, CIBA_TEST_TLS_DIRECTORY: directory, NODE_EXTRA_CA_CERTS: join(directory, 'cert.pem') } });
    if (child.error) throw child.error;
    process.exitCode = child.status ?? 1;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
} else {
  await testPing();
}

async function testPing() {
  const directory = process.env.CIBA_TEST_TLS_DIRECTORY;
  const received = [];
  let status = 204;
  let allowTestReceiver = false;
  let provider;
  let deliveryBarrier;
  let sectorStatus = 200;
  let sectorBody = '[]';
  const sectorRequests = [];
  let sectorRedirectBody = '[]';
  let sectorRedirects = 0;
  const receiver = httpsServer({ key: readFileSync(join(directory, 'key.pem')), cert: readFileSync(join(directory, 'cert.pem')) }, async (req, res) => {
    if (req.url === '/sector') {
      sectorRequests.push(req.headers.authorization);
      res.writeHead(sectorStatus, { 'content-type': 'application/json', ...(sectorStatus === 302 ? { location: '/sector-target' } : {}) });
      res.end(sectorBody);
      return;
    }
    if (req.url === '/sector-target') {
      sectorRedirects++;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(sectorRedirectBody);
      return;
    }
    let body = '';
    for await (const chunk of req) body += chunk;
    received.push({ path: req.url, method: req.method, authorization: req.headers.authorization,
      type: req.headers['content-type'], body: JSON.parse(body) });
    res.writeHead(status, status === 302 ? { location: '/redirect-target' } : {});
    res.end(status === 200 ? "ignored".repeat(20000) : undefined);
  });
  const op = httpServer((req, res) => provider.callback()(req, res));
  const listen = (server) => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  try {
    await listen(receiver);
    await listen(op);
    const issuer = `http://127.0.0.1:${op.address().port}`;
    const endpoint = `https://127.0.0.1:${receiver.address().port}/notify`;
    const sectorEndpoint = endpoint.replace('/notify', '/sector');
    const replacementEndpoint = endpoint.replace('/notify', '/replacement');
    const grantType = 'urn:openid:params:grant-type:ciba';
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    provider = new Provider(issuer, {
      // Test-only exception for this owned loopback receiver. Keep TLS verification,
      // timeout and redirect policy; every other URL retains the default dispatcher.
      subjectTypes: ['public', 'pairwise'],
      fetch: async (url, options) => {
        if (deliveryBarrier && url === endpoint) {
          const barrier = deliveryBarrier;
          deliveryBarrier = undefined;
          barrier.arrive();
          await barrier.release;
        }
        return fetch(url, allowTestReceiver && [endpoint, replacementEndpoint, sectorEndpoint].includes(url) ? { ...options, dispatcher: undefined } : options);
      },
      jwks: { keys: [{ ...privateKey.export({ format: 'jwk' }), kid: 'op', alg: 'RS256', use: 'sig' }] },
      clients: [{ client_id: 'ping', client_secret: 'test-secret', grant_types: [grantType], response_types: [], redirect_uris: [],
        token_endpoint_auth_method: 'client_secret_basic', backchannel_token_delivery_mode: 'ping',
        backchannel_client_notification_endpoint: endpoint }],
      features: { devInteractions: { enabled: false }, registration: { enabled: true, initialAccessToken: 'sector-fixture' }, registrationManagement: { enabled: true }, ciba: { enabled: true, deliveryModes: ['poll', 'ping'],
        processLoginHint: async (_ctx, hint) => hint === 'customer' ? hint : undefined,
        verifyUserCode: async () => {}, validateRequestContext: async () => {}, triggerAuthenticationDevice: async () => {} } },
      findAccount: async (_ctx, id) => ({ accountId: id, claims: async () => ({ sub: id }) }),
    });
    const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
    assert.deepEqual(metadata.backchannel_token_delivery_modes_supported, ['poll', 'ping']);
    const post = async (url, params) => {
      const response = await fetch(url, { method: 'POST', headers: { authorization: `Basic ${Buffer.from('ping:test-secret').toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params) });
      return { status: response.status, body: await response.json() };
    };
    const notificationToken = 'client-generated-notification-token-123456789';
    const start = async () => {
      const response = await post(metadata.backchannel_authentication_endpoint,
        { scope: 'openid', login_hint: 'customer', client_notification_token: notificationToken });
      assert.equal(response.status, 200, JSON.stringify(response.body));
      return response.body.auth_req_id;
    };
    const poll = (id) => post(metadata.token_endpoint, { grant_type: grantType, auth_req_id: id });
    const consent = async () => {
      const grant = new provider.Grant({ clientId: 'ping', accountId: 'customer' });
      grant.addOIDCScope('openid');
      await grant.save();
      return grant;
    };
    for (const token of [undefined, 'bad token', 'x'.repeat(1025)]) {
      const params = { scope: 'openid', login_hint: 'customer' };
      if (token !== undefined) params.client_notification_token = token;
      const response = await post(metadata.backchannel_authentication_endpoint, params);
      assert.equal(response.status, 400);
      assert.equal(response.body.error, 'invalid_request');
    }
    const id = await start();
    assert.equal((await poll(id)).body.error, 'authorization_pending');
    assert.equal(received.length, 0);
    await assert.rejects(provider.backchannelResult(id, await consent(), { authTime: Math.floor(Date.now() / 1000) }),
      (error) => error.cause?.message === 'hostname resolves to a special-use IP address');
    assert.equal(received.length, 0);
    allowTestReceiver = true;
    await (await provider.Client.find('ping')).backchannelPing(await provider.BackchannelAuthenticationRequest.find(id));
    assert.deepEqual(received[0], { path: '/notify', method: 'POST', authorization: `Bearer ${notificationToken}`,
      type: 'application/json', body: { auth_req_id: id } });
    assert.equal((await poll(id)).status, 200);
    const denied = await start();
    status = 200;
    await provider.backchannelResult(denied, new errors.AccessDenied());
    assert.deepEqual(received.at(-1).body, { auth_req_id: denied });
    assert.equal((await poll(denied)).body.error, 'access_denied');
    for (const responseStatus of [503, 302]) {
      status = responseStatus;
      const failed = await start();
      const grant = await consent();
      const before = received.length;
      await assert.rejects(provider.backchannelResult(failed, grant), /expected 204/);
      assert.equal(received.length, before + 1); // No automatic retry or redirect following.
      const saved = await provider.BackchannelAuthenticationRequest.find(failed);
      assert.equal(saved.grantId, grant.jti);
      status = 204;
      const client = await provider.Client.find('ping');
      await client.backchannelPing(saved); // Explicit delivery retry, without recompleting the request.
      assert.equal(received.length, before + 2);
      assert.equal((await poll(failed)).status, 200);
    }
    console.log('PASS ping: default SSRF blocks loopback; exact test-receiver exception retains verified TLS; Bearer/JSON, approval/denial, 200/204, saved result after failure, explicit retry, no redirects');
    for (const change of ['endpoint', 'mode']) {
      const registration = await fetch(metadata.registration_endpoint, { method: 'POST',
        headers: { authorization: 'Bearer sector-fixture', 'content-type': 'application/json' },
        body: JSON.stringify({ grant_types: [grantType], response_types: [], redirect_uris: [],
          token_endpoint_auth_method: 'client_secret_basic', backchannel_token_delivery_mode: 'ping',
          backchannel_client_notification_endpoint: endpoint }) });
      const registered = await registration.json();
      assert.equal(registration.status, 201, JSON.stringify(registered));
      const request = async (url, params) => {
        const result = await fetch(url, { method: 'POST', headers: {
          authorization: `Basic ${Buffer.from(`${registered.client_id}:${registered.client_secret}`).toString('base64')}`,
          'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params) });
        return { status: result.status, body: await result.json() };
      };
      const accepted = await request(metadata.backchannel_authentication_endpoint,
        { scope: 'openid', login_hint: 'customer', client_notification_token: notificationToken });
      assert.equal(accepted.status, 200);
      const requestId = accepted.body.auth_req_id;
      const grant = new provider.Grant({ clientId: registered.client_id, accountId: 'customer' });
      grant.addOIDCScope('openid');
      await grant.save();
      let arrive, release;
      const arrived = new Promise((resolve) => { arrive = resolve; });
      deliveryBarrier = { arrive, release: new Promise((resolve) => { release = resolve; }) };
      const completing = provider.backchannelResult(requestId, grant);
      try {
        await Promise.race([arrived, completing.then(() => { throw new Error('sender never reached barrier'); })]);
        const updated = { ...registered };
        for (const field of ['registration_access_token', 'registration_client_uri', 'client_secret_expires_at', 'client_id_issued_at']) delete updated[field];
        if (change === 'endpoint') updated.backchannel_client_notification_endpoint = replacementEndpoint;
        else { updated.backchannel_token_delivery_mode = 'poll'; delete updated.backchannel_client_notification_endpoint; }
        const management = await fetch(registered.registration_client_uri, { method: 'PUT',
          headers: { authorization: `Bearer ${registered.registration_access_token}`, 'content-type': 'application/json' },
          body: JSON.stringify(updated) });
        assert.equal(management.status, 200, await management.text());
      } finally { release(); }
      await completing;
      assert.equal(received.at(-1).path, '/notify');
      const saved = await provider.BackchannelAuthenticationRequest.find(requestId);
      const currentClient = await provider.Client.find(registered.client_id);
      const beforeRetry = received.length;
      if (change === 'endpoint') {
        await currentClient.backchannelPing(saved);
        assert.equal(received.length, beforeRetry + 1);
        assert.equal(received.at(-1).path, '/replacement');
        assert.equal(received.at(-1).authorization, `Bearer ${notificationToken}`);
        assert.deepEqual(received.at(-1).body, { auth_req_id: requestId });
      } else {
        await assert.rejects(currentClient.backchannelPing(saved), TypeError);
        assert.equal(received.length, beforeRetry);
      }
      const token = await request(metadata.token_endpoint, { grant_type: grantType, auth_req_id: requestId });
      assert.equal(token.status, 200, JSON.stringify(token.body));
      assert.equal((await request(metadata.token_endpoint, { grant_type: grantType, auth_req_id: requestId })).body.error, 'invalid_grant');
    }
    console.log('PASS ping management overlap: in-flight original destination; fresh-client retry forwards saved credential to replacement endpoint, poll-mode retry rejects; token issuance once');
    const jwksUri = endpoint.replace('/notify', '/jwks');
    const redirect = 'https://rp.example.test/callback';
    sectorRedirectBody = JSON.stringify([jwksUri, redirect]);
    let validSectorClient;
    for (const [code, body, expected] of [
      [200, 'not json', 400], [200, '{}', 400], [200, JSON.stringify([redirect]), 400],
      [200, JSON.stringify([jwksUri]), 400], [302, '[]', 201], [503, '[]', 400],
      [200, JSON.stringify([jwksUri, redirect]), 201],
    ]) {
      sectorStatus = code;
      sectorBody = body;
      const response = await fetch(metadata.registration_endpoint, { method: 'POST',
        headers: { authorization: 'Bearer sector-fixture', 'content-type': 'application/json' },
        body: JSON.stringify({ grant_types: [grantType, 'authorization_code'], response_types: ['code'],
          redirect_uris: [redirect], subject_type: 'pairwise', token_endpoint_auth_method: 'private_key_jwt',
          backchannel_token_delivery_mode: 'poll', jwks_uri: jwksUri, sector_identifier_uri: sectorEndpoint }) });
      const result = await response.json();
      assert.equal(response.status, expected, JSON.stringify(result));
      if (expected === 400) assert.equal(result.error, 'invalid_client_metadata');
      else { assert.equal(result.subject_type, 'pairwise'); validSectorClient = result; }
    }
    assert.equal(sectorRequests.length, 7);
    assert.equal(sectorRedirects, 1);
    assert(sectorRequests.every((authorization) => authorization === undefined));
    const loadedClient = await provider.Client.find(validSectorClient.client_id);
    const beforeUnavailable = sectorRequests.length;
    sectorStatus = 503;
    assert.equal(await provider.Client.find(validSectorClient.client_id), loadedClient);
    assert.equal(sectorRequests.length, beforeUnavailable);
    const replacementMetadata = { ...validSectorClient, client_name: 'changed' };
    for (const field of ['registration_access_token', 'registration_client_uri', 'client_secret_expires_at', 'client_id_issued_at']) delete replacementMetadata[field];
    const updateClient = async () => {
      const response = await fetch(validSectorClient.registration_client_uri, { method: 'PUT',
        headers: { authorization: `Bearer ${validSectorClient.registration_access_token}`, 'content-type': 'application/json' },
        body: JSON.stringify(replacementMetadata) });
      return { status: response.status, body: await response.json() };
    };
    const refusedUpdate = await updateClient();
    assert.equal(refusedUpdate.status, 400, JSON.stringify(refusedUpdate));
    assert.equal(refusedUpdate.body.error, 'invalid_client_metadata');
    assert.equal(await provider.Client.find(validSectorClient.client_id), loadedClient);
    sectorStatus = 200;
    const acceptedUpdate = await updateClient();
    assert.equal(acceptedUpdate.status, 200, JSON.stringify(acceptedUpdate));
    console.log('PASS sector cache: unchanged loaded client survives document outage; changed metadata revalidates, failed management update preserves client and credential, retry succeeds');
    console.log('PASS sector TLS: hybrid pairwise registration requires jwks_uri and redirects in HTTPS document; invalid JSON, membership and HTTP errors rejected; same-origin 302 followed to valid document; no registration bearer forwarded');
  } finally {
    for (const server of [op, receiver]) {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  }
}
