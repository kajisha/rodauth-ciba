// Actual HTTP listeners with one canonical issuer and two endpoint origins.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, randomUUID, createHash } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { Provider } from 'oidc-provider';
const grantType = 'urn:openid:params:grant-type:ciba';
const issuerKey = generateKeyPairSync('rsa', {modulusLength:2048});
const proofKey = generateKeyPairSync('ec', {namedCurve:'prime256v1'});
let provider;
const servers = [0,1].map(() => createServer((req,res) => provider.callback()(req,res)));
for (const server of servers) await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
const [issuer, alias] = servers.map(server => `http://127.0.0.1:${server.address().port}`);
try {
  provider = new Provider(issuer, {
    jwks:{keys:[{...issuerKey.privateKey.export({format:'jwk'}), kid:'op', use:'sig', alg:'RS256'}]},
    scopes:['openid','offline_access'],
    clients:[{client_id:'client',client_secret:'alias-test-secret',grant_types:[grantType,'refresh_token'],
      response_types:[],redirect_uris:[],backchannel_token_delivery_mode:'poll',token_endpoint_auth_method:'client_secret_basic'}],
    features:{devInteractions:{enabled:false},dPoP:{enabled:true,requireNonce:()=>false},ciba:{enabled:true,deliveryModes:['poll'],
      processLoginHint:async()=> 'customer',validateRequestContext:async()=>{},validateBindingMessage:async()=>{},
      verifyUserCode:async()=>{},triggerAuthenticationDevice:async()=>{}}},
    findAccount:async(_ctx,accountId)=>({accountId,claims:async()=>({sub:accountId})}),
  });
  async function proof(htu, htm='POST', token) {
    return new SignJWT({htu,htm,iat:Math.floor(Date.now()/1000),jti:randomUUID(),
      ...(token ? {ath:createHash('sha256').update(token).digest('base64url')} : {})})
      .setProtectedHeader({typ:'dpop+jwt',alg:'ES256',jwk:proofKey.publicKey.export({format:'jwk'})}).sign(proofKey.privateKey);
  }
  async function post(url, params, htu, headers = {}) {
    const res=await fetch(url,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',
      authorization:`Basic ${Buffer.from('client:alias-test-secret').toString('base64')}`,
      ...(htu ? {dpop:await proof(htu)} : {}), ...headers},body:new URLSearchParams(params)});
    return {status:res.status,body:await res.json()};
  }
  const metadata=await(await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  const begin=await post(metadata.backchannel_authentication_endpoint,{scope:'openid offline_access',login_hint:'customer'});
  assert.equal(begin.status,200);
  const grant=new provider.Grant({accountId:'customer',clientId:'client'});
  grant.addOIDCScope('openid offline_access');await grant.save();
  await provider.backchannelResult(begin.body.auth_req_id,grant);
  const params={grant_type:grantType,auth_req_id:begin.body.auth_req_id};
  const wrong=await post(`${alias}/token`,params,`${issuer}/token`);
  assert.equal(wrong.status,400);assert.equal(wrong.body.error,'invalid_dpop_proof');
  for (const headers of [{forwarded:`host="${new URL(issuer).host}";proto=http`},
    {'x-forwarded-host':new URL(issuer).host,'x-forwarded-proto':'http'}]) {
    const spoofed=await post(`${alias}/token`,params,`${issuer}/token`,headers);
    assert.equal(spoofed.status,400);assert.equal(spoofed.body.error,'invalid_dpop_proof');
  }

  const issued=await post(`${alias}/token`,params,`${alias}/token`);
  assert.equal(issued.status,200,JSON.stringify(issued.body));
  const identity = await jwtVerify(issued.body.id_token,issuerKey.publicKey,{issuer,audience:'client'});
  assert.equal(Object.hasOwn(identity.payload, 'cnf'),false);
  for (const target of [`${issuer}/me`,`${alias}/wrong`,`${alias}/me`]) {
    const res=await fetch(`${alias}/me`,{headers:{authorization:`DPoP ${issued.body.access_token}`,
      dpop:await proof(target,'GET',issued.body.access_token)}});
    assert.equal(res.status,target===`${alias}/me`?200:401);
    if(res.status===200) assert.equal((await res.json()).sub,'customer');
  }
  const refresh={grant_type:'refresh_token',refresh_token:issued.body.refresh_token};
  assert.equal((await post(`${alias}/token`,refresh,`${issuer}/token`)).body.error,'invalid_dpop_proof');
  const renewed = await post(`${alias}/token`,refresh,`${alias}/token`);
  assert.equal(renewed.status,200);
  const renewedIdentity = await jwtVerify(renewed.body.id_token,issuerKey.publicKey,{issuer,audience:'client'});
  assert.equal(Object.hasOwn(renewedIdentity.payload,'cnf'),false);
  assert.equal((await post(`${issuer}/token`,refresh,`${alias}/token`)).body.error,'invalid_dpop_proof');
  console.log('PASS DPoP alias origin/path binding: issuance, UserInfo, refresh; canonical issuer retained; cross-origin proofs rejected');
} finally {
  for(const server of servers) {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
}
