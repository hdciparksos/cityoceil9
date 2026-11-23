/*  S.O.S 푸시 알림 발송 Worker  (Cloudflare Workers, 무료 플랜)
 *  ------------------------------------------------------------
 *  앱(관리 탭)이 등록된 기기 목록과 알림 내용을 보내면, 이 Worker가 각 기기의
 *  푸시 서비스(구글·애플)에 암호화해서 전달합니다.
 *
 *  환경 변수 (Cloudflare 대시보드 → Worker → Settings → Variables and Secrets):
 *    VAPID_PRIVATE_JWK  (Secret)  vapid_keygen.html 이 만들어 준 "비공개 키(JWK)" 한 줄
 *    SEND_KEY           (Secret)  발송 비밀번호 — 아무 긴 문자열. 관리자 기기에만 입력
 *    VAPID_SUBJECT      (Text)    mailto:담당자이메일  (푸시 서비스가 문제 시 연락할 주소)
 *    ALLOWED_ORIGIN     (Text)    https://hakdong4safety.github.io   (앱 주소)
 *
 *  요청:  POST /send   { key, title, body, url, tag, subs:[{id, endpoint, keys:{p256dh,auth}}, …] }
 *  응답:  { sent, results:[{id, status}] }   status 404/410 = 만료된 기기(앱이 목록에서 지움)
 */

const te = new TextEncoder();
const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); s += '='.repeat((4 - s.length % 4) % 4); return Uint8Array.from(atob(s), c => c.charCodeAt(0)); },
};
const concat = (...arrs) => { const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0)); let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out; };

/* ── VAPID (RFC 8292): 발송자 서명 ─────────────────────────── */
async function vapidAuthHeader(endpoint, env) {
  const jwk = JSON.parse(env.VAPID_PRIVATE_JWK);
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const pubRaw = concat(new Uint8Array([4]), b64u.dec(jwk.x), b64u.dec(jwk.y));   // 비압축 공개키 65바이트
  const header = b64u.enc(te.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64u.enc(te.encode(JSON.stringify({
    aud: new URL(endpoint).origin,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: env.VAPID_SUBJECT || 'mailto:safety@example.com',
  })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, te.encode(header + '.' + claims));
  return `vapid t=${header}.${claims}.${b64u.enc(sig)}, k=${b64u.enc(pubRaw)}`;
}

/* ── 메시지 암호화 (RFC 8291 aes128gcm) ─────────────────────── */
async function hkdf(ikm, salt, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
async function encryptPayload(sub, payloadStr) {
  const uaPub = b64u.dec(sub.keys.p256dh), auth = b64u.dec(sub.keys.auth);
  const asKey = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', asKey.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, asKey.privateKey, 256));
  const ikm = await hkdf(ecdh, auth, concat(te.encode('WebPush: info\0'), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(ikm, salt, te.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(ikm, salt, te.encode('Content-Encoding: nonce\0'), 12);
  const plain = concat(te.encode(payloadStr), new Uint8Array([2]));   // 마지막 레코드 구분자
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, plain));
  const rs = new Uint8Array([0, 0, 16, 0]);                                  // record size 4096
  return concat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}

/* ── 기기 1대 발송 ──────────────────────────────────────────── */
async function sendOne(sub, payloadStr, env) {
  const body = await encryptPayload(sub, payloadStr);
  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      Authorization: await vapidAuthHeader(sub.endpoint, env),
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      TTL: '86400',
      Urgency: 'high',
    },
    body,
  });
  return res.status;
}

const corsHeaders = (env) => ({
  'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
});
const json = (obj, status, env) => new Response(JSON.stringify(obj), { status: status || 200, headers: { 'Content-Type': 'application/json', ...corsHeaders(env) } });

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(env) });
    const url = new URL(req.url);
    if (url.pathname === '/send' && req.method === 'POST') {
      let body; try { body = await req.json(); } catch (e) { return json({ error: 'bad json' }, 400, env); }
      if (!env.SEND_KEY || body.key !== env.SEND_KEY) return json({ error: 'unauthorized' }, 401, env);
      if (!env.VAPID_PRIVATE_JWK) return json({ error: 'VAPID_PRIVATE_JWK not set' }, 500, env);
      const subs = Array.isArray(body.subs) ? body.subs.slice(0, 45) : [];   // 무료 플랜 하위요청 한도(50) 안에서
      const payload = JSON.stringify({
        title: String(body.title || 'S.O.S 공지').slice(0, 80),
        body: String(body.body || '').slice(0, 500),
        url: String(body.url || './'),
        tag: String(body.tag || 'sos-notice'),
      });
      const results = await Promise.all(subs.map(s =>
        sendOne(s, payload, env).then(status => ({ id: s.id, status })).catch(e => ({ id: s.id, status: 0, error: String(e).slice(0, 120) }))
      ));
      return json({ sent: results.filter(r => r.status >= 200 && r.status < 300).length, results }, 200, env);
    }
    return json({ ok: true, service: 'sos-push' }, 200, env);
  },
};

/* 테스트용 내보내기 (Node에서 검증할 때만 사용) */
export { encryptPayload, vapidAuthHeader };
