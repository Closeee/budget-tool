/**
 * 本月预算 · Cloudflare Worker
 * - 密码门：所有页面与接口都需登录（PIN 存在环境变量 APP_PIN）
 * - 跨设备同步：Durable Object 保存全部记录
 * - 静态资源：由 ASSETS 托管 public/
 */

const COOKIE_NAME = 'budget_auth';

// ---------- HMAC 签名（防伪造 cookie）----------
async function sign(secret, msg) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// 恒定时间比较，防时序攻击
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function getCookie(request, name) {
  const c = request.headers.get('Cookie') || '';
  const m = c.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}

async function isAuthed(request, env) {
  const token = getCookie(request, COOKIE_NAME);
  if (!token) return false;
  const expect = await sign(env.AUTH_SECRET || 'default-secret-change-me', 'ok');
  return safeEqual(token, expect);
}

// ---------- 登录页 ----------
function loginPage(error = '') {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · 本月预算</title>
<style>
:root{--bg:#0f1420;--tx:#e6ecf5;--sub:#8b98ad;--acc:#3d7bfd;--bad:#f0584d}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;
min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:330px;background:#1a2130;border:1px solid #2a3448;border-radius:20px;padding:32px 26px;text-align:center}
.icon{font-size:40px;margin-bottom:10px}
h1{font-size:18px;font-weight:600;margin-bottom:6px}
p{color:var(--sub);font-size:13px;margin-bottom:22px}
input{width:100%;padding:14px;border:1px solid #2a3448;background:#0f1420;color:var(--tx);
border-radius:12px;font-size:18px;text-align:center;letter-spacing:4px;outline:none;margin-bottom:14px}
input:focus{border-color:var(--acc)}
button{width:100%;padding:14px;background:var(--acc);color:#fff;border:none;border-radius:12px;font-size:16px;font-weight:600;cursor:pointer}
.err{color:var(--bad);font-size:13px;margin-bottom:12px}
</style></head><body>
<div class="card">
  <div class="icon">🔒</div>
  <h1>本月预算</h1>
  <p>请输入访问密码</p>
  ${error ? `<div class="err">${error}</div>` : ''}
  <form method="POST" action="/api/login">
    <input name="pin" type="password" inputmode="numeric" autocomplete="current-password" placeholder="••••" autofocus>
    <button type="submit">进入</button>
  </form>
</div></body></html>`;
}

// ---------- Durable Object：保存全部记录 ----------
export class BudgetRoom {
  constructor(state, env) { this.state = state; }

  async fetch(request) {
    const method = request.method;
    if (method === 'GET') {
      const data = (await this.state.storage.get('state')) || { txs: [] };
      return Response.json(data);
    }
    if (method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return new Response('bad json', { status: 400 }); }
      if (!Array.isArray(body.txs)) return new Response('invalid', { status: 400 });
      // 限制规模，防止异常膨胀
      body.txs = body.txs.slice(0, 20000);
      await this.state.storage.put('state', body);
      return Response.json({ ok: true, count: body.txs.length });
    }
    return new Response('method not allowed', { status: 405 });
  }
}

// ---------- 主 Worker ----------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 登录
    if (path === '/api/login' && request.method === 'POST') {
      let pin = '';
      const ct = request.headers.get('Content-Type') || '';
      if (ct.includes('application/json')) {
        try { pin = (await request.json()).pin || ''; } catch {}
      } else {
        const form = await request.formData();
        pin = form.get('pin') || '';
      }
      const expect = env.APP_PIN || '';
      if (!expect) {
        return new Response(loginPage('服务端未设置密码（APP_PIN）'), {
          status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }
      if (!safeEqual(pin, expect)) {
        return new Response(loginPage('密码不对，再试一次'), {
          status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }
      const token = await sign(env.AUTH_SECRET || 'default-secret-change-me', 'ok');
      const maxAge = 60 * 60 * 24 * 365; // 记一年
      return new Response(null, {
        status: 302,
        headers: {
          'Location': '/',
          'Set-Cookie': `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`
        }
      });
    }

    // 退出
    if (path === '/api/logout') {
      return new Response(null, {
        status: 302,
        headers: { 'Location': '/', 'Set-Cookie': `${COOKIE_NAME}=; Path=/; Max-Age=0` }
      });
    }

    const authed = await isAuthed(request, env);

    // API：需要登录
    if (path.startsWith('/api/')) {
      if (!authed) return new Response('unauthorized', { status: 401 });
      if (path === '/api/state') {
        const id = env.BUDGET_ROOM.idFromName('owner');   // 单人使用，固定房间
        const stub = env.BUDGET_ROOM.get(id);
        return stub.fetch(request);
      }
      return new Response('not found', { status: 404 });
    }

    // 静态资源：未登录一律给登录页
    if (!authed) {
      return new Response(loginPage(), {
        status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }
    return env.ASSETS.fetch(request);
  }
};
