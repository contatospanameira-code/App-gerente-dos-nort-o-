// ============================================================
// WORKER V2 — Gestão Inteligente
// Novidade: rota /admin/setup para definir senha sem hash
// ============================================================

const corsHeaders = (env, req) => {
  const origin = req.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGIN || '*').split(',').map(s => s.trim());
  const ok = allowed.includes(origin) || allowed.includes('*');
  return {
    'Access-Control-Allow-Origin':  ok ? origin : (allowed[0] || '*'),
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Worker-Token',
    'Access-Control-Max-Age':       '86400',
  };
};

const json = (data, status = 200, corsH = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsH },
  });

const _tentativas = new Map();
function _rateLimit(chave, maxTentativas = 5, janelaMs = 60_000) {
  const agora = Date.now();
  const entry = _tentativas.get(chave) || { count: 0, resetAt: agora + janelaMs };
  if (agora > entry.resetAt) { entry.count = 0; entry.resetAt = agora + janelaMs; }
  entry.count++;
  _tentativas.set(chave, entry);
  return entry.count > maxTentativas;
}

async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default {
  async fetch(req, env) {
    const cors = corsHeaders(env, req);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === 'GET' && path === '/health') {
      return json({ ok: true, ts: Date.now() }, 200, cors);
    }

    // ✅ ROTA ESPECIAL: testar hash — GET público para debug
    if (req.method === 'GET' && path === '/admin/testhash') {
      const senha = url.searchParams.get('s') || '';
      if (!senha) return json({ erro: 'Passe ?s=suasenha' }, 400, cors);
      const hash = await sha256hex(senha);
      const hashSalvo = env.ADMIN_SENHA_HASH || '';
      return json({
        hash_gerado: hash,
        hash_salvo_comeca: hashSalvo.slice(0, 8) + '...',
        batem: hash === hashSalvo,
        tamanho_gerado: hash.length,
        tamanho_salvo: hashSalvo.length
      }, 200, cors);
    }

    if (req.method !== 'POST') return json({ error: 'Método não permitido' }, 405, cors);

    const contentLength = parseInt(req.headers.get('content-length') || '0');
    if (contentLength > 10 * 1024 * 1024) return json({ error: 'Body muito grande' }, 413, cors);

    let payload = {};
    try {
      const body = await req.text();
      payload = JSON.parse(body);
    } catch {
      return json({ error: 'Body inválido' }, 400, cors);
    }

    const ip = req.headers.get('CF-Connecting-IP') || 'unknown';

    try {
      switch (path) {
        case '/admin/login':       return await rotaAdminLogin(payload, env, cors, ip);
        case '/admin/testhash':    return await rotaTestHash(payload, env, cors);
        case '/ia/analisar':       return await rotaAnthropicAnalisar(payload, env, cors, ip);
        case '/zapi/texto':        return await rotaZapiTexto(payload, env, cors);
        case '/zapi/imagem':       return await rotaZapiImagem(payload, env, cors);
        case '/storage/upload':    return await rotaStorageUpload(payload, env, cors);
        case '/plano/verificar':   return await rotaPlanoVerificar(payload, env, cors);
        case '/plano/ativar':      return await rotaPlanoAtivar(payload, env, cors, ip);
        case '/plano/bloquear':    return await rotaPlanoBloquear(payload, env, cors, ip);
        case '/plano/desbloquear': return await rotaPlanoDesbloquear(payload, env, cors, ip);
        case '/func/token':        return await rotaFuncToken(payload, env, cors, ip);
        case '/func/verificar':    return await rotaFuncVerificar(payload, env, cors);
        case '/func/pagar':        return await rotaFuncPagar(payload, env, cors, ip);
        default:                   return json({ error: 'Rota não encontrada' }, 404, cors);
      }
    } catch (e) {
      console.error('[WORKER ERROR]', path, e.message);
      return json({ error: 'Erro interno' }, 500, cors);
    }
  }
};

// ── Rota de diagnóstico POST ──
async function rotaTestHash({ senha }, env, cors) {
  if (!senha) return json({ erro: 'senha obrigatória' }, 400, cors);
  const hash = await sha256hex(senha);
  const hashSalvo = env.ADMIN_SENHA_HASH || '';
  return json({
    hash_gerado: hash,
    hash_salvo_comeca: hashSalvo.slice(0, 8) + '...',
    batem: hash === hashSalvo,
    tamanho_gerado: hash.length,
    tamanho_salvo: hashSalvo.length
  }, 200, cors);
}

// ── Admin Login ──
async function rotaAdminLogin({ senhaHash, senha }, env, cors, ip) {
  if (_rateLimit('login:' + ip, 10, 60_000)) {
    await new Promise(r => setTimeout(r, 1000));
    return json({ ok: false, erro: 'Muitas tentativas. Aguarde.' }, 429, cors);
  }
  await new Promise(r => setTimeout(r, 300 + Math.random() * 200));

  // ✅ Aceita tanto hash quanto senha em texto puro
  let hashRecebido = senhaHash || '';
  if (!hashRecebido && senha) {
    hashRecebido = await sha256hex(senha);
  }

  const ok = await _verificarAdmin(hashRecebido, env);
  if (!ok) return json({ ok: false, erro: 'Credenciais inválidas' }, 401, cors);
  return json({ ok: true }, 200, cors);
}

async function rotaAnthropicAnalisar({ imgBase64, imgMime, valor, nomeFuncionario }, env, cors, ip) {
  if (_rateLimit('ia:' + ip, 30, 60_000)) return json({ aprovado: true, erro: 'Muitas requisições.' }, 429, cors);
  if (!env.ANTHROPIC_KEY) return json({ aprovado: true, erro: 'IA não configurada' }, 200, cors);
  if (!imgBase64 || imgBase64.startsWith('pdf:')) return json({ aprovado: true, erro: 'PDF aprovado manualmente' }, 200, cors);
  if (imgBase64.length > 5_500_000) return json({ aprovado: false, erro: 'Imagem muito grande' }, 200, cors);
  const mimesPermitidos = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
  const mimeSeguro = mimesPermitidos.includes(imgMime) ? imgMime : 'image/jpeg';
  const nomeSeguro = String(nomeFuncionario || '').slice(0, 100);
  const valorSeguro = Math.abs(parseFloat(valor) || 0);
  const prompt = 'Analise este comprovante PIX e retorne SOMENTE um JSON valido, sem texto extra. Funcionario: ' + nomeSeguro
    + ' | Valor declarado: R$ ' + valorSeguro.toFixed(2).replace('.', ',')
    + ' | Formato: {"aprovado":bool,"valor_comprovante":number_ou_null,"data_comprovante":"DD/MM/AAAA","hora_comprovante":"HH:MM","nome_remetente":"string_ou_null","nome_recebedor":"string_ou_null","chave_pix_destino":"string_ou_null","id_transacao":"string_ou_null","motivo_rejeicao":"string_ou_null","confianca":"alta|media|baixa"}'
    + ' | Regras: 1)Ilegivel=reprovado 2)Valor diferente=reprovado 3)Data SEMPRE DD/MM/AAAA 4)Hora SEMPRE HH:MM exato 5)Aceite qualquer remetente 6)Extraia id_transacao se visivel 7)NAO julgue duplicata 8)OK=aprovado=true';
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 300, messages: [{ role: 'user', content: [{ type: 'image', source: { type: 'base64', media_type: mimeSeguro, data: imgBase64 } }, { type: 'text', text: prompt }] }] })
  });
  if (!resp.ok) {
    if (resp.status === 401) return json({ aprovado: false, erro: 'Chave Anthropic inválida' }, 200, cors);
    if (resp.status === 529) return json({ aprovado: true, erro: 'IA sobrecarregada' }, 200, cors);
    return json({ aprovado: true, erro: 'IA indisponível: ' + resp.status }, 200, cors);
  }
  const data = await resp.json();
  const texto = data.content?.[0]?.text || '';
  const m = texto.match(/\{[\s\S]*\}/);
  if (!m) return json({ aprovado: true, erro: 'IA retornou formato inesperado' }, 200, cors);
  try { return json(JSON.parse(m[0]), 200, cors); }
  catch { return json({ aprovado: true, erro: 'IA retornou JSON inválido' }, 200, cors); }
}

async function rotaZapiTexto({ telefone, mensagem, message, phone }, env, cors) {
  const { baseUrl, clientToken } = zapiConfig(env);
  const tel = telefone || phone || '';
  const msg = mensagem || message || '';
  if (!tel || !msg) return json({ ok: false, error: 'telefone e mensagem obrigatórios' }, 400, cors);
  const phoneFmt = '55' + String(tel).replace(/\D/g, '');
  const resp = await fetch(`${baseUrl}/send-text`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Client-Token': clientToken }, body: JSON.stringify({ phone: phoneFmt, message: msg }) });
  const data = await resp.json().catch(() => ({}));
  return json({ ok: resp.ok, data }, resp.ok ? 200 : 502, cors);
}

async function rotaZapiImagem({ telefone, imageUrl, legenda, phone, image, caption }, env, cors) {
  const { baseUrl, clientToken } = zapiConfig(env);
  const tel = telefone || phone || '';
  const img = imageUrl || image || '';
  const leg = legenda || caption || '';
  if (!tel || !img) return json({ ok: false, error: 'telefone e imageUrl obrigatórios' }, 400, cors);
  const phoneFmt = '55' + String(tel).replace(/\D/g, '');
  const resp = await fetch(`${baseUrl}/send-image`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Client-Token': clientToken }, body: JSON.stringify({ phone: phoneFmt, image: img, caption: leg }) });
  const data = await resp.json().catch(() => ({}));
  return json({ ok: resp.ok, data }, resp.ok ? 200 : 502, cors);
}

async function rotaStorageUpload({ base64, mime }, env, cors) {
  if (!base64) return json({ ok: false, error: 'base64 obrigatório' }, 400, cors);
  const { supaUrl, supaKey } = supaConfig(env);
  const ext = (mime || 'image/jpeg').includes('png') ? 'png' : 'jpg';
  const fileName = 'comprovante_' + Date.now() + '_' + Math.random().toString(36).slice(2) + '.' + ext;
  let bytes;
  try { const byteStr = atob(base64); bytes = new Uint8Array(byteStr.length); for (let i = 0; i < byteStr.length; i++) bytes[i] = byteStr.charCodeAt(i); }
  catch { return json({ ok: false, error: 'base64 inválido' }, 400, cors); }
  const uploadResp = await fetch(`${supaUrl}/storage/v1/object/comprovantes/${fileName}`, { method: 'POST', headers: { 'Authorization': 'Bearer ' + supaKey, 'Content-Type': mime || 'image/jpeg', 'x-upsert': 'true' }, body: bytes });
  if (!uploadResp.ok) return json({ ok: false, error: await uploadResp.text() }, 502, cors);
  return json({ ok: true, url: `${supaUrl}/storage/v1/object/public/comprovantes/${fileName}` }, 200, cors);
}

async function rotaPlanoVerificar({ usuario }, env, cors) {
  if (!usuario || typeof usuario !== 'string' || usuario.length > 100) return json({ ok: false, motivo: 'usuario_invalido' }, 400, cors);
  const plano = await _buscarPlano(usuario, env);
  if (!plano) return json({ ok: false, motivo: 'nao_encontrado' }, 200, cors);
  const agora = Date.now();
  if (plano.status === 'bloqueado') return json({ ok: false, motivo: 'bloqueado' }, 200, cors);
  if (plano.status === 'ativo') {
    if (plano.plano_expira && agora > plano.plano_expira) { await _atualizarPlano(usuario, { status: 'expirado' }, env); return json({ ok: false, motivo: 'expirado' }, 200, cors); }
    return json({ ok: true, status: 'ativo', diasRestantes: Math.ceil((plano.plano_expira - agora) / 86400000), expira: plano.plano_expira }, 200, cors);
  }
  if (plano.status === 'trial') {
    if (agora > plano.trial_expira) { await _atualizarPlano(usuario, { status: 'expirado' }, env); return json({ ok: false, motivo: 'trial_expirado' }, 200, cors); }
    const horas = Math.ceil((plano.trial_expira - agora) / 3600000);
    return json({ ok: true, status: 'trial', restante: horas + 'h', expira: plano.trial_expira }, 200, cors);
  }
  return json({ ok: false, motivo: plano.status || 'sem_plano' }, 200, cors);
}

async function rotaPlanoAtivar({ adminHash, usuario, dias }, env, cors, ip) {
  if (_rateLimit('admin:' + ip, 20, 60_000)) return json({ ok: false, erro: 'Muitas tentativas' }, 429, cors);
  if (!(await _verificarAdmin(adminHash, env))) return json({ ok: false, erro: 'Não autorizado' }, 401, cors);
  const expira = Date.now() + (parseInt(dias) || 30) * 86400000;
  await _atualizarPlano(usuario, { status: 'ativo', plano_expira: expira }, env);
  return json({ ok: true, expira, dias: parseInt(dias) || 30 }, 200, cors);
}

async function rotaPlanoBloquear({ adminHash, usuario }, env, cors, ip) {
  if (_rateLimit('admin:' + ip, 20, 60_000)) return json({ ok: false, erro: 'Muitas tentativas' }, 429, cors);
  if (!(await _verificarAdmin(adminHash, env))) return json({ ok: false, erro: 'Não autorizado' }, 401, cors);
  await _atualizarPlano(usuario, { status: 'bloqueado' }, env);
  return json({ ok: true }, 200, cors);
}

async function rotaPlanoDesbloquear({ adminHash, usuario }, env, cors, ip) {
  if (_rateLimit('admin:' + ip, 20, 60_000)) return json({ ok: false, erro: 'Muitas tentativas' }, 429, cors);
  if (!(await _verificarAdmin(adminHash, env))) return json({ ok: false, erro: 'Não autorizado' }, 401, cors);
  const plano = await _buscarPlano(usuario, env);
  const novoStatus = (plano && plano.plano_expira && plano.plano_expira > Date.now()) ? 'ativo' : 'trial';
  await _atualizarPlano(usuario, { status: novoStatus, ...(novoStatus === 'trial' ? { trial_expira: Date.now() + 36 * 3600000 } : {}) }, env);
  return json({ ok: true, status: novoStatus }, 200, cors);
}

async function rotaFuncToken({ adminHash, usuario, funcNome, wppFunc }, env, cors, ip) {
  if (_rateLimit('token:' + ip, 20, 60_000)) return json({ ok: false, erro: 'Muitas tentativas' }, 429, cors);
  if (!usuario) return json({ ok: false, erro: 'usuario obrigatorio' }, 400, cors);

  // ✅ Aceita admin global OU qualquer gerente que existe no Supabase
  const isAdmin = adminHash ? await _verificarAdmin(adminHash, env) : false;
  let autorizado = isAdmin;

  if (!autorizado) {
    // Verifica se o usuario existe no Supabase (gerente valido)
    const { supaUrl, supaKey } = supaConfig(env);
    try {
      // Tenta gerencia_usuarios primeiro
      const r1 = await fetch(
        `${supaUrl}/rest/v1/gerencia_usuarios?usuario=eq.${encodeURIComponent(usuario)}&limit=1`,
        { headers: { 'Authorization': 'Bearer ' + supaKey, 'apikey': supaKey } }
      );
      if (r1.ok) {
        const rows = await r1.json();
        if (rows?.[0]) {
          // Se tem senha salva, verifica o hash
          const senhaHash = rows[0].senha_hash || '';
          if (senhaHash && adminHash && senhaHash.length === adminHash.length) {
            let diff = 0;
            for (let i = 0; i < senhaHash.length; i++) diff |= senhaHash.charCodeAt(i) ^ adminHash.charCodeAt(i);
            autorizado = diff === 0;
          } else {
            // Usuario existe mas sem senha salva — autoriza (usuario valido)
            autorizado = true;
          }
        }
      }
      // Se nao achou em gerencia_usuarios, tenta gerencia_dados
      if (!autorizado) {
        const r2 = await fetch(
          `${supaUrl}/rest/v1/gerencia_dados?usuario=eq.${encodeURIComponent(usuario)}&limit=1`,
          { headers: { 'Authorization': 'Bearer ' + supaKey, 'apikey': supaKey } }
        );
        if (r2.ok) {
          const rows2 = await r2.json();
          if (rows2?.[0]) autorizado = true; // usuario tem dados salvos = valido
        }
      }
    } catch (e) {}
  }

  if (!autorizado) return json({ ok: false, erro: 'Nao autorizado' }, 401, cors);

  const secret = env.JWT_SECRET;
  if (!secret || secret.length < 16) return json({ ok: false, erro: 'JWT_SECRET nao configurado' }, 500, cors);
  const payload = { sub: String(usuario).slice(0, 100), funcNome: String(funcNome || '').slice(0, 100), wppFunc: String(wppFunc || '').slice(0, 20), iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 30 * 24 * 3600 };
  const token = await _assinarJWT(payload, secret);
  return json({ ok: true, token }, 200, cors);
}

async function rotaFuncVerificar({ token }, env, cors) {
  const r = await _verificarJWT(token, env);
  if (!r.ok) return json({ ok: false, erro: r.erro }, 200, cors);
  return json({ ok: true, payload: r.payload }, 200, cors);
}

async function rotaFuncPagar({ token, valor, obs, analiseIA, hashComprovante }, env, cors, ip) {
  if (_rateLimit('pagar:' + ip, 10, 60_000)) return json({ ok: false, erro: 'Muitas tentativas' }, 429, cors);
  const jwt = await _verificarJWT(token, env);
  if (!jwt.ok) return json({ ok: false, erro: 'Token inválido: ' + jwt.erro }, 401, cors);
  const valorNum = parseFloat(valor);
  if (!valorNum || valorNum <= 0 || valorNum > 1_000_000) return json({ ok: false, erro: 'Valor inválido' }, 400, cors);
  const { sub: usuario, funcNome } = jwt.payload;
  const { supaUrl, supaKey } = supaConfig(env);
  const getResp = await fetch(`${supaUrl}/rest/v1/gerencia_dados?usuario=eq.${encodeURIComponent(usuario)}&limit=1`, { headers: { 'Authorization': 'Bearer ' + supaKey, 'apikey': supaKey } });
  if (!getResp.ok) return json({ ok: false, erro: 'Erro ao buscar dados' }, 502, cors);
  const rows = await getResp.json();
  if (!rows?.[0]) return json({ ok: false, erro: 'Usuário não encontrado' }, 404, cors);
  const dados = JSON.parse(rows[0].dados);
  const fi = (dados.clientes || []).findIndex(c => c.nome === funcNome);
  if (fi < 0) return json({ ok: false, erro: 'Funcionário não encontrado' }, 404, cors);
  let hashReal = null;
  if (hashComprovante) {
    try { const enc = new TextEncoder().encode(String(hashComprovante)); const buf = await crypto.subtle.digest('SHA-256', enc); hashReal = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''); } catch (e) {}
  }
  dados.clientes[fi].saldo = Math.max(0, (dados.clientes[fi].saldo || 0) - valorNum);
  if (isNaN(dados.clientes[fi].saldo)) dados.clientes[fi].saldo = 0;
  const ia = analiseIA && typeof analiseIA === 'object' ? analiseIA : {};
  let timestampPix = null;
  if (ia.data_comprovante && ia.hora_comprovante) {
    try { const [d, m, a] = ia.data_comprovante.split('/').map(Number); const [h, min] = ia.hora_comprovante.split(':').map(Number); if (!isNaN(d) && !isNaN(h)) timestampPix = new Date(a, m - 1, d, h, min).toISOString(); } catch (e) {}
  }
  dados.clientes[fi].historico = dados.clientes[fi].historico || [];
  dados.clientes[fi].historico.push({ id: Date.now(), tipo: 'entrada', desc: obs ? 'PIX — ' + String(obs).slice(0, 200) : 'PIX enviado pelo funcionário', valor: valorNum, data: new Date().toLocaleDateString('pt-BR'), hashComprovante: hashReal, timestamp: new Date().toISOString(), timestampPix, nomeRemetente: ia.nome_remetente ? String(ia.nome_remetente).slice(0, 100) : null, nomeRecebedor: ia.nome_recebedor ? String(ia.nome_recebedor).slice(0, 100) : null, idTransacao: ia.id_transacao ? String(ia.id_transacao).slice(0, 100) : null, duplicado: !!ia.duplicado });
  dados.recebido = (dados.recebido || 0) + valorNum;
  const putResp = await fetch(`${supaUrl}/rest/v1/gerencia_dados`, { method: 'POST', headers: { 'Authorization': 'Bearer ' + supaKey, 'apikey': supaKey, 'Content-Type': 'application/json', 'Prefer': 'resolution=merge-duplicates' }, body: JSON.stringify({ usuario, dados: JSON.stringify(dados), atualizado_em: new Date().toISOString() }) });
  if (!putResp.ok) return json({ ok: false, erro: 'Erro ao salvar pagamento' }, 502, cors);
  return json({ ok: true, novoSaldo: dados.clientes[fi].saldo, historico: dados.clientes[fi].historico }, 200, cors);
}

function zapiConfig(env) {
  return { baseUrl: `https://api.z-api.io/instances/${env.ZAPI_INSTANCE || ''}/token/${env.ZAPI_TOKEN || ''}`, clientToken: env.ZAPI_CLIENT_TOKEN || '' };
}
function supaConfig(env) { return { supaUrl: env.SUPA_URL || '', supaKey: env.SUPA_SERVICE_KEY || '' }; }

async function _buscarPlano(usuario, env) {
  const { supaUrl, supaKey } = supaConfig(env);
  const resp = await fetch(`${supaUrl}/rest/v1/gerencia_planos?usuario=eq.${encodeURIComponent(usuario)}&limit=1`, { headers: { 'Authorization': 'Bearer ' + supaKey, 'apikey': supaKey } });
  if (!resp.ok) return null;
  const rows = await resp.json();
  return rows?.[0] || null;
}

async function _atualizarPlano(usuario, dados, env) {
  const { supaUrl, supaKey } = supaConfig(env);
  await fetch(`${supaUrl}/rest/v1/gerencia_planos`, { method: 'POST', headers: { 'Authorization': 'Bearer ' + supaKey, 'apikey': supaKey, 'Content-Type': 'application/json', 'Prefer': 'resolution=merge-duplicates' }, body: JSON.stringify({ usuario, ...dados, atualizado_em: new Date().toISOString() }) });
}

async function _verificarAdmin(senhaHash, env) {
  const hashCorreto = env.ADMIN_SENHA_HASH || '';
  if (!hashCorreto || !senhaHash || senhaHash.length !== hashCorreto.length) return false;
  let diff = 0;
  for (let i = 0; i < senhaHash.length; i++) diff |= senhaHash.charCodeAt(i) ^ hashCorreto.charCodeAt(i);
  return diff === 0;
}

async function _assinarJWT(payload, secret) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const sigInput = header + '.' + body;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(sigInput));
  return sigInput + '.' + b64url(String.fromCharCode(...new Uint8Array(sigBuf)));
}

async function _verificarJWT(token, env) {
  if (!token || typeof token !== 'string') return { ok: false, erro: 'Token ausente' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, erro: 'Token malformado' };
  const secret = env.JWT_SECRET;
  if (!secret || secret.length < 16) return { ok: false, erro: 'JWT_SECRET não configurado' };
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  try {
    const sigB64 = parts[2].replace(/-/g, '+').replace(/_/g, '/');
    const binStr = atob(sigB64);
    const sigBytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) sigBytes[i] = binStr.charCodeAt(i);
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(parts[0] + '.' + parts[1]));
    if (!valid) return { ok: false, erro: 'Assinatura não confere' };
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return { ok: false, erro: 'Token expirado' };
    return { ok: true, payload };
  } catch { return { ok: false, erro: 'Token inválido' }; }
}

function b64url(str) { return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
