#!/usr/bin/env node

/**
 * Incudal 邀請碼發放機器人 (@incudal_invite_bot)
 * Polling mode, independent service, zero npm deps.
 *
 * Features:
 *   /start → submit essay → admin gets Approve/Reject buttons
 *   approve → picks code from inventory, sends to applicant
 *   reject → says "不通過"
 *   /su → admin mode to add invite codes (one per line)
 *   Admin locked to first /su caller via persistent db.adminId
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';

// ── Config ────────────────────────────────────────────────────────
const BOT_TOKEN = process.env.BOT_TOKEN;
const POLL_TIMEOUT = 30;
const CODE_MIN_LEN = 4;

if (!BOT_TOKEN) { console.error('FATAL: BOT_TOKEN required'); process.exit(1); }
const API = `https://api.telegram.org/bot${BOT_TOKEN}`;

// ── DB ────────────────────────────────────────────────────────────
function ensureDbDir() {
  const d = dirname(DB_PATH);
  if (!existsSync(d)) mkdirSync(d, { recursive: true });
}
function loadDb() {
  if (!existsSync(DB_PATH)) return { applications: [], inventory: [], adminId: null };
  try { return JSON.parse(readFileSync(DB_PATH, 'utf-8')); }
  catch { return { applications: [], inventory: [], adminId: null }; }
}
function saveDb(data) { ensureDbDir(); writeFileSync(DB_PATH, JSON.stringify(data, null, 2)); }

const db = loadDb();
let adminUserId = db.adminId;                        // persisted, survives restart

// ── State ─────────────────────────────────────────────────────────
let lastUpdateId = 0;
const suSessions = new Set();                        // chat-ids in /su mode
let heartBeat = 0;

// ── TG API helpers ───────────────────────────────────────────────
async function tg(method, payload = {}) {
  const r = await fetch(`${API}/${method}`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
  const j = await r.json();
  if (!j.ok) console.warn(`[tg] ${method}:`, JSON.stringify(j).slice(0,200));
  return j;
}
async function sendMessage(chatId, text, extra={}) {
  return tg('sendMessage', { chat_id:chatId, text, parse_mode:'HTML', disable_web_page_preview:true, ...extra });
}
async function editMsg(chatId, msgId, text, extra={}) {
  return tg('editMessageText', { chat_id:chatId, message_id:msgId, text, parse_mode:'HTML', ...extra });
}
async function answerCbq(cbId, text='', alert=false) {
  return tg('answerCallbackQuery', { callback_query_id:cbId, text, show_alert:alert });
}
async function getUpdates(offset) {
  const r = await fetch(`${API}/getUpdates`, { method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ offset, timeout:POLL_TIMEOUT, allowed_updates:['message','callback_query'] }) });
  return r.json();
}

// ── Handle messages ──────────────────────────────────────────────
async function handleMessage(msg) {
  const chatId = msg.chat.id, userId = msg.from.id;
  const uname = msg.from.username || '', fn = msg.from.first_name||'', ln = msg.from.last_name||'';
  const text = (msg.text||'').trim();
  const display = [fn,ln].filter(Boolean).join(' ') || uname || String(userId);

  // Auto-capture admin on first /su
  if (!adminUserId && text.startsWith('/su')) { adminUserId = userId; db.adminId = userId; saveDb(db); console.log(`Admin set: ${userId}`); }

  if (text.startsWith('/start')) {
    return sendMessage(chatId, `🎉 歡迎來到 Incudal 邀請碼申請 Bot！

請提交一篇自我介紹，說明：你為什麼需要 Incudal 服務、你的使用經驗、用途等。

📝 <b>直接發送文字給我</b>即可提交申請。
⚠️ 每個帳號只能提交一次。`);
  }
  if (text.startsWith('/id')) return sendMessage(chatId, `你的 Telegram ID：<code>${userId}</code>`);

  // /su — inline or enter mode
  if (text.startsWith('/su')) {
    if (userId !== adminUserId) return sendMessage(chatId, '❌ 你不是管理員。');
    const rest = text.slice(3).trim();
    if (rest) {
      const codes = rest.split('\n').flatMap(l=>l.split(/[\s,;]+/)).map(c=>c.trim()).filter(c=>c.length>=CODE_MIN_LEN);
      let added=0;
      for (const c of codes) { if (!db.inventory.some(i=>i.code===c)) { db.inventory.push({code:c, usedBy:null, usedAt:null, createdAt:new Date().toISOString()}); added++; } }
      if (added) { saveDb(db); }
      return sendMessage(chatId, `✅ 已添加 <b>${added}</b> 個。📦 可用：${db.inventory.filter(i=>!i.usedBy).length}`);
    }
    suSessions.add(chatId);
    return sendMessage(chatId, `📦 <b>已進入添加庫存模式</b>\n\n請傳送邀請碼，一行一個。完成後發 /done 或 /cancel 退出。`);
  }
  if (/^\/(done|cancel)$/i.test(text)) {
    if (userId!==adminUserId) return;
    if (suSessions.has(chatId)) { suSessions.delete(chatId); return sendMessage(chatId, `✅ 已退出。📦 可用：${db.inventory.filter(i=>!i.usedBy).length}`); }
    return;
  }
  // SU mode — parse codes from plain text
  if (suSessions.has(chatId) && userId===adminUserId) {
    const codes = text.split('\n').map(c=>c.trim()).filter(c=>c.length>=CODE_MIN_LEN);
    let added=0;
    for (const c of codes) { if (!db.inventory.some(i=>i.code===c)) { db.inventory.push({code:c, usedBy:null, usedAt:null, createdAt:new Date().toISOString()}); added++; } }
    if (added) { saveDb(db); }
    return sendMessage(chatId, added ? `✅ 已添加 <b>${added}</b> 個。📦 可用：${db.inventory.filter(i=>!i.usedBy).length}` : '⚠️ 無新有效碼。');
  }

  // Duplicate check
  const existing = db.applications.find(a=>a.telegramUserId===userId);
  if (existing) {
    const msgs = { pending:'⏳ 審核中。', approved:'✅ 已通過！', rejected:'❌ 未通過。' };
    return sendMessage(chatId, msgs[existing.status]||'❓');
  }

  // Save application
  const app = { id:Date.now(), telegramUserId:userId, telegramUsername:uname||null, firstName:fn||null, lastName:ln||null, essay:text, status:'pending', createdAt:new Date().toISOString(), processedAt:null, processedBy:null };
  db.applications.push(app); saveDb(db);

  await sendMessage(chatId, '✅ 你的申請已提交，請等待管理員審核。');
  if (adminUserId) {
    await sendMessage(adminUserId,
`🆕 <b>新申請</b>
👤 ${display}${uname?` (@${uname})`:''}
🆔 <code>${userId}</code>

<b>小作文：</b>
${text}`, { reply_markup:{ inline_keyboard:[[ { text:'✅ 批准', callback_data:`approve:${userId}:${app.id}` }, { text:'❌ 駁回', callback_data:`reject:${userId}:${app.id}` } ]] } });
  }
}

// ── Handle callbacks ──────────────────────────────────────────────
async function handleCallbackQuery(cb) {
  const [action, strUserId, strAppId] = cb.data.split(':');
  const userId = Number(strUserId), appId = Number(strAppId);
  const msg = cb.message, chatId = msg.chat.id, msgId = msg.message_id;

  if (cb.from.id !== adminUserId) return answerCbq(cb.id, '❌ 你不是管理員', true);

  const app = db.applications.find(a=>a.id===appId && a.telegramUserId===userId);
  if (!app) return answerCbq(cb.id, '❌ 申請不存在', true);
  if (app.status!=='pending') return answerCbq(cb.id, `⚠️ 已${app.status==='approved'?'批准':'駁回'}`, false);

  if (action === 'approve') {
    const avail = db.inventory.find(c=>!c.usedBy);
    if (!avail) return answerCbq(cb.id, '⚠️ 庫存不足！請先用 /su 補充', true);
    avail.usedBy = userId; avail.usedAt = new Date().toISOString();
    app.status='approved'; app.processedAt=new Date().toISOString(); app.processedBy=adminUserId;
    saveDb(db);
    await sendMessage(userId, `✅ <b>你的申請已通過！</b>\n\n這是你的 Incudal 邀請碼：\n<code>${avail.code}</code>\n\n前往 https://incudal.di0.uk 註冊使用。`);
    const rem = db.inventory.filter(c=>!c.usedBy).length;
    await editMsg(chatId, msgId, `✅ <b>已批准</b>\n👤 ${app.firstName||''} ${app.lastName||''}${app.telegramUsername?` (@${app.telegramUsername})`:''}\n🆔 <code>${userId}</code>\n\n📦 庫存剩餘：${rem} 個`, { reply_markup:{ inline_keyboard:[] } });
    await answerCbq(cb.id, '✅ 已批准，邀請碼已發送');
  } else if (action === 'reject') {
    app.status='rejected'; app.processedAt=new Date().toISOString(); app.processedBy=adminUserId;
    saveDb(db);
    await sendMessage(userId, '❌ 你的申請未通過。');
    await editMsg(chatId, msgId, `❌ <b>已駁回</b>\n👤 ${app.firstName||''} ${app.lastName||''}${app.telegramUsername?` (@${app.telegramUsername})`:''}\n🆔 <code>${userId}</code>`, { reply_markup:{ inline_keyboard:[] } });
    await answerCbq(cb.id, '❌ 已駁回');
  }
}

// ── Poll loop ─────────────────────────────────────────────────────
async function poll() {
  console.log(`🤖 Bot started. Admin: ${adminUserId||'not set'}`);
  while (true) {
    try {
      const data = await getUpdates(lastUpdateId);
      if (data.ok && data.result.length > 0) {
        for (const u of data.result) {
          lastUpdateId = u.update_id + 1;
          if (u.message) await handleMessage(u.message);
          else if (u.callback_query) await handleCallbackQuery(u.callback_query);
        }
      }
      if (++heartBeat % 600 === 0) console.log(`[hb] Inv:${db.inventory.filter(i=>!i.usedBy).length} Pending:${db.applications.filter(a=>a.status==='pending').length}`);
    } catch(e) { console.error('Poll:', e.message); await new Promise(r=>setTimeout(r,5000)); }
  }
}

process.on('SIGINT',()=>{console.log('Bye');process.exit(0);});
process.on('SIGTERM',()=>{console.log('Bye');process.exit(0);});
poll().catch(e=>{console.error('FATAL:',e);process.exit(1);});
