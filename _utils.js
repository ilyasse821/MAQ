const { MongoClient } = require('mongodb');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// يعيد استخدام نفس الاتصال بين استدعاءات الفنكشن (Netlify يحافظ على الحاوية أحيانًا) بدل فتح اتصال جديد كل مرة
let cachedClient = null;

async function getDb() {
  if (cachedClient) return cachedClient.db('maq_security');
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI غير مضبوط في متغيرات بيئة Netlify.');
  const client = new MongoClient(process.env.MONGODB_URI);
  await client.connect();
  cachedClient = client;
  return client.db('maq_security');
}

function verifyAuth(event) {
  const cookieHeader = event.headers.cookie || event.headers.Cookie || '';
  const match = cookieHeader.match(/maq_session=([^;]+)/);
  if (!match) return null;
  try {
    return jwt.verify(decodeURIComponent(match[1]), process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

function jsonResponse(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Credentials': 'true',
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  };
}

// --- تشفير الرقم السري (PIN) لتخزينه بقاعدة البيانات بدل نص واضح ---
function hashPin(pin) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(pin), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPinHash(pin, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(String(pin), salt, 64).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
  } catch {
    return false;
  }
}

// يتحقق من رقم سري: يقارن بالنسخة المحفوظة بقاعدة البيانات إن وُجدت، وإلا يرجع
// لـ DASHBOARD_PIN من متغيرات البيئة كبداية (أول مرة قبل أي تغيير من الداشبورد)
async function checkPin(db, pin) {
  const authDoc = await db.collection('dashboardAuth').findOne({ _id: 'pin' });
  if (authDoc) return verifyPinHash(pin, authDoc.hash);
  return String(pin) === String(process.env.DASHBOARD_PIN || '');
}

async function setPin(db, pin) {
  await db.collection('dashboardAuth').updateOne({ _id: 'pin' }, { $set: { hash: hashPin(pin), updatedAt: new Date() } }, { upsert: true });
}

module.exports = { getDb, verifyAuth, jsonResponse, checkPin, setPin };
