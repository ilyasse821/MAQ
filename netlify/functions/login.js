const jwt = require('jsonwebtoken');
const { getDb, checkPin, jsonResponse } = require('./_utils');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return jsonResponse(405, { error: 'Method not allowed' });

  if (!process.env.JWT_SECRET) {
    return jsonResponse(500, { error: 'لوحة التحكم غير مُعدّة بعد: تأكد من ضبط JWT_SECRET في إعدادات Netlify.' });
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return jsonResponse(400, { error: 'بيانات غير صالحة' });
  }

  const { pin, guildId } = body;
  if (!pin || !guildId) {
    return jsonResponse(400, { error: 'الرقم السري ومعرف السيرفر (Guild ID) مطلوبان' });
  }

  let db;
  try {
    db = await getDb();
  } catch (e) {
    return jsonResponse(500, { error: e.message });
  }

  const valid = await checkPin(db, pin);
  if (!valid) return jsonResponse(401, { error: 'الرقم السري غير صحيح' });

  const token = jwt.sign({ guildId: String(guildId) }, process.env.JWT_SECRET, { expiresIn: '12h' });

  return jsonResponse(
    200,
    { ok: true },
    {
      'Set-Cookie': `maq_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`,
    }
  );
};
