// فنكشن واحدة تجمع كل عمليات الداشبورد (بدل ملف منفصل لكل عملية) لتقليل تكرار
// كود الاتصال بقاعدة البيانات والتحقق من الجلسة. التوجيه يتم عبر body.action.
const { getDb, verifyAuth, checkPin, setPin, jsonResponse } = require('./_utils');

const SETTINGS_FIELDS = ['protections', 'whitelist', 'helpAllowedRoles', 'backupAllowedUsers', 'punishment', 'logChannelId'];

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return jsonResponse(405, { error: 'Method not allowed' });

  const auth = verifyAuth(event);
  if (!auth) return jsonResponse(401, { error: 'يرجى تسجيل الدخول' });

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return jsonResponse(400, { error: 'بيانات غير صالحة' });
  }

  if (body.action === 'logout') {
    return jsonResponse(200, { ok: true }, { 'Set-Cookie': 'maq_session=; HttpOnly; Path=/; Max-Age=0' });
  }

  let db;
  try {
    db = await getDb();
  } catch (e) {
    return jsonResponse(500, { error: e.message });
  }
  const { guildId } = auth;

  switch (body.action) {
    case 'get-config': {
      const [settings, panic, attackers] = await Promise.all([
        db.collection('guildSettings').findOne({ guildId }),
        db.collection('panicStates').findOne({ guildId }),
        db.collection('activeAttackers').find({ guildId }).toArray(),
      ]);
      return jsonResponse(200, { settings: settings || null, panic: panic || { active: false }, attackers });
    }

    case 'update-settings': {
      const update = {};
      for (const field of SETTINGS_FIELDS) if (body[field] !== undefined) update[field] = body[field];
      if (!Object.keys(update).length) return jsonResponse(400, { error: 'لا يوجد شيء لتحديثه' });
      await db
        .collection('guildSettings')
        .updateOne({ guildId }, { $set: { ...update, guildId, updatedAt: new Date(), updatedBy: 'dashboard' } }, { upsert: true });
      return jsonResponse(200, { ok: true });
    }

    case 'panic': {
      if (!['activate', 'restore'].includes(body.panicAction)) return jsonResponse(400, { error: 'إجراء غير معروف' });
      await db.collection('panicCommands').insertOne({
        guildId,
        action: body.panicAction,
        targetUserId: body.targetUserId || null,
        processed: false,
        requestedAt: new Date(),
      });
      return jsonResponse(200, { ok: true, message: 'تم إرسال الأمر، البوت سينفذه خلال ثوانٍ (تأكد إنه أونلاين).' });
    }

    case 'change-pin': {
      const { currentPin, newPin } = body;
      if (!currentPin || !newPin) return jsonResponse(400, { error: 'أدخل الرقم الحالي والرقم الجديد' });
      if (String(newPin).length < 4) return jsonResponse(400, { error: 'الرقم الجديد لازم يكون 4 أرقام/رموز على الأقل' });
      const currentValid = await checkPin(db, currentPin);
      if (!currentValid) return jsonResponse(401, { error: 'الرقم الحالي غير صحيح' });
      await setPin(db, newPin);
      return jsonResponse(200, { ok: true, message: 'تم تغيير الرقم السري بنجاح — استخدمه بالمرة الجاية.' });
    }

    default:
      return jsonResponse(400, { error: 'إجراء غير معروف' });
  }
};
