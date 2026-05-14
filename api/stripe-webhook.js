/**
 * KYUBI — Stripe Webhook → Token Generator
 * Deploy to Vercel (free tier), set env vars, done.
 *
 * Flow:
 *  1. Coach pays on Stripe Payment Link (with ?client_reference_id=coach_id)
 *  2. Stripe sends webhook here
 *  3. We verify signature, generate HMAC token, email it to coach
 *  4. Coach pastes token in KYUBI dashboard → credits confirmed
 */

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const crypto = require('crypto');
const { Resend } = require('resend');
const getRawBody = require('raw-body');

const HMAC_SECRET    = process.env.HMAC_SECRET;
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const RESEND_KEY     = process.env.RESEND_API_KEY;
const FROM_EMAIL     = process.env.FROM_EMAIL || 'KYUBI <noreply@kyubi.app>';

// Paliers bonus — identique au dashboard
const PALIERS = [
  [500, 0.50], [250, 0.25], [100, 0.20],
  [50,  0.15], [25,  0.12], [10,  0.10],
];

function chakraForEuros(euros) {
  const base = euros * 100;
  for (const [min, bonus] of PALIERS) {
    if (euros >= min) return Math.floor(base * (1 + bonus));
  }
  return Math.floor(base);
}

function generateToken(coachId, chakra, ttlSec = 259200) {
  const nonce   = crypto.randomBytes(8).toString('hex');
  const expires = Math.floor(Date.now() / 1000) + ttlSec;
  const payload = `1|${coachId}|${chakra}|${expires}|${nonce}`;
  const sig     = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
  return `${payload}|${sig}`;
}

// Vercel config — raw body needed for Stripe sig verification
module.exports.config = { api: { bodyParser: false } };

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Read raw body
  let rawBody;
  try {
    rawBody = await getRawBody(req, { encoding: 'utf8' });
  } catch (e) {
    return res.status(400).json({ error: 'Cannot read body' });
  }

  // Verify Stripe signature
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(rawBody, sig, WEBHOOK_SECRET);
  } catch (err) {
    console.error('[KYUBI] Stripe sig error:', err.message);
    return res.status(400).json({ error: `Webhook error: ${err.message}` });
  }

  // Only handle completed checkouts
  if (event.type !== 'checkout.session.completed') {
    return res.status(200).json({ received: true, skipped: event.type });
  }

  const session    = event.data.object;
  const coachId    = session.client_reference_id || 'unknown';
  const coachEmail = session.customer_details?.email || '';
  const euros      = (session.amount_total || 0) / 100;
  const chakra     = chakraForEuros(euros);
  const token      = generateToken(coachId, chakra);

  console.log(`[KYUBI] Payment ${euros}€ → ${chakra} Chakra → coach: ${coachId}`);

  // Send email with token
  if (RESEND_KEY && coachEmail) {
    try {
      const resend = new Resend(RESEND_KEY);
      await resend.emails.send({
        from: FROM_EMAIL,
        to:   coachEmail,
        subject: `🌀 Votre recharge KYUBI — ${chakra.toLocaleString('fr')} Chakra`,
        html: `
          <div style="font-family:system-ui,sans-serif;max-width:520px;margin:0 auto;padding:32px;background:#faf6f0">
            <div style="background:#2c1810;border-radius:12px;padding:20px;text-align:center;margin-bottom:24px">
              <span style="font-size:32px">キ</span>
              <div style="color:#c4a265;font-weight:700;font-size:18px;margin-top:4px">KYUBI System</div>
            </div>
            <h2 style="font-size:20px;color:#2c1810;margin-bottom:8px">🌀 Recharge confirmée</h2>
            <p style="color:#7a5c42;margin-bottom:24px">Paiement de <strong>${euros}€</strong> reçu — voici votre token de recharge.</p>
            <div style="background:#fff;border:1px solid #d4b87a;border-radius:10px;padding:18px;margin-bottom:20px">
              <p style="font-size:10px;font-weight:700;color:#7a5c42;margin:0 0 8px;text-transform:uppercase;letter-spacing:.07em">
                TOKEN DE RECHARGE (copier-coller dans KYUBI)
              </p>
              <code style="font-size:10px;word-break:break-all;color:#2c1810;line-height:1.6;display:block">${token}</code>
            </div>
            <div style="background:#f5f0e8;border-radius:8px;padding:14px;margin-bottom:20px;font-size:13px;color:#4a2e1e">
              <strong>Comment utiliser ce token :</strong><br>
              Dans KYUBI, cliquez sur <strong>🌀 Chakra</strong> en haut à droite<br>
              → Section <strong>"Code de recharge"</strong> → Coller → Valider<br><br>
              ✅ <strong>${chakra.toLocaleString('fr')} Chakra</strong> seront crédités immédiatement.
            </div>
            <p style="font-size:11px;color:#9a8060;text-align:center">
              Token valide 72h · Usage unique · KYUBI System
            </p>
          </div>
        `
      });
      console.log(`[KYUBI] Email envoyé à ${coachEmail}`);
    } catch (emailErr) {
      console.error('[KYUBI] Email error:', emailErr.message);
      // Don't fail the webhook even if email fails
    }
  }

  return res.status(200).json({ received: true, chakra, coachId });
};
