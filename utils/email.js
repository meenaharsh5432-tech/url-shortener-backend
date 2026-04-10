const { Resend } = require('resend')

const resend = new Resend(process.env.RESEND_API_KEY)

async function sendVerificationEmail(toEmail, username, token) {
  const verifyUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`

  await resend.emails.send({
    from: process.env.EMAIL_FROM || 'Cuts.ink <noreply@cuts.ink>',
    to: toEmail,
    subject: 'Verify your Cuts.ink account',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px">
        <h2 style="margin:0 0 8px">Hey ${username},</h2>
        <p style="color:#555;margin:0 0 24px">Thanks for signing up. Click the button below to verify your email address.</p>
        <a href="${verifyUrl}"
           style="display:inline-block;padding:14px 28px;background:#cb5f35;color:#fff;border-radius:999px;text-decoration:none;font-weight:600">
          Verify email
        </a>
        <p style="color:#888;font-size:13px;margin-top:24px">
          This link expires in 24 hours. If you didn't create an account, you can ignore this email.
        </p>
      </div>
    `
  })
}

module.exports = { sendVerificationEmail }
