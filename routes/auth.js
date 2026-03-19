const express = require('express')
const router = express.Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const { Resend } = require('resend')
const User = require('../models/User')
const { OAuth2Client } = require('google-auth-library')
const authMiddleware = require('../middleware/auth')
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)

const resend = new Resend(process.env.RESEND_API_KEY)

async function sendWelcomeEmail(email, name) {
  const setPasswordUrl = `${(process.env.FRONTEND_URL || '').replace(/\/$/, '')}/dashboard`
  await resend.emails.send({
    from: 'cuts.ink <onboarding@resend.dev>',
    to: email,
    subject: 'Welcome to cuts.ink!',
    html: `
      <p>Hi ${name},</p>
      <p>Welcome to <strong>cuts.ink</strong>! Your account has been created using Google Sign In.</p>
      <p>You can start shortening links right away. If you'd also like to log in with email and password, visit your dashboard and click <strong>"Set Password"</strong>.</p>
      <a href="${setPasswordUrl}">Go to Dashboard</a>
      <p>Thanks for joining!</p>
    `
  })
}

async function sendVerificationEmail(email, token) {
  const backendUrl = (process.env.BACKEND_URL || '').replace(/\/$/, '')
  const verifyUrl = `${backendUrl}/auth/verify-email/${token}`
  await resend.emails.send({
    from: 'cuts.ink <onboarding@resend.dev>',
    to: email,
    subject: 'Verify your email - cuts.ink',
    html: `
      <p>Thanks for signing up!</p>
      <p>Click the link below to verify your email address. This link expires in 24 hours.</p>
      <a href="${verifyUrl}">${verifyUrl}</a>
      <p>If you did not create an account, you can ignore this email.</p>
    `
  })
}

router.post('/google', async (req, res) => {
  const { credential } = req.body

  try {
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    })

    const payload = ticket.getPayload()
    const { email, name } = payload

    // Check if user exists with this email
    let user = await User.findOne({ email })

    if (!user) {
      const randomPassword = Math.random().toString(36).slice(-8)
      const hashedPassword = await bcrypt.hash(randomPassword, 10)

      let username = name
      const existing = await User.findOne({ username })
      if (existing) username = `${name}${Math.random().toString(36).slice(-4)}`

      user = new User({
        username,
        email,
        password: hashedPassword,
        isVerified: true,
        isGoogleUser: true
      })
      await user.save()

      sendWelcomeEmail(email, name).catch(err => console.error('Failed to send welcome email:', err))
    }

    // Create JWT token — works for both existing and new users!
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    )

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isGoogleUser: user.isGoogleUser || false
      }
    })

  } catch (err) {
    console.log('Google auth error:', err)
    res.status(401).json({ error: 'Google authentication failed' })
  }
})
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' })
  }
  try {
    const existingUser = await User.findOne({ email })
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const verificationToken = crypto.randomBytes(32).toString('hex')
    const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours

    const user = new User({
      username,
      email,
      password: hashedPassword,
      verificationToken,
      verificationTokenExpires
    })
    await user.save()

    // Send email in background — don't block the response
    sendVerificationEmail(email, verificationToken).catch(err =>
      console.error('Failed to send verification email:', err)
    )

    res.json({ message: 'Account created! Please check your email to verify your account.' })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Server error' })
  }
})

router.get('/verify-email/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      verificationToken: req.params.token,
      verificationTokenExpires: { $gt: new Date() }
    })

    if (!user) {
      return res.redirect(`${process.env.FRONTEND_URL}/login?error=invalid-or-expired-link`)
    }

    user.isVerified = true
    user.verificationToken = undefined
    user.verificationTokenExpires = undefined
    await user.save()

    res.redirect(`${process.env.FRONTEND_URL}/login?verified=true`)
  } catch (err) {
    console.error(err)
    res.redirect(`${process.env.FRONTEND_URL}/login?error=server-error`)
  }
})

router.post('/login', async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ error: 'All fields are required' })
  }
  try {
    const user = await User.findOne({ email })

    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' })
    }
    const isMatch = await bcrypt.compare(password, user.password)

    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password' })
    }

    if (user.isVerified === false) {
      return res.status(403).json({ error: 'Please verify your email before logging in.' })
    }

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    )
    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password -verificationToken -resetPasswordToken')
    if (!user) return res.status(404).json({ error: 'User not found' })
    res.json({ isGoogleUser: user.isGoogleUser || false })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

router.post('/forgot-password', async (req, res) => {
  const { email } = req.body
  if (!email) return res.status(400).json({ error: 'Email is required' })

  try {
    const user = await User.findOne({ email })
    // Always respond the same to prevent email enumeration
    if (!user) return res.json({ message: 'If that email exists, a reset link has been sent.' })

    const resetToken = crypto.randomBytes(32).toString('hex')
    user.resetPasswordToken = resetToken
    user.resetPasswordExpires = new Date(Date.now() + 60 * 60 * 1000) // 1 hour
    await user.save()

    const resetUrl = `${(process.env.FRONTEND_URL || '').replace(/\/$/, '')}/reset-password/${resetToken}`
    resend.emails.send({
      from: 'cuts.ink <onboarding@resend.dev>',
      to: email,
      subject: 'Reset your password - cuts.ink',
      html: `
        <p>You requested a password reset.</p>
        <p>Click the link below to set a new password. This link expires in 1 hour.</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>If you did not request this, you can ignore this email.</p>
      `
    }).catch(err => console.error('Failed to send reset email:', err))

    res.json({ message: 'If that email exists, a reset link has been sent.' })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Server error' })
  }
})

router.post('/reset-password/:token', async (req, res) => {
  const { password } = req.body
  if (!password) return res.status(400).json({ error: 'Password is required' })

  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: new Date() }
    })

    if (!user) return res.status(400).json({ error: 'Reset link is invalid or has expired.' })

    user.password = await bcrypt.hash(password, 10)
    user.resetPasswordToken = undefined
    user.resetPasswordExpires = undefined
    await user.save()

    res.json({ message: 'Password reset successfully. You can now log in.' })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Server error' })
  }
})

router.post('/change-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body
  if (!newPassword) return res.status(400).json({ error: 'New password is required' })

  try {
    const user = await User.findById(req.user.userId)

    if (!user.isGoogleUser) {
      if (!currentPassword) return res.status(400).json({ error: 'Current password is required' })
      const isMatch = await bcrypt.compare(currentPassword, user.password)
      if (!isMatch) return res.status(400).json({ error: 'Current password is incorrect' })
    }

    user.password = await bcrypt.hash(newPassword, 10)
    user.isGoogleUser = false // now has a real password
    await user.save()

    res.json({ message: 'Password set successfully.' })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Server error' })
  }
})

module.exports = router