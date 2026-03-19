const express = require('express')
const router = express.Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const nodemailer = require('nodemailer')
const User = require('../models/User')
const { OAuth2Client } = require('google-auth-library')
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
})

async function sendVerificationEmail(email, token) {
  const verifyUrl = `${process.env.BACKEND_URL}/auth/verify-email/${token}`
  await transporter.sendMail({
    from: `"cuts.ink" <${process.env.EMAIL_USER}>`,
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
      // Create new user with random password
      const randomPassword = Math.random().toString(36).slice(-8)
      const hashedPassword = await bcrypt.hash(randomPassword, 10)
      
      user = new User({
        username: name,
        email,
        password: hashedPassword,
        isVerified: true
      })
      await user.save()
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
        email: user.email
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

    await sendVerificationEmail(email, verificationToken)

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

    if (!user.isVerified) {
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

module.exports = router