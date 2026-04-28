const express = require('express')
const router = express.Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const User = require('../models/User')
const { sendVerificationEmail } = require('../utils/email')
const { OAuth2Client } = require('google-auth-library')
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)

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
      const randomPassword = crypto.randomBytes(16).toString('hex')
      const hashedPassword = await bcrypt.hash(randomPassword, 10)

      user = new User({
        username: name,
        email,
        password: hashedPassword,
        isGoogleUser: true
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
    const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000)

    const user = new User({
      username,
      email,
      password: hashedPassword,
      verificationToken,
      verificationTokenExpires
    })
    await user.save()

    await sendVerificationEmail(email, username, verificationToken)

    res.json({ message: '✅ Account created! Please check your email to verify your account.' })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
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
    if (!user.isVerified) {
      return res.status(403).json({ error: 'Please verify your email before logging in' })
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password' })
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

router.get('/verify-email', async (req, res) => {
  const { token } = req.query

  if (!token) {
    return res.status(400).json({ error: 'Verification token is required' })
  }

  try {
    const user = await User.findOne({
      verificationToken: token,
      verificationTokenExpires: { $gt: new Date() }
    })

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification link' })
    }

    user.isVerified = true
    user.verificationToken = undefined
    user.verificationTokenExpires = undefined
    await user.save()

    res.json({ message: '✅ Email verified successfully! You can now log in.' })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

router.post('/resend-verification', async (req, res) => {
  const { email } = req.body

  if (!email) {
    return res.status(400).json({ error: 'Email is required' })
  }

  try {
    const user = await User.findOne({ email })

    if (!user) {
      // Return success anyway to avoid email enumeration
      return res.json({ message: 'If that email exists, a verification link has been sent.' })
    }

    if (user.isVerified) {
      return res.status(400).json({ error: 'This account is already verified' })
    }

    const verificationToken = crypto.randomBytes(32).toString('hex')
    user.verificationToken = verificationToken
    user.verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000)
    await user.save()

    await sendVerificationEmail(email, user.username, verificationToken)

    res.json({ message: 'Verification email sent! Please check your inbox.' })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

module.exports = router