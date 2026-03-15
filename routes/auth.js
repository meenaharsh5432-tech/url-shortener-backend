const express = require('express')
const router = express.Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../models/User')
const { OAuth2Client } = require('google-auth-library')
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)

// ====================================
// POST /auth/google → Google Sign In
// ====================================
router.post('/google', async (req, res) => {
  const { credential } = req.body

  try {
    // Verify Google token
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    })

    const payload = ticket.getPayload()
    const { email, name, sub } = payload

    // Check if user exists
    let user = await User.findOne({ email })

    if (!user) {
      // Create new user
      user = new User({
        username: name,
        email,
        password: sub // use Google ID as password (won't be used)
      })
      await user.save()
    }

    // Create JWT token
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
 console.log('Register route hit!')
 
  const { username, email, password } = req.body
 console.log('Body:', username, email, password) 
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' })
  }
  try {
    console.log('Trying to find user...')
    const existingUser = await User.findOne({ email })
     console.log('Found user:', existingUser)
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    console.log('Password hashed!')
    const user = new User({
      username,
      email,
      password: hashedPassword
    })
    console.log('User object created!') 
    await user.save()
    console.log('User saved!') 

    res.json({ message: '✅ Account created successfully!' })
  } catch (err) {
    console.log('Full error:', err.message)
    console.log('Error code:', err.code)
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
  }  catch (err) {
  console.log('Full error:', err.message)
  console.log('Error code:', err.code)
  res.status(500).json({ error: err.message })
}
})

module.exports = router