const express = require('express')
const { default: mongoose } = require('mongoose')
const cors = require('cors')
const dotenv = require('dotenv')
const rateLimit = require('express-rate-limit')
const helmet = require('helmet')

dotenv.config()

const app = express()

app.set('trust proxy', 1)

app.use(helmet())
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:3001',
    'https://cuts.ink',
    'https://www.cuts.ink',
    'https://url-shortener-frontend-five-nu.vercel.app'
  ],
  credentials: true
}))
app.use(express.json())

const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again after an hour' }
})
app.use('/shorten', limiter)

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts, please try again in 15 minutes' }
})
app.use('/auth/login', authLimiter)

app.use('/auth',require('./routes/auth'))

app.use('/',require('./routes/url'))

const PORT = process.env.PORT || 5000

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB Connected!')
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`)
    })
  })
  .catch((err) => {
    console.error('❌ Connection failed:', err)
    process.exit(1)
  })
