const express =require('express')
const path = require('path')
const { default: mongoose } = require('mongoose')
const cors=require('cors')
const dotenv=require('dotenv')
const rateLimit=require('express-rate-limit')


dotenv.config()

const app=express()
const publicDir = path.join(__dirname, 'public')

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
app.use(express.static(publicDir))

app.get('/protected/:code', (req, res) => {
  res.sendFile(path.join(publicDir, 'protected.html'))
})

const limiter=rateLimit({
  windowMs:60*60*1000,
  max:100,
  message:{error:'Too many requests, please try again after an hour'}
})
app.use('/shorten',limiter)

app.use('/auth',require('./routes/auth'))

app.use('/',require('./routes/url'))

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB Connected!')
    app.listen(process.env.PORT, () => {
      console.log(`🚀 Server running on port ${process.env.PORT}`)
    })
  })
  .catch((err) => {
    console.log('❌ Connection failed:', err)
  })
