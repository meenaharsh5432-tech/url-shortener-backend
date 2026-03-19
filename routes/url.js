
const express = require('express')
const router = express.Router()
const { nanoid } = require('nanoid')
const bcrypt = require('bcryptjs')
const Url = require('../models/Url')
const authMiddleware = require('../middleware/auth')
const geoip = require('geoip-lite')


router.post('/shorten', authMiddleware, async (req, res) => {
  const { originalUrl, customAlias, password } = req.body

  if (!originalUrl) {
    return res.status(400).json({ error: 'Please provide a URL' })
  }

  try {
    const shortCode = customAlias || nanoid(6)
    const existing = await Url.findOne({ shortCode })

    if (existing) {
      return res.status(400).json({ error: 'This Alias is Already Taken!' })
    }

    const expiresAt = new Date()
    expiresAt.setDate(expiresAt.getDate() + 30)

    let hashedPassword = null
    if (password) {
      hashedPassword = await bcrypt.hash(password, 10)
    }


    const url = new Url({
      userId: req.user.userId,    
      originalUrl,
      shortCode,
      expiresAt,
      password: hashedPassword
    })
    await url.save()

    res.json({
      originalUrl,
      shortUrl: `${process.env.BASE_URL}/${shortCode}`,
      shortCode
    })

  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

router.get('/myurls', authMiddleware, async (req, res) => {
  try {
    const urls = await Url.find({ userId: req.user.userId }).select('-password')
    res.json(urls)
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

router.delete('/:id', authMiddleware, async(req,res)=>{
  try{
    const url= await Url.findById(req.params.id)

    if(!url){
      return res.status(404).json({error:'URL not found'})
    }

    if(url.userId.toString()!==req.user.userId){
      return res.status(403).json({error: 'Not Authorized'})
    }
    await Url.findByIdAndDelete(req.params.id)
    res.json({message: 'URL Deleted Successfully'})

  }catch(err){
    res.status(500).json({error: 'Server Error'})
  }
})

router.get('/:code', async (req, res) => {
  const { code } = req.params

  try {
    const url = await Url.findOne({ shortCode: code })

    if (!url) {
      return res.status(404).json({ error: 'URL not found' })
    }

    if (new Date() > url.expiresAt) {
      return res.status(410).json({ error: 'URL has expired' })
    }

    // If password protected → redirect to password page
    if (url.password) {
      return res.redirect(`${process.env.FRONTEND_URL}/protected/${code}`)
    }

    const userAgent = req.headers['user-agent'] || ''
    const isMobile = /mobile|android|iphone|ipad/i.test(userAgent)

    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress
    const ip = rawIp.split(',')[0].trim().replace(/^::ffff:/, '')
    const geo = geoip.lookup(ip)
    const country = geo?.country || 'Unknown'

    url.clicks++
    if (isMobile) {
      url.deviceStats.mobile++
    } else {
      url.deviceStats.desktop++
    }
    const currentCount = url.geoStats.get(country) || 0
    url.geoStats.set(country, currentCount + 1)

    await url.save()

    res.redirect(url.originalUrl)

  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

router.post('/verify/:code', async (req, res) => {
  const { code } = req.params
  const { password } = req.body

  try {
    const url = await Url.findOne({ shortCode: code })
    if (!url) {
      return res.status(404).json({ error: 'URL not found' })
    }

    const isMatch = await bcrypt.compare(password, url.password)

    if (!isMatch) {
      return res.status(401).json({ error: 'Wrong Password' })
    }

    // Detect device
    const userAgent = req.headers['user-agent'] || ''
    const isMobile = /mobile|android|iphone|ipad/i.test(userAgent)

    // Detect country
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress
    const ip = rawIp.split(',')[0].trim().replace(/^::ffff:/, '')
    const geo = geoip.lookup(ip)
    const country = geo?.country || 'Unknown'

    // Update stats
    url.clicks++
    if (isMobile) {
      url.deviceStats.mobile++
    } else {
      url.deviceStats.desktop++
    }
    const currentCount = url.geoStats.get(country) || 0
    url.geoStats.set(country, currentCount + 1)

    await url.save()

    res.json({ originalUrl: url.originalUrl })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

module.exports = router