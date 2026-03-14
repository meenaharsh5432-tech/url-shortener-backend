const mongoose = require('mongoose')

const urlSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  password:{
    type:String,
    default: null
  },
  originalUrl: {
    type: String,
    required: true
  },
  shortCode: {
    type: String,
    required: true,
    unique: true
  },
  clicks: {
    type: Number,
    default: 0
  },
  deviceStats:{
    mobile:{type: Number, default: 0},
    desktop:{type: Number, default:0}
  },
  geoStats:{
    type:Map,
    of:Number,
    default:{}
  },
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
  }
}, { timestamps: true })

module.exports = mongoose.model('Url', urlSchema)