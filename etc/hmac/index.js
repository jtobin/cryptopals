const express = require('express')
const hmac = require('./hmac')

// web app ////////////////////////////////////////////////////////////////////

const sec = hmac.gen_key()

const app = express()

app.get('/', (req, res) => {
  res.send('waiting to do something cool..')
})

app.get('/hmac', async (req, res) => {
  const saf = req.query.safe
  const del = req.query.delay
  const fil = req.query.file
  const sig = req.query.signature

  const msg  = Buffer.from(fil).toString('hex')
  const safe = saf == "true"
  const wat  = parseInt(del, 10)

  const valid = safe
    ? hmac.verify_hmac_sha1(sec, msg, sig)
    : await hmac.insecure_compare(sec, msg, sig, wat)

  if (valid) {
    res.status(200).send({ 'HTTP': 200 })
  } else {
    res.status(500).send({ 'HTTP': 500 })
  }

})

const port = 3000

app.listen(port, () => {
  console.log(`server listening on ${port}`)
})

console.log('server generated the following key:')
console.log(`${sec}`)
console.log('for dev convenience, hmac for \'secrets.csv\' is:')
console.log(`${hmac.hmac_sha1(sec, Buffer.from('secrets.csv').toString('hex'))}`)

