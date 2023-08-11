const sha1 = require('js-sha1')
const crypto = require('crypto')

// hmac utils /////////////////////////////////////////////////////////////////

const buf2hex = buf =>
  Buffer.from(buf).toString('hex')

const hex2buf = hex =>
  Buffer.from(hex, 'hex')

const bufs2buf = (a, b) =>
  Buffer.concat([a, b])

// returns hex
const gen_key = () => {
  const arr = crypto.getRandomValues(new Uint8Array(16))
  return buf2hex(arr)
}

// expects hex, returns hex
const pad = (hex, siz) =>
  hex.padEnd(siz, '0')

// expects buffer, returns hex
const compute_sized_key = (key, hash, siz) =>
    key.length > siz ?
    hash(key) :
    key.length < siz ?
    pad(buf2hex(key), siz * 2) : // bytes, not length
    buf2hex(key)

// expects hex, returns hex
const hmac_sha1 = (k, m) => {
  const bk = hex2buf(k)
  const bm = hex2buf(m)

  const sized_key = hex2buf(compute_sized_key(bk, sha1, 64))

  const okey_pad = sized_key.map(x => x ^ 0x5c)
  const ikey_pad = sized_key.map(x => x ^ 0x36)

  const inner  = bufs2buf(ikey_pad, bm)
  const hinner = hex2buf(sha1(inner))
  const outer  = bufs2buf(okey_pad, hinner)

  return sha1(outer)
}

const verify_hmac_sha1 = (key, msg, mac) =>
  hmac_sha1(key, msg) == mac

async function insecure_compare(key, msg, mac) {
  const bcal = Buffer.from(hmac_sha1(key, msg), 'hex')
  const bmac = Buffer.from(mac, 'hex')

  const idxs = Array(bcal.length).fill().map((el, idx) => idx)

  for await (const idx of idxs) {
    if (bcal[idx] != bmac[idx]) {
      return false
    }
    await new Promise(r => setTimeout(r, 50))
  }

  return true
}

module.exports = {
  gen_key,
  hmac_sha1,
  verify_hmac_sha1,
  insecure_compare
}
