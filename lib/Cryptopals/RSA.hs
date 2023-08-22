module Cryptopals.RSA (
    Key(..)
  , Keypair(..)
  , keygen

  , bitl

  , unroll
  , roll
  , unroll'
  , roll'

  , invmod
  , invmod'

  , encrypt
  , decrypt

  , pkcs1v1p5encode
  , pkcs1v1p5verify
  , asnSha512
  , asnSha1

  , sign
  , verify
  ) where

import qualified Cryptopals.DH as DH
import qualified Cryptopals.Digest.Pure.SHA as CS
import qualified Crypto.Number.Prime as P
import qualified Data.Binary as DB
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Math.NumberTheory.Logarithms as L
import Numeric.Natural

-- bit length
bitl :: Natural -> Int
bitl (fromIntegral -> n)
  | n > 0     = succ . L.integerLog2' $ n
  | otherwise = 0

-- big-endian natural encoding
unroll :: Natural -> BS.ByteString
unroll nat = case nat of
    0 -> BS.singleton 0
    _ -> BS.reverse $ BS.unfoldr step nat
  where
    step 0 = Nothing
    step i = Just (fromIntegral i, i `B.shiftR` 8)

-- big-endian bytestring decoding
roll :: BS.ByteString -> Natural
roll = BS.foldl' unstep 0 where
  unstep a b = a `B.shiftL` 8 B..|. fromIntegral b

-- little-endian natural encoding
unroll' :: Natural -> BS.ByteString
unroll' nat = case nat of
    0 -> BS.singleton 0
    _ -> BS.unfoldr step nat
  where
    step 0 = Nothing
    step i = Just (fromIntegral i, i `B.shiftR` 8)

-- little-endian bytestring decoding
roll' :: BS.ByteString -> Natural
roll' = BS.foldr unstep 0 where
  unstep b a = a `B.shiftL` 8 B..|. fromIntegral b

-- egcd/invmod adapted from https://rosettacode.org/wiki/Modular_inverse

-- for a, b, return x, y, g such that ax + by = g for g = gcd(a, b)
egcd :: Integer -> Integer -> (Integer, Integer, Integer)
egcd a 0 = (1, 0, a)
egcd a b =
  let (q, r)    = a `quotRem` b
      (s, t, g) = egcd b r
  in  (t, s - q * t, g)

-- for a, m return x such that ax = 1 mod m
invmod :: Natural -> Natural -> Maybe Natural
invmod (fromIntegral -> a) (fromIntegral -> m)
    | g == 1    = Just (pos i)
    | otherwise = Nothing
  where
    (i, _, g) = egcd a m
    pos x
      | x < 0     = fromIntegral (x + m)
      | otherwise = fromIntegral x

-- unsafe invmod
invmod' :: Natural -> Natural -> Natural
invmod' a m = case invmod a m of
  Just x  -> x
  Nothing -> error "invmod': no modular inverse"

data Key =
    Sec Natural Natural
  | Pub Natural Natural
  deriving (Eq, Show)

data Keypair = Keypair {
    sec :: Key
  , pub :: Key
  } deriving (Eq, Show)

keygen :: Int -> IO Keypair
keygen siz = loop where
  loop = do
    p <- fromIntegral <$> P.generatePrime siz
    q <- fromIntegral <$> P.generatePrime siz
    let n   = p * q
        et  = pred p * pred q
        e   = 3
        md  = invmod e et
    case md of
      Nothing -> loop
      Just d  -> pure $ Keypair (Sec d n) (Pub e n)

-- XX padding for crypt ops / other hash functions for signatures

encrypt :: Key -> BS.ByteString -> BS.ByteString
encrypt key msg = case key of
  Sec {}  -> error "encrypt: need public key"
  Pub e n -> unroll (DH.modexp (roll msg) e n)

decrypt :: Key -> BS.ByteString -> BS.ByteString
decrypt key cip = case key of
  Pub {}  -> error "decrypt: need secret key"
  Sec d n -> unroll (DH.modexp (roll cip) d n)

-- sign using SHA512
sign :: Key -> BS.ByteString -> (BS.ByteString, BS.ByteString)
sign key msg = case key of
  Pub {}  -> error "sign: need secret key"
  Sec d n ->
    let padded = pkcs1v1p5encode key msg
    in  (msg, unroll (DH.modexp (roll padded) d n))

-- verify using broken pkcs1 (SHA512) verification
verify :: Key -> BS.ByteString -> BS.ByteString -> Bool
verify key msg sig = case key of
  Sec {}  -> error "verify: need public key"
  Pub e n ->
    let h = BL.toStrict $ CS.bytestringDigest (CS.sha512 (BL.fromStrict msg))
        r = DH.modexp (roll sig) e n
    in  case pkcs1v1p5verify (BS.cons 0 (unroll r)) of -- BE-storage hack
          Nothing -> False
          Just l  -> h == l

-- pkcs#1 v1.5-encode a message (using SHA512)
pkcs1v1p5encode :: Key -> BS.ByteString -> BS.ByteString
pkcs1v1p5encode key msg =
    BS.cons 0x00 (BS.snoc (BS.cons 0x01 ffs) 0x00) <> asnSha512 <> has
  where
    siz = case key of
      Pub _ n -> BS.length (unroll n)
      Sec _ n -> BS.length (unroll n)
    len = fromIntegral siz - (3 + BS.length (asnSha512 <> has))
    ffs = BS.replicate len 0xff
    has = BL.toStrict $ CS.bytestringDigest (CS.sha512 (BL.fromStrict msg))

-- sloppy pkcs#1 v1.5 verification (SHA512); doesn't verify the length
-- of the padding
pkcs1v1p5verify :: BS.ByteString -> Maybe BS.ByteString
pkcs1v1p5verify = checknul where
  checknul bs = case BS.uncons bs of
    Nothing -> Nothing
    Just (w, etc)
      | w == 0x00 -> checksoh etc
      | otherwise -> Nothing

  checksoh bs = case BS.uncons bs of
    Nothing -> Nothing
    Just (w, etc)
      | w == 0x01 -> check255 etc
      | otherwise -> Nothing

  check255 bs = case BS.uncons bs of
    Nothing -> Nothing
    Just (w, etc)
      | w == 0xff -> check255 etc
      | w == 0x00 -> checkasn asnSha512 etc
      | otherwise -> Nothing

  checkasn asn bs = case BS.uncons bs of
    Nothing -> Nothing
    Just (w, etc) -> case BS.uncons asn of
      Nothing -> checkhash bs
      Just (h, t)
        | w == h    -> checkasn t etc
        | otherwise -> Nothing

  checkhash bs =
    let has = BS.take 64 bs
    in  if   BS.length has == 64
        then pure has
        else Nothing

-- ASN.1 encoding of SHA512
asnSha512 :: BS.ByteString
asnSha512 = BS.pack [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48
  , 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04
  , 0x40
  ]

-- ASN.1 encoding of SHA1
asnSha1 :: BS.ByteString
asnSha1 = BS.pack [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03
  , 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
  ]
