module Cryptopals.RSA (
    Key(..)
  , Keypair(..)
  , keygen

  , unroll
  , roll

  , invmod
  , encrypt
  , decrypt
  ) where

import qualified Cryptopals.DH as DH
import qualified Crypto.Number.Prime as P
import qualified Data.Binary as DB
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import Data.List (unfoldr)
import qualified Data.Maybe as M
import qualified Math.NumberTheory.Roots as R
import Numeric.Natural

-- | Simple little-endian ByteString encoding for Naturals.
unroll :: Natural -> BS.ByteString
unroll nat = case nat of
    0 -> BS.singleton 0
    _ -> BS.pack (unfoldr step nat)
  where
    step 0 = Nothing
    step i = Just (fromIntegral i, i `B.shiftR` 8)

-- | Simple little-endian ByteString decoding for Naturals.
roll :: BS.ByteString -> Natural
roll = foldr unstep 0 . BS.unpack where
  unstep b a = a `B.shiftL` 8 B..|. fromIntegral b

-- egcd/invmod adapted from https://rosettacode.org/wiki/Modular_inverse

-- for a, b, return x, y, g such that ax + by = g for g = gcd(a, b)
egcd :: Integer -> Integer -> (Integer, Integer, Integer)
egcd a 0 = (1, 0, a)
egcd a b =
  let (q, r) = a `quotRem` b
      (s, t, g) = egcd b r
  in (t, s - q * t, g)

-- for a, m return x such that ax = 1 mod m
invmod :: Natural -> Natural -> Maybe Natural
invmod (fromIntegral -> a) (fromIntegral -> m)
    | 1 == g    = Just (pos i)
    | otherwise = Nothing
  where
    (i, _, g) = egcd a m
    pos x
      | x < 0     = fromIntegral (x + m)
      | otherwise = fromIntegral x

data Key = Key Natural Natural
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
      Just d  -> pure $ Keypair (Key d n) (Key e n)

encrypt :: Key -> BS.ByteString -> BS.ByteString
encrypt (Key e n) m = unroll (DH.modexp (roll m) e n)

decrypt :: Key -> BS.ByteString -> BS.ByteString
decrypt = encrypt

