
module Cryptopals.DH (
    p
  , g
  , modexp

  , unroll
  , roll
  ) where

import Control.Monad.Primitive
import qualified Control.Monad.Trans.Reader as R
import qualified Cryptopals.Digest.Pure.SHA as S
import qualified Data.Binary.Get as BG
import qualified Data.Binary.Put as BP
import Data.Bits ((.|.))
import qualified Data.Bits as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.List as L
import Numeric.Natural
import qualified System.Random.MWC as MWC
import GHC.Word (Word16)

-- modified from https://gist.github.com/trevordixon/6788535
modexp :: Natural -> Natural -> Natural -> Natural
modexp b e m
  | e == 0    = 1
  | otherwise =
      let t = if B.testBit e 0 then b `mod` m else 1
      in  t * modexp ((b * b) `mod` m) (B.shiftR e 1) m `mod` m

-- little-endian natural serialization
unroll :: Natural -> BL.ByteString
unroll nat = case nat of
    0 -> BL.singleton 0
    _ -> BL.pack (L.unfoldr step nat)
  where
    step 0 = Nothing
    step i = Just (fromIntegral i, i `B.shiftR` 8)

roll :: BL.ByteString -> Natural
roll = foldr unstep 0 . BL.unpack where
  unstep b a = a `B.shiftL` 8 .|. fromIntegral b

p :: Natural
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

g :: Natural
g = 2

