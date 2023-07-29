module Cryptopals.Stream.RNG.MT19937 (
    Gen
  , seed
  , extract
  ) where

import Data.Bits ((.&.))
import qualified Data.Bits as B
import qualified Data.Vector.Unboxed as VU
import GHC.Word (Word32)

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral

-- following notation in https://en.wikipedia.org/wiki/Mersenne_Twister

w, n, m, r, a, u, d, s, b, t, c, l :: Word32
w = 32
n = 624
m = 397
r = 31
a = 0x9908B0DF
u = 11
d = 0xFFFFFFFF
s = 7
b = 0x9D2C5680
t = 15
c = 0xEFC60000
l = 18

f :: Word32
f = 1812433253

lm :: Word32
lm = B.shiftL 1 (fi r) - 1 -- 0x0111 1111 1111 1111 1111 1111 1111 1111

um :: Word32
um = B.complement lm       -- 0x1000 0000 0000 0000 0000 0000 0000 0000

data Gen = Gen !Word32 !(VU.Vector Word32)
  deriving (Eq, Show)

seed :: Word32 -> Gen
seed s = Gen n (loop 0 mempty) where
  loop j !acc
    | j == n    = VU.fromList (reverse acc)
    | otherwise = case acc of
        []    -> loop (succ j) (pure s)
        (h:_) ->
          let v = f * (h `B.xor` (B.shiftR h (fi w - 2))) + j -- XX can overflow?
          in  loop (succ j) (v : acc)

extract :: Gen -> (Word32, Gen)
extract gen@(Gen idx _) =
  let Gen i g = if   idx == n
                then twist gen
                else gen

      y0 = g `VU.unsafeIndex` fi i
      y1 = y0 `B.xor` ((B.shiftR y0 (fi u)) .&. d)
      y2 = y1 `B.xor` ((B.shiftL y1 (fi s)) .&. b)
      y3 = y2 `B.xor` ((B.shiftL y2 (fi t)) .&. c)
      y4 = y3 `B.xor` (B.shiftR y3 1)

  in  (y4, Gen (succ i) g)

twist :: Gen -> Gen
twist (Gen i g) = loop 0 mempty where
  loop j !acc
    | j == fi n = Gen 0 (g VU.// acc)
    | otherwise =
        let x  = ((g `VU.unsafeIndex` j) .&. um) +
                 ((g `VU.unsafeIndex` (succ j `mod` fi n)) .&. lm) -- XX check
            xa = B.shiftR x 1
            xA | x `mod` 2 /= 0 = xa `B.xor` a
               | otherwise      = xa

            v  = (g `VU.unsafeIndex` ((j + fi m) `mod` fi n)) `B.xor` xA

        in  loop (succ j) ((j, v) : acc)

