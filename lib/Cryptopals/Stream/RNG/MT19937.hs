module Cryptopals.Stream.RNG.MT19937 (
    Gen
  , seed
  , extract
  , tap

  , clone
  ) where

import qualified Control.Monad.ST as ST
import Data.Bits ((.&.))
import qualified Data.Bits as B
import qualified Data.Vector.Unboxed as VU
import qualified Data.Vector.Unboxed.Mutable as VUM
import GHC.Word (Word32)

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral

-- following notation in https://en.wikipedia.org/wiki/Mersenne_Twister

w, n, m, r, a, u, s, b, t, c, l :: Word32
w = 32            -- word size
n = 624           -- degree of recurrence
m = 397           -- 'middle term'
r = 31            -- word separation index
a = 0x9908B0DF    -- rational normal form twist matrix coefficients
u = 11            -- tempering parameter
s = 7             -- tempering parameter (shift)
b = 0x9D2C5680    -- tempering parameter (mask)
t = 15            -- tempering parameter (shift)
c = 0xEFC60000    -- tempering parameter (mask)
l = 18            -- tempering parameter

f :: Word32
f = 1812433253

lm :: Word32
lm = B.shiftL 1 (fi r) - 1 -- 0b0111 1111 1111 1111 1111 1111 1111 1111

um :: Word32
um = B.complement lm       -- 0b1000 0000 0000 0000 0000 0000 0000 0000

data Gen = Gen !Word32 !(VU.Vector Word32)
  deriving Eq

instance Show Gen where
  show Gen {} = "<MT19937.Gen>"

tap :: Int -> Gen -> ([Word32], Gen)
tap = loop mempty where
  loop !acc j gen
    | j == 0    = (reverse acc, gen)
    | otherwise =
        let (w, g) = extract gen
        in  loop (w : acc) (pred j) g

seed :: Word32 -> Gen
seed s = Gen n (loop 0 mempty) where
  loop j !acc
    | j == n    = VU.fromList (reverse acc)
    | otherwise = case acc of
        []    -> loop (succ j) (pure s)
        (h:_) ->
          let v = f * (h `B.xor` (B.shiftR h (fi w - 2))) + j
          in  loop (succ j) (v : acc)

extract :: Gen -> (Word32, Gen)
extract gen@(Gen idx _) =
  let Gen i g = if   idx >= n
                then twist gen
                else gen

      y = g `VU.unsafeIndex` fi i

  in  (temper y, Gen (succ i) g)

temper :: Word32 -> Word32
temper = e4 . e3 . e2 . e1 where
  e1 = rs u
  e2 = ls s b
  e3 = ls t c
  e4 = rs l

untemper :: Word32 -> Word32
untemper = n1 . n2 . n3 . n4 where
  n1 = rsinv u
  n2 = lsinv s b
  n3 = lsinv t c
  n4 = rsinv l

mask :: B.Bits b => Int -> Int -> b
mask l h = loop l B.zeroBits where
  loop j !b
    | j > h = b
    | otherwise =
        loop (succ j) (B.setBit b j)

ls :: Word32 -> Word32 -> Word32 -> Word32
ls s m a = a `B.xor` (B.shiftL a (fi s) .&. m)

lsinv :: Word32 -> Word32 -> Word32 -> Word32
lsinv s bm = loop 0 where
  loop j !b
    | j >= fi w = b
    | otherwise =
        let m = mask j (min (fi w - 1) (j + fi s - 1))
            x = ((m .&. b) `B.shiftL` fi s) .&. bm
        in  loop (j + fi s) (b `B.xor` x)

rs :: Word32 -> Word32 -> Word32
rs s a = a `B.xor` B.shiftR a (fi s)

rsinv :: Word32 -> Word32 -> Word32
rsinv s = loop (fi w - 1) where
  loop j !b
    | j <= 0    = b
    | otherwise =
        let m = mask (max 0 (j - fi s + 1)) j
            x = (m .&. b) `B.shiftR` fi s
        in  loop (j - fi s) (b `B.xor` x)

twist :: Gen -> Gen
twist (Gen i gen) = ST.runST $ do
    g <- VU.thaw gen

    let loop j
          | j == fi n = pure ()
          | otherwise = do
              x0 <- g `VUM.unsafeRead` j
              x1 <- g `VUM.unsafeRead` ((succ j) `mod` fi n)

              let x  = (x0 .&. um) + (x1 .&. lm)
                  xa = B.shiftR x 1
                  xA | x `mod` 2 /= 0 = xa `B.xor` a
                     | otherwise      = xa

              v <- g `VUM.unsafeRead` ((j + fi m) `mod` fi n)

              VUM.write g j $ v `B.xor` xA
              loop (succ j)

    loop 0

    fen <- VU.freeze g
    pure (Gen 0 fen)

clone :: [Word32] -> Gen
clone = Gen n . VU.fromList . fmap untemper

