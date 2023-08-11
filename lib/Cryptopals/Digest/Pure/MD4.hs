-- copied/modified from
--
-- https://github.com/mfeyg/md4/blob/master/Data/Digest/Pure/MD4.hs
module Cryptopals.Digest.Pure.MD4 (
    md4
  , md4'
  ) where

import Control.Applicative
import Control.Monad
import Control.Monad.Trans.State
import Data.Bits
import Data.Binary.Put
import Data.Binary.Get
import qualified Data.ByteString.Lazy as L
import Data.Word
import GHC.Word (Word64)

f x y z = x .&. y .|. complement x .&. z
g x y z = x .&. y .|. x .&. z .|. y .&. z
h x y z = x `xor` y `xor` z

abcd f a b c d = f a b c d
dabc f a b c d = f d a b c
cdab f a b c d = f c d a b
bcda f a b c d = f b c d a

data State = Vals !Word32 !Word32 !Word32 !Word32

store1 x (Vals a b c d) = Vals x b c d
store2 x (Vals a b c d) = Vals a x c d
store3 x (Vals a b c d) = Vals a b x d
store4 x (Vals a b c d) = Vals a b c x

get1 (Vals x _ _ _) = x
get2 (Vals _ x _ _) = x
get3 (Vals _ _ x _) = x
get4 (Vals _ _ _ x) = x

op f n k s x a b c d =
  rotateL (a + f b c d + (x!!k) + n) s

op1 = op f 0
op2 = op g 0x5a827999
op3 = op h 0x6ed9eba1

params1 = [ 0, 3,  1, 7,  2, 11,  3, 19
          , 4, 3,  5, 7,  6, 11,  7, 19
          , 8, 3,  9, 7, 10, 11, 11, 19
          ,12, 3, 13, 7, 14, 11, 15, 19]

params2 = [0, 3, 4, 5,  8, 9, 12, 13
          ,1, 3, 5, 5,  9, 9, 13, 13
          ,2, 3, 6, 5, 10, 9, 14, 13
          ,3, 3, 7, 5, 11, 9, 15, 13]

params3 = [0, 3,  8, 9, 4, 11, 12, 15
          ,2, 3, 10, 9, 6, 11, 14, 15
          ,1, 3,  9, 9, 5, 11, 13, 15
          ,3, 3, 11, 9, 7, 11, 15, 15]

apply x op p k s = p go (gets get1, modify . store1)
                        (gets get2, modify . store2)
                        (gets get3, modify . store3)
                        (gets get4, modify . store4)
  where go (a, store) (b,_) (c,_) (d,_) =
           store =<< (op k s x <$> a <*> b <*> c <*> d)

on app = go
  where go [] = pure ()
        go (k1:s1:k2:s2:k3:s3:k4:s4:r)
             = app abcd k1 s1
            *> app dabc k2 s2
            *> app cdab k3 s3
            *> app bcda k4 s4
            *> go r

proc !x = (modify . add) =<<
    (get <* go op1 params1
         <* go op2 params2
         <* go op3 params3)
  where add (Vals a b c d) (Vals a' b' c' d') =
          Vals (a+a') (b+b') (c+c') (d+d')
        go op params = apply x op `on` params

md4'
  :: Word32
  -> Word32
  -> Word32
  -> Word32
  -> Word64
  -> L.ByteString
  -> L.ByteString
md4' a b c d n s = output $ execState (go (prep' n s) (pure ())) $
    Vals a b c d
  where
    go [] m = m
    go !s m = go (drop 16 s) $ m >> proc (take 16 s)

pad' n bs = bs <> evilpadding n bs

prep' n = getWords . pad' n

md4 :: L.ByteString -> L.ByteString
md4 s = output $ execState (go (prep s) (return ())) $
    Vals 0x67452301 0xefcdab89 0x98badcfe 0x10325476
  where go [] m = m
        go !s m = go (drop 16 s) $ m >> proc (take 16 s)

prep = getWords . pad

pad bs = runPut $ putAndCountBytes bs >>= \len ->
                  putWord8 0x80
               *> replicateM_ (mod (55 - fromIntegral len)  64) (putWord8 0)
               *> putWord64le (len * 8)

putAndCountBytes = go 0
  where go !n s = case L.uncons s of
                    Just (w, s') -> putWord8 w >> go (n+1) s'
                    Nothing      -> return $! n

getWords = runGet words where
  words = isEmpty >>= \e ->
    if   e
    then pure []
    else (:) <$> getWord32le <*> words

output (Vals a b c d) = runPut $ mapM_ putWord32le [a,b,c,d]

-- required padding bytes
pbytes :: Integral a => a -> a
pbytes ((\k -> 64 - k `mod` 64) -> l)
  | l == 0    = l + 56
  | otherwise = l - 8

-- padding for a supplied message, using arbitrary bytelength n
evilpadding :: Word64 -> L.ByteString -> L.ByteString
evilpadding n bs = runPut $ do
    putWord8 128
    loop (pred (pbytes (L.length bs)))
  where
    loop l
      | l == 0    = putWord64le (n * 8)
      | otherwise = do
          putWord8 0
          loop (pred l)

