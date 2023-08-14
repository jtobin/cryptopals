module Cryptopals.Util (
    CUB.chunks
  , CUB.hamming
  , fixedXor
  , lpkcs7
  , CUB.nhamming
  , CUS.often
  , CUB.panhamming
  , pkcs7
  , repeatingKeyXor
  , CUB.rotate
  , roundUpToMul
  , CUS.score
  , CUS.scoreAlt
  , singleByteXor
  , CUS.tally
  , CUS.gtally
  , unpkcs7
  , bytes
  ) where

import Control.Monad
import Control.Monad.Primitive
import qualified Cryptopals.Util.ByteString as CUB
import qualified Cryptopals.Util.Similarity as CUS
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.Text as T
import GHC.Word (Word8)
import qualified System.Random.MWC as MWC

bytes :: PrimMonad m => Int -> MWC.Gen (PrimState m) -> m BS.ByteString
bytes n gen = fmap BS.pack $ replicateM n (MWC.uniform gen)

fixedXor :: BS.ByteString -> BS.ByteString -> BS.ByteString
fixedXor l r = BS.pack $ BS.zipWith B.xor l r

singleByteXor :: Word8 -> BS.ByteString -> BS.ByteString
singleByteXor byt = BS.map (B.xor byt)

repeatingKeyXor :: BS.ByteString -> BS.ByteString -> BS.ByteString
repeatingKeyXor key pla =
  let pl = BS.length pla
      ks = BS.pack $ take pl (cycle (BS.unpack key))
  in  BS.pack $ BS.zipWith B.xor ks pla

pkcs7 :: Int -> BS.ByteString -> BS.ByteString
pkcs7 tar bs
  | BS.length bs `rem` tar == 0 = bs <> BS.replicate 16 16
  | otherwise =
      let len = BS.length bs
          byt = tar - len `mod` tar
      in  bs <> BS.replicate byt (fromIntegral byt)

-- lazy man's pkcs#7 padding
lpkcs7 :: BS.ByteString -> BS.ByteString
lpkcs7 bs
  | BS.null bs = BS.replicate 16 16
  | otherwise  = pkcs7 (roundUpToMul 16 (BS.length bs)) bs

unpkcs7 :: BS.ByteString -> Maybe BS.ByteString
unpkcs7 bs = do
  (_, c) <- BS.unsnoc bs
  let len = BS.length bs
  if   fromIntegral c > len || c == 0
  then Nothing
  else let (str, pad) = BS.splitAt (len - fromIntegral c) bs
       in  if   BS.all (== fromIntegral c) pad
           then pure str
           else Nothing

roundUpToMul :: Int -> Int -> Int
roundUpToMul mul num =
  let r = num `rem` mul
  in  if   r == 0
      then num
      else num + mul - r

