module Cryptopals.Util (
    CUB.chunks
  , CUB.hamming
  , fixedXor
  , CUB.nhamming
  , CUS.often
  , CUB.panhamming
  , pkcs7
  , repeatingKeyXor
  , CUB.rotate
  , roundUpToMul
  , CUS.score
  , singleByteXor
  , CUS.tally
  , unpkcs7
  ) where

import qualified Cryptopals.Util.ByteString as CUB
import qualified Cryptopals.Util.Similarity as CUS
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.Text as T
import GHC.Word (Word8)

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
pkcs7 tar bs =
  let len = BS.length bs
      byt = tar - len `mod` tar
  in  bs <> BS.replicate byt (fromIntegral byt)

unpkcs7 :: BS.ByteString -> Maybe BS.ByteString
unpkcs7 bs = do
  (_, c) <- BS.unsnoc bs
  let len = BS.length bs
  if   fromIntegral c > len
  then Nothing
  else let (str, pad) = BS.splitAt (len - fromIntegral c) bs
       in  if   BS.all (== fromIntegral (BS.length pad)) pad
           then pure str
           else Nothing

roundUpToMul :: Int -> Int -> Int
roundUpToMul mul num =
  let r = num `rem` mul
  in  if   r == 0
      then num
      else num + mul - r

