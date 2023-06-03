module Cryptopals.Util (
    Hex(..)
  , Base64(..)

  , CUB.chunks
  , CUB.hamming
  , hexToB64
  , fixedXor
  , CUB.nhamming
  , CUS.often
  , CUB.panhamming
  , repeatingKeyXor
  , CUB.rotate
  , CUS.score
  , singleByteXor
  , CUS.tally
  ) where

import qualified Cryptopals.Util.ByteString as CUB
import qualified Cryptopals.Util.Similarity as CUS
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.Text as T
import GHC.Word (Word8)

newtype Hex = Hex BS.ByteString
  deriving (Eq, Show)

newtype Base64 = Base64 BS.ByteString
  deriving (Eq, Show)

hexToB64 :: Hex -> Either T.Text Base64
hexToB64 (Hex b) = do
  b16 <- B16.decodeBase16 b
  pure $ Base64 (B64.encodeBase64' b16)

fixedXor :: BS.ByteString -> BS.ByteString -> BS.ByteString
fixedXor l r = BS.pack $ BS.zipWith B.xor l r

singleByteXor :: Word8 -> BS.ByteString -> BS.ByteString
singleByteXor byt = BS.map (B.xor byt)

repeatingKeyXor :: BS.ByteString -> BS.ByteString -> BS.ByteString
repeatingKeyXor key pla =
  let pl = BS.length pla
      ks = BS.pack $ take pl (cycle (BS.unpack key))
  in  BS.pack $ BS.zipWith B.xor ks pla

