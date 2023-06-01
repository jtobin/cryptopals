module Cryptopals.Util (
    Hex(..)
  , Base64(..)

  , hexToB64
  , fixedXor
  , CUS.score
  , singleByteXor
  ) where

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

singleByteXor :: Word8 -> Hex -> Either T.Text Hex
singleByteXor byt (Hex bs) = do
  s <- B16.decodeBase16 bs
  pure $ Hex (B16.encodeBase16' . BS.map (B.xor byt) $ s)

