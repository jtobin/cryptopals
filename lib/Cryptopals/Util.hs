module Cryptopals.Util (
    Hex(..)
  , Base64(..)

  , hexToB64
  , fixedXor
  ) where

import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.Text as T

newtype Hex = Hex BS.ByteString
  deriving (Eq, Show)

newtype Base64 = Base64 BS.ByteString
  deriving (Eq, Show)

hexToB64 :: Hex -> Either T.Text Base64
hexToB64 (Hex b) = do
  b16 <- B16.decodeBase16 b
  pure $ Base64 (B64.encodeBase64' b16)

fixedXor :: Hex -> Hex -> Either T.Text Hex
fixedXor (Hex a) (Hex b) = do
  l <- B16.decodeBase16 a
  r <- B16.decodeBase16 b
  if   BS.length l /= BS.length r
  then Left "fixedXor: unequal-length buffers"
  else pure $ Hex (B16.encodeBase16' . BS.pack $ BS.zipWith B.xor l r)

