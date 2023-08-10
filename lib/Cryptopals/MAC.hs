module Cryptopals.MAC (
    sha1
  , sha1mac
  , verifysha1mac
  ) where

import qualified Data.ByteString.Lazy.Char8 as BL8
import qualified Data.ByteString.Lazy as BSL
import qualified Cryptopals.Digest.Pure.SHA as S

sha1 :: BSL.ByteString -> BSL.ByteString
sha1 = S.bytestringDigest . S.sha1

sha1mac :: BSL.ByteString -> BSL.ByteString -> BSL.ByteString
sha1mac k m = S.bytestringDigest . hash $ k <> m where
  hash :: BSL.ByteString -> S.Digest S.SHA1State
  hash = S.sha1

verifysha1mac :: BSL.ByteString -> BSL.ByteString -> BSL.ByteString -> Bool
verifysha1mac key mac message = sha1mac key message == mac


