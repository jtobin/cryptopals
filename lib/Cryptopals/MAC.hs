module Cryptopals.MAC (
    sha1mac
  , verifysha1mac

  , md4mac
  , verifymd4mac
  ) where

import qualified Data.ByteString.Lazy.Char8 as BL8
import qualified Data.ByteString.Lazy as BSL
import qualified Cryptopals.Digest.Pure.MD4 as M
import qualified Cryptopals.Digest.Pure.SHA as S

sha1mac :: BSL.ByteString -> BSL.ByteString -> BSL.ByteString
sha1mac k m = S.bytestringDigest . S.sha1 $ k <> m

verifysha1mac :: BSL.ByteString -> BSL.ByteString -> BSL.ByteString -> Bool
verifysha1mac key mac message = sha1mac key message == mac

md4mac :: BSL.ByteString -> BSL.ByteString -> BSL.ByteString
md4mac k m = M.md4 $ k <> m

verifymd4mac :: BSL.ByteString -> BSL.ByteString -> BSL.ByteString -> Bool
verifymd4mac key mac message = md4mac key message == mac

