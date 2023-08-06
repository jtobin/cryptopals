module Cryptopals.MAC (
    sha1mac
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy as BSL
import qualified Cryptopals.Digest.Pure.SHA as S (Digest, SHA1State, sha1)

sha1mac :: BS.ByteString -> BS.ByteString -> BS.ByteString
sha1mac k m = B8.pack . show . hash . BSL.fromStrict $ k <> m where
  hash :: BSL.ByteString -> S.Digest S.SHA1State
  hash = S.sha1


