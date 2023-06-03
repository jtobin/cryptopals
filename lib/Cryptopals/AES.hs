module Cryptopals.AES (
    encryptEcbAES128
  , decryptEcbAES128
  ) where

import qualified Data.ByteString as BS
import qualified Crypto.Cipher.AES as CAES
import qualified Crypto.Cipher.Types as CT
import qualified Crypto.Error as CE

initAES128 :: BS.ByteString -> CAES.AES128
initAES128 =  CE.throwCryptoError . CT.cipherInit

encryptEcbAES128 :: BS.ByteString -> BS.ByteString -> BS.ByteString
encryptEcbAES128 key = CT.ecbEncrypt (initAES128 key)

decryptEcbAES128 :: BS.ByteString -> BS.ByteString -> BS.ByteString
decryptEcbAES128 key = CT.ecbDecrypt (initAES128 key)

