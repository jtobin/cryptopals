module Cryptopals.AES (
    encryptCbcAES128
  , encryptEcbAES128
  , decryptCbcAES128
  , decryptEcbAES128
  ) where

import qualified Data.ByteString as BS
import qualified Cryptopals.Util as CU
import qualified Crypto.Cipher.AES as CAES
import qualified Crypto.Cipher.Types as CT
import qualified Crypto.Error as CE

initAES128 :: BS.ByteString -> CAES.AES128
initAES128 =  CE.throwCryptoError . CT.cipherInit

encryptEcbAES128 :: BS.ByteString -> BS.ByteString -> BS.ByteString
encryptEcbAES128 key = CT.ecbEncrypt (initAES128 key)

decryptEcbAES128 :: BS.ByteString -> BS.ByteString -> BS.ByteString
decryptEcbAES128 key = CT.ecbDecrypt (initAES128 key)

encryptCbcAES128
  :: BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString
encryptCbcAES128 iv key plaintext = loop iv iv (BS.splitAt 16 plaintext)
  where
    loop las !acc (b, bs) =
      let xed  = CU.fixedXor las b
          enc  = encryptEcbAES128 key xed
          nacc = acc <> enc
      in  if   BS.null bs
          then nacc
          else loop enc nacc (BS.splitAt 16 bs)

decryptCbcAES128
  :: BS.ByteString -> BS.ByteString -> BS.ByteString
decryptCbcAES128 key ciphertext =
    let (iv, cip) = BS.splitAt 16 ciphertext
    in  loop iv mempty (BS.splitAt 16 cip)
  where
    loop !las !acc (b, bs) =
      let dec  = decryptEcbAES128 key b
          nacc = acc <> CU.fixedXor dec las
          niv  = b
      in  if   BS.null bs
          then nacc
          else loop b nacc (BS.splitAt 16 bs)

