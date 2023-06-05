module Cryptopals.Block.Attacks (
    chaosEncrypter
  , alienEncrypter
  , weirdEncrypter
  ) where

import Control.Monad
import Control.Monad.Primitive
import qualified Control.Monad.ST as ST
import qualified Cryptopals.AES as AES
import qualified Cryptopals.Util as CU
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.HashMap.Strict as HMS
import qualified Data.List as L
import qualified Data.List.NonEmpty as NE
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import GHC.Word (Word8)
import qualified System.Random.MWC as MWC

bytes :: PrimMonad m => Int -> MWC.Gen (PrimState m) -> m BS.ByteString
bytes n gen = fmap BS.pack $ replicateM n (MWC.uniform gen)

-- | An unknown AES key.
consistentKey :: BS.ByteString
consistentKey = ST.runST $ do
  gen <- MWC.create
  bytes 16 gen

chaosEncrypter
  :: PrimMonad m
  => BS.ByteString
  -> MWC.Gen (PrimState m)
  -> m BS.ByteString
chaosEncrypter plaintext gen = do
  key  <- bytes 16 gen
  pre  <- MWC.uniformR (5, 10) gen >>= flip bytes gen
  pos  <- MWC.uniformR (5, 10) gen >>= flip bytes gen

  let tex = pre <> plaintext <> pos
      pad = CU.roundUpToMul 16 (BS.length tex)
      bs = CU.pkcs7 pad tex

  ecb  <- MWC.uniform gen

  if   ecb
  then pure $ AES.encryptEcbAES128 key bs
  else do
    iv <- bytes 16 gen
    pure $ AES.encryptCbcAES128 iv key bs

alienEncrypter :: BS.ByteString -> BS.ByteString
alienEncrypter plaintext =
  let pos = B64.decodeBase64Lenient $ mconcat [
          "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        , "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        , "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        , "YnkK"
        ]

      par = plaintext <> pos
      pad = CU.roundUpToMul 16 (BS.length par)
      bs  = CU.pkcs7 pad par

  in  AES.encryptEcbAES128 consistentKey bs

ciphertextMap
  :: (BS.ByteString -> BS.ByteString)
  -> BS.ByteString
  -> HMS.HashMap BS.ByteString Word8
ciphertextMap oracle input = loop [0..255] mempty where
  loop ps !acc = case ps of
    []    -> acc
    (h:t) ->
      let key = BS.take (CU.roundUpToMul 16 (BS.length input)) $
                  oracle (input <> BS.singleton h)
      in  loop t (HMS.insert key h acc)

mciphertextMap
  :: PrimMonad m
  => (BS.ByteString -> MWC.Gen (PrimState m) -> m BS.ByteString)
  -> BS.ByteString
  -> MWC.Gen (PrimState m)
  -> m (HMS.HashMap BS.ByteString Word8)
mciphertextMap oracle input = loop [0..255] mempty where
  loop ps !acc gen = case ps of
    []    -> pure acc
    (h:t) -> do
      ciph <- oracle (input <> BS.singleton h) gen
      let key = BS.take (CU.roundUpToMul 16 (BS.length input)) $ ciph
      loop t (HMS.insert key h acc) gen

incrByteEcbAttack :: (BS.ByteString -> BS.ByteString) -> BS.ByteString
incrByteEcbAttack oracle = loop input mempty where
  ciphertext = oracle mempty
  input      = BS.replicate (BS.length ciphertext - 1) 65

  loop !inp !plain = case BS.unsnoc inp of
    Nothing      -> plain
    Just (bs, _) ->
      let raw  = oracle inp
          quer = inp <> plain
          dict = ciphertextMap oracle quer
          key  = BS.take (CU.roundUpToMul 16 (BS.length input)) raw
      in  case HMS.lookup key dict of
            Nothing  -> plain -- XX need better stopping condition?
            Just byt -> loop bs (plain <> BS.singleton byt)

-- XX something probably a little off here; sometimes returns truncated
--    plaintexts
hardIncrByteEcbAttack
  :: PrimMonad m
  => (BS.ByteString -> MWC.Gen (PrimState m) -> m BS.ByteString)
  -> MWC.Gen (PrimState m)
  -> m BS.ByteString
hardIncrByteEcbAttack oracle gen = do
    ciphertext <- oracle mempty gen
    let input = BS.replicate (BS.length ciphertext - 1) 66
    loop input mempty gen
  where
    loop !inp !plain gen = case BS.unsnoc inp of
      Nothing -> pure plain
      Just (bs, _) -> do
        raw <- oracle inp gen
        let quer = inp <> plain
        dict <- mciphertextMap oracle quer gen
        let key = BS.take (CU.roundUpToMul 16 (BS.length (inp <> plain))) raw
        case HMS.lookup key dict of
          Nothing  -> pure plain -- XX ?
          Just byt -> loop bs (plain <> BS.singleton byt) gen

kvParser :: T.Text -> HMS.HashMap T.Text T.Text
kvParser = L.foldl' alg mempty . T.splitOn "&" where
  alg acc val = case T.splitOn "=" val of
    (h:t:[]) -> HMS.insert h t acc
    _        -> acc

profileFor :: T.Text -> T.Text
profileFor addr =
  let email = T.filter (`notElem` ("&=" :: String)) addr
  in  "email=" <> email <> "&" <> "uid=10&role=user"

-- cut-and-paste ECB
cpeEncrypt :: BS.ByteString -> BS.ByteString
cpeEncrypt user =
  let tex = TE.encodeUtf8 $ profileFor (TE.decodeUtf8 user)

      pad = CU.roundUpToMul 16 (BS.length tex)
      bs  = CU.pkcs7 pad tex

  in  AES.encryptEcbAES128 consistentKey bs

-- cut-and-paste ECB
cpeDecrypt :: BS.ByteString -> BS.ByteString
cpeDecrypt ciphertext = AES.decryptEcbAES128 consistentKey ciphertext

weirdEncrypter
  :: PrimMonad m
  => BS.ByteString
  -> MWC.Gen (PrimState m)
  -> m BS.ByteString
weirdEncrypter plaintext gen = do
  let pos = B64.decodeBase64Lenient $ mconcat [
          "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        , "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        , "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        , "YnkK"
        ]

  bys <- MWC.uniformR (1, 256) gen
  pre <- bytes bys gen

  let par = pre <> plaintext <> pos
      pad = CU.roundUpToMul 16 (BS.length par)
      bs  = CU.pkcs7 pad par

  pure $ AES.encryptEcbAES128 consistentKey bs

-- The idea is to inject a block whose ciphertext is known, followed by
-- the malicious alignment block(s). One can figure out ciphertext
-- corresponding to any block of repeated bytes by just feeding in more
-- than a block's worth of them -- necessarily some (plaintext) block
-- will then include only that repeated byte.
--
-- E.g.: "AAAAAAAAAAAAAAAA" encrypts to "57eef2e16c3867b9889350eb5732c183",
-- so we can look for that ciphertext in the result in order to locate
-- an "origin," only analyzing ciphertexts in which it appears.
--
-- This function returns the ciphertext following the "identifier" block.
attackProxy
  :: PrimMonad m
  => (BS.ByteString -> MWC.Gen (PrimState m) -> m BS.ByteString)
  -> BS.ByteString
  -> MWC.Gen (PrimState m)
  -> m BS.ByteString
attackProxy oracle input gen = loop gen where
  identifier = BS.replicate 16 65
  Right knownBlock = B16.decodeBase16 "57eef2e16c3867b9889350eb5732c183"

  loop g = do
    ciph <- oracle (identifier <> input) gen
    let (_, target) = BS.breakSubstring knownBlock ciph
    if   target == mempty
    then loop g
    else pure $ BS.drop 16 target

nubplusplus :: (Eq a, Ord a) => [a] -> [a]
nubplusplus = fmap NE.head . NE.group . L.sort

