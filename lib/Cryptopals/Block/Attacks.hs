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
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.HashMap.Strict as HMS
import qualified Data.List as L
import qualified Data.Maybe as M
import qualified Data.Set as S
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
      bs  = CU.lpkcs7 tex

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
      bs  = CU.lpkcs7 par

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
    loop !inp !plain g = case BS.unsnoc inp of
      Nothing -> pure plain
      Just (bs, _) -> do
        raw <- oracle inp g
        let quer = inp <> plain
        dict <- mciphertextMap oracle quer g
        let key = BS.take (CU.roundUpToMul 16 (BS.length (inp <> plain))) raw
        case HMS.lookup key dict of
          Nothing  -> pure plain -- XX ?
          Just byt -> loop bs (plain <> BS.singleton byt) g

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

      bs  = CU.lpkcs7 tex

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
      bs  = CU.lpkcs7 par

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
attackProxy oracle input = loop where
  identifier = BS.replicate 16 65
  Right knownBlock = B16.decodeBase16 "57eef2e16c3867b9889350eb5732c183"

  loop g = do
    ciph <- oracle (identifier <> input) g
    let (_, target) = BS.breakSubstring knownBlock ciph
    if   target == mempty
    then loop g
    else pure $ BS.drop 16 target

-- bitflipping CBC

bfcEncrypter :: BS.ByteString -> BS.ByteString
bfcEncrypter input = AES.encryptCbcAES128 iv consistentKey padded where
  iv = BS.replicate 16 0
  filtered  = BS.filter (`notElem` (BS.unpack ";=")) input
  plaintext = "comment1=cooking%20MCs;userdata=" <> filtered <>
              ";comment2=%20like%20a%20pound%20of%20bacon"
  padded = CU.lpkcs7 plaintext

bfcChecker :: BS.ByteString -> Bool
bfcChecker ciphertext = target /= mempty where
  iv          = BS.replicate 16 0
  plaintext   = AES.decryptCbcAES128 consistentKey ciphertext
  (_, target) = BS.breakSubstring ";admin=true;" plaintext

-- CBC padding oracle

-- see https://en.wikipedia.org/wiki/Padding_oracle_attack
poInputs :: [BS.ByteString]
poInputs = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
  , "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
  , "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
  , "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
  , "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
  , "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
  , "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
  , "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
  , "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
  , "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
  ]

paddingOracle
  :: PrimMonad m
  => MWC.Gen (PrimState m)
  -> m BS.ByteString
paddingOracle gen = do
  idx <- MWC.uniformR (0, length poInputs - 1) gen
  let Right input = B64.decodeBase64 (poInputs !! idx)
      padded      = CU.lpkcs7 input
  iv <- bytes 16 gen
  pure $ AES.encryptCbcAES128 iv consistentKey padded

poValidate :: BS.ByteString -> Bool
poValidate bs = case CU.unpkcs7 (AES.decryptCbcAES128 consistentKey bs) of
  Nothing -> False
  Just _  -> True

paddingOracleAttack :: BS.ByteString -> BS.ByteString
paddingOracleAttack cip = loop mempty (reverse (CU.chunks 16 cip)) where
  loop !acc rcs = case rcs of
    []     -> acc
    (h:[]) -> acc
    (h:r@(i:t)) -> loop (poAttackBlock i h <> acc) r

poAttackBlock :: BS.ByteString -> BS.ByteString -> BS.ByteString
poAttackBlock tol tar = byte tol tar mempty mempty where
  byte c0' c1 p1 i1 = case BS.unsnoc c0' of
    Nothing     -> p1
    Just (t, h) ->
      let ncb = next t h i1 c1
          il  = BS.length i1
          pb  = fromIntegral il + 1
          nib = ncb `B.xor` pb
          npb = BS.index tol (15 - fromIntegral il) `B.xor` nib
      in  byte t c1 (BS.cons npb p1) (BS.cons nib i1)

  next bs b i1 c1 =
    let l   = fromIntegral (BS.length i1) + 1
        c   = BS.map (B.xor l) i1
        c0' = BS.snoc bs b <> c

        roll byt =
          let c0' = BS.snoc bs byt <> c
          in  if   poValidate (c0' <> c1) && cert bs (BS.cons byt c <> c1)
              then byt
              else roll (byt + 1)

    in  roll b

  cert c0' etc = case BS.unsnoc c0' of
    Nothing -> True
    Just (bs, b)
      | poValidate (BS.snoc bs (b + 1) <> etc) -> True
      | otherwise -> False

-- CTR reused-nonce

rninputs :: [BS.ByteString]
rninputs = [
    "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ=="
  , "Q29taW5nIHdpdGggdml2aWQgZmFjZXM="
  , "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ=="
  , "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4="
  , "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk"
  , "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA=="
  , "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ="
  , "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA=="
  , "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU="
  , "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl"
  , "VG8gcGxlYXNlIGEgY29tcGFuaW9u"
  , "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA=="
  , "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk="
  , "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg=="
  , "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo="
  , "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
  , "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA=="
  , "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA=="
  , "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA=="
  , "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg=="
  , "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw=="
  , "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA=="
  , "U2hlIHJvZGUgdG8gaGFycmllcnM/"
  , "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w="
  , "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4="
  , "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ="
  , "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs="
  , "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA=="
  , "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA=="
  , "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4="
  , "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA=="
  , "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu"
  , "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc="
  , "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs"
  , "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs="
  , "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0"
  , "SW4gdGhlIGNhc3VhbCBjb21lZHk7"
  , "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw="
  , "VHJhbnNmb3JtZWQgdXR0ZXJseTo="
  , "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
  ]

rncrypted :: [BS.ByteString]
rncrypted = fmap (enc . B64.decodeBase64Lenient) rninputs where
  enc = AES.encryptCtrAES128 0 "YELLOW SUBMARINE"

rnscrypted :: [BS.ByteString]
rnscrypted = fmap (BS.take 16) rncrypted

rnrotated :: [BS.ByteString]
rnrotated = CU.rotate 16 (BS.concat rnscrypted)

-- FIXME replace Cryptopals.Util.best with this?
rnBest :: BS.ByteString -> (Word8, Double, BS.ByteString)
rnBest s = loop (0, 1 / 0, s) 0 where
  loop acc@(_, asc, _) b
    | b == 255 = acc
    | otherwise =
        let xo = CU.singleByteXor b s
        in  case CU.scoreAlt xo of
              Nothing  -> loop acc (succ b)
              Just sc
                | sc < asc  -> loop (b, sc, xo) (succ b)
                | otherwise -> loop acc (succ b)

-- CBC key recovery w/IV=key

bfcIvEncrypter :: BS.ByteString -> BS.ByteString
bfcIvEncrypter input =
    AES.encryptCbcAES128 consistentKey consistentKey padded
  where
    filtered  = BS.filter (`notElem` (BS.unpack ";=")) input
    plaintext = "comment1=cooking%20MCs;userdata=" <> filtered <>
                ";comment2=%20like%20a%20pound%20of%20bacon"
    padded = CU.lpkcs7 plaintext


