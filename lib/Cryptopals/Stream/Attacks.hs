module Cryptopals.Stream.Attacks where

import Control.Monad
import Control.Monad.Primitive
import qualified Control.Monad.ST as ST
import qualified Data.Binary.Put as BP
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
import qualified Data.Time.Clock.System as TS
import qualified Cryptopals.AES as AES
import qualified Cryptopals.Stream.RNG.MT19937 as MT
import qualified Cryptopals.Util as CU
import GHC.Word (Word64, Word16, Word8)
import qualified System.Random.MWC as MWC

bytes :: PrimMonad m => Int -> MWC.Gen (PrimState m) -> m BS.ByteString
bytes n gen = fmap BS.pack $ replicateM n (MWC.uniform gen)

-- | An unknown AES key.
consistentKey :: BS.ByteString
consistentKey = ST.runST $ do
  gen <- MWC.create
  bytes 16 gen

consistentNonce :: Word64
consistentNonce = ST.runST $ do
  gen <- MWC.create
  MWC.uniformR (0, 0xffffffffffffffff) gen

-- MT19937-related attacks

keystream :: Int -> MT.Gen -> BS.ByteString
keystream nb g =
    let l  = nb `quot` 4 + nb `rem` 4
        ws = fst (MT.tap l g)
    in  BS.take nb . BSL.toStrict . BP.runPut $ loop ws
  where
    loop bs = case bs of
      []    -> pure ()
      (h:t) -> do
        BP.putWord32le h
        loop t

encryptMT19937 :: Word16 -> BS.ByteString -> BS.ByteString
encryptMT19937 s pt = pt `CU.fixedXor` bs where
  g  = MT.seed (fromIntegral s)
  bs = keystream (BS.length pt) g

decryptMT19937 :: Word16 -> BS.ByteString -> BS.ByteString
decryptMT19937 = encryptMT19937

ciphertext :: BS.ByteString
ciphertext = encryptMT19937 50000 $ ST.runST $ do
  g <- MWC.create
  n <- MWC.uniformR (1, 10) g
  bs <- fmap BS.pack $ replicateM n (MWC.uniformR (32, 126) g)
  pure (bs <> BS.replicate 14 65)

mtCipherAttack :: BS.ByteString -> Word16
mtCipherAttack cip = loop 0 where
  l = BS.length cip
  t = BS.replicate 14 65
  loop j
    | j > (maxBound :: Word16) = error "impossible seed"
    | otherwise =
        let g  = MT.seed (fromIntegral j)
            bs = keystream l g
            pt = BS.drop (l - 14) (bs `CU.fixedXor` cip)
        in  if   pt == t
            then j
            else loop (succ j)

pwntToken :: IO T.Text
pwntToken = do
  s <- fmap (fromIntegral . TS.systemSeconds) TS.getSystemTime
  let g = MT.seed s
  pure $ B64.encodeBase64 (keystream 16 g)

notPwntToken :: IO T.Text
notPwntToken = do
  g  <- MWC.createSystemRandom
  bs <- fmap BS.pack $ replicateM 16 (MWC.uniformR (32, 126) g)
  pure $ B64.encodeBase64 bs

isPwnt :: T.Text -> IO Bool
isPwnt token = do
  s <- fmap (fromIntegral . TS.systemSeconds) TS.getSystemTime
  let g = MT.seed s
      ks = keystream 16 g
  pure $ token == B64.encodeBase64 ks

-- CTR attacks

ctrEdit
  :: BS.ByteString
  -> BS.ByteString
  -> Word64
  -> Int
  -> BS.ByteString
  -> BS.ByteString
ctrEdit cip key non off new =
  let (pre, _) = BS.splitAt off cip
      ced      = AES.encryptCtrAES128 non key new
  in  pre <> ced

rawrCtrInput :: IO BS.ByteString
rawrCtrInput = do
  raw <- B8.readFile "data/s4/q25_input.txt"
  let bs = B64.decodeBase64Lenient . mconcat .B8.lines $ raw
  let pay = AES.decryptEcbAES128 "YELLOW SUBMARINE" bs
  pure $ AES.encryptCtrAES128 consistentNonce consistentKey pay

rawrCtrOracle :: Int -> BS.ByteString -> IO BS.ByteString
rawrCtrOracle off pay = do
  let k = consistentKey
      n = consistentNonce

  cip <- rawrCtrInput

  pure $ ctrEdit cip k n off pay

rawrCtrAttack :: IO BS.ByteString
rawrCtrAttack = do
  cip <- rawrCtrOracle (maxBound :: Int) mempty
  let l = BS.length cip
      p = BS.replicate l 65

  new <- rawrCtrOracle 0 p
  let ks = new `CU.fixedXor` p

  pure $ ks `CU.fixedXor` cip

