module Cryptopals.Stream.Attacks where

import Control.Monad
import qualified Control.Monad.ST as ST
import qualified Data.Binary.Put as BP
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
import qualified Data.Time.Clock.System as TS
import qualified Cryptopals.Stream.RNG.MT19937 as MT
import qualified Cryptopals.Util as CU
import GHC.Word (Word16, Word8)
import qualified System.Random.MWC as MWC

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
