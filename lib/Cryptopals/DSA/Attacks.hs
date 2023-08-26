module Cryptopals.DSA.Attacks where

import qualified Control.Monad.ST as ST
import qualified Cryptopals.DH as DH
import qualified Cryptopals.Digest.Pure.SHA as CS
import Cryptopals.DSA
import qualified Cryptopals.RSA as RSA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Lazy as BL
import GHC.Word (Word16)
import Numeric.Natural
import qualified System.Random.MWC as MWC

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral

-- key recovery from nonce ----------------------------------------------------

-- recover private key given a subkey
fromsub :: Params -> BS.ByteString -> Sig -> Natural -> Key
fromsub Params {..} msg Sig {..} k =
  let h   = fi . CS.integerDigest . CS.sha1 $ BL.fromStrict msg
      num = (sigs * k - h) `rem` dsaq
      den = RSA.modinv' sigr dsaq
  in  Sec $ (num * den) `rem` dsaq

-- brute-force a private key with a Word16 subkey
recover :: Params -> BS.ByteString -> Sig -> Key -> Key
recover ps@Params {..} msg sig pub = ST.runST $ do
    gen <- MWC.create
    loop 2 gen
  where
    p = case pub of
      Sec {} -> error "recover: need public key"
      Pub pb -> pb
    loop :: forall s. Word16 -> MWC.Gen s -> ST.ST s Key
    loop k g = do
      let sk@(Sec x) = fromsub ps msg sig (fi k)
      sig' <- sign ps sk msg g
      if   DH.modexp dsag x dsap == p && verify ps pub msg sig'
      then pure sk
      else loop (succ k) g

rawmsg :: BS.ByteString
rawmsg = mconcat [
    "For those that envy a MC it can be hazardous to your health "
  , "So be friendly, a matter of life and death, just like a etch-a-sketch "
  ]

rawpub :: Key
rawpub = Pub 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17

rawsig :: Sig
rawsig = Sig {
    sigr = 548099063082341131477253921760299949438196259240
  , sigs = 857042759984254168557880549501802188789837994940
  }

-- nonce recovery from repeated nonce -----------------------------------------

recoverNonce :: Params -> Sig -> Sig -> Natural -> Natural -> Natural
recoverNonce Params {..} (Sig _ s1) (Sig _ s2) h1 h2 =
  let num = (fi h1 - fi h2) `mod` (fi dsaq :: Integer)
      den = (fi s1 - fi s2) `mod` (fi dsaq :: Integer)
  in  (fi num * RSA.modinv' (fi den) dsaq) `mod` dsaq

tarpub :: Key
tarpub = Pub 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

-- msg: Listen for me, you better listen for me now.
-- s: 1267396447369736888040262262183731677867615804316
-- r: 1105520928110492191417703162650245113664610474875
-- m: a4db3de27e2db3e5ef085ced2bced91b82e0df19
r1 :: Natural
r1 = 1105520928110492191417703162650245113664610474875

s1 :: Natural
s1 = 1267396447369736888040262262183731677867615804316

m1 :: BS.ByteString
m1 = "Listen for me, you better listen for me now. "

sig1 :: Sig
sig1 = Sig r1 s1

h1 :: Natural
h1 = 0xa4db3de27e2db3e5ef085ced2bced91b82e0df19

-- msg: Pure black people mon is all I mon know.
-- s: 1021643638653719618255840562522049391608552714967
-- r: 1105520928110492191417703162650245113664610474875
-- m: d22804c4899b522b23eda34d2137cd8cc22b9ce8
r2 :: Natural
r2 = 1105520928110492191417703162650245113664610474875

s2 :: Natural
s2 = 1021643638653719618255840562522049391608552714967

m2 :: BS.ByteString
m2 = "Pure black people mon is all I mon know. "

sig2 :: Sig
sig2 = Sig r2 s2

h2 :: Natural
h2 = 0xd22804c4899b522b23eda34d2137cd8cc22b9ce8

-- msg: Listen for me, you better listen for me now.
-- s: 29097472083055673620219739525237952924429516683
-- r: 51241962016175933742870323080382366896234169532
-- m: a4db3de27e2db3e5ef085ced2bced91b82e0df19

m3 :: BS.ByteString
m3 = "Listen for me, you better listen for me now. "

s3 :: Natural
s3 = 29097472083055673620219739525237952924429516683

r3 :: Natural
r3 = 51241962016175933742870323080382366896234169532

sig3 :: Sig
sig3 = Sig r3 s3

h3 :: Natural
h3 = 0xa4db3de27e2db3e5ef085ced2bced91b82e0df19

-- msg: Yeah me shoes a an tear up an' now me toes is a show a
-- s: 506591325247687166499867321330657300306462367256
-- r: 51241962016175933742870323080382366896234169532
-- m: bc7ec371d951977cba10381da08fe934dea80314

m4 :: BS.ByteString
m4 = "Yeah me shoes a an tear up an' now me toes is a show a "

s4 :: Natural
s4 = 506591325247687166499867321330657300306462367256

r4 :: Natural
r4 = 51241962016175933742870323080382366896234169532

sig4 :: Sig
sig4 = Sig r4 s4

h4 :: Natural
h4 = 0xbc7ec371d951977cba10381da08fe934dea80314

-- msg: When me rockin' the microphone me rock on steady,
-- s: 277954141006005142760672187124679727147013405915
-- r: 228998983350752111397582948403934722619745721541
-- m: 21194f72fe39a80c9c20689b8cf6ce9b0e7e52d4

m5 :: BS.ByteString
m5 = "When me rockin' the microphone me rock on steady, "

s5 :: Natural
s5 = 277954141006005142760672187124679727147013405915

r5 :: Natural
r5 = 228998983350752111397582948403934722619745721541

sig5 :: Sig
sig5 = Sig r5 s5

h5 :: Natural
h5 = 0x21194f72fe39a80c9c20689b8cf6ce9b0e7e52d4

-- msg: Where me a born in are de one Toronto, so
-- s: 458429062067186207052865988429747640462282138703
-- r: 228998983350752111397582948403934722619745721541
-- m: d6340bfcda59b6b75b59ca634813d572de800e8f

m6 :: BS.ByteString
m6 = "Where me a born in are de one Toronto, so "

s6 :: Natural
s6 = 458429062067186207052865988429747640462282138703

r6 :: Natural
r6 = 228998983350752111397582948403934722619745721541

sig6 :: Sig
sig6 = Sig r6 s6

h6 :: Natural
h6 = 0xd6340bfcda59b6b75b59ca634813d572de800e8f

