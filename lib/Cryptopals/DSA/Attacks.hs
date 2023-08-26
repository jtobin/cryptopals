module Cryptopals.DSA.Attacks where

import qualified Control.Monad.ST as ST
import qualified Cryptopals.DH as DH
import qualified Cryptopals.Digest.Pure.SHA as CS
import Cryptopals.DSA
import qualified Cryptopals.RSA as RSA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import GHC.Word (Word16)
import Numeric.Natural
import qualified System.Random.MWC as MWC

-- recover private key given a subkey
fromsub :: Params -> BS.ByteString -> Sig -> Natural -> Key
fromsub Params {..} msg Sig {..} k =
  let h   = fromIntegral . CS.integerDigest . CS.sha1 $ BL.fromStrict msg
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
      let sk@(Sec x) = fromsub ps msg sig (fromIntegral k)
      sig' <- sign ps sk msg g
      if   DH.modexp dsag x dsap == p && verify ps pub msg sig'
      then pure sk
      else loop (succ k) g

rawmsg :: BS.ByteString
rawmsg = mconcat [
    "For those that envy a MC it can be hazardous to your health\n"
  , "So be friendly, a matter of life and death, just like a etch-a-sketch\n"
  ]

rawpub :: Key
rawpub = Pub 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17

rawsig :: Sig
rawsig = Sig {
    sigr = 548099063082341131477253921760299949438196259240
  , sigs = 857042759984254168557880549501802188789837994940
  }

