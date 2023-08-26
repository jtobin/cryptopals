module Cryptopals.DSA (
    Params(..)
  , defaultParams

  , Keypair(..)
  , Key(..)
  , keygen

  , Sig(..)
  , sign
  , sign'
  , verify

  , unsafeSign
  , unsafeVerify
  ) where

import Control.Monad.Primitive
import qualified Cryptopals.Digest.Pure.SHA as CS
import qualified Cryptopals.DH as DH
import qualified Cryptopals.RSA as RSA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Numeric.Natural
import qualified System.Random.MWC as MWC

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral

data Params = Params {
    dsap :: Natural
  , dsaq :: Natural
  , dsag :: Natural
  } deriving (Eq, Show)

p :: Natural
p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1

q :: Natural
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

g :: Natural
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

defaultParams :: Params
defaultParams = Params p q g

data Keypair = Keypair {
    sec :: Key
  , pub :: Key
  } deriving (Eq, Show)

data Key =
    Pub Natural
  | Sec Natural
  deriving (Eq, Show)

keygen :: PrimMonad m => Params -> MWC.Gen (PrimState m) -> m Keypair
keygen Params {..} gen = do
  x <- MWC.uniformRM (1, dsaq - 1) gen
  let y = DH.modexp dsag x dsap
  pure $ Keypair (Sec x) (Pub y)

data Sig = Sig {
    sigr :: Natural
  , sigs :: Natural
  } deriving (Eq, Show)

sign
  :: PrimMonad m
  => Params
  -> Key
  -> BS.ByteString
  -> MWC.Gen (PrimState m)
  -> m Sig
sign ps@Params {..} key msg gen = case key of
  Pub {} -> error "sign: need secret key"
  Sec x  -> do
    k <- MWC.uniformRM (1, dsaq - 1) gen
    let r = DH.modexp dsag k p `rem` dsaq
    if   r == 0
    then sign ps key msg gen
    else do
      let h = fi . CS.integerDigest . CS.sha1 $ BL.fromStrict msg
          s = (RSA.modinv' k dsaq * (h + x * r)) `rem` dsaq
      if   s == 0
      then sign ps key msg gen
      else pure (Sig r s)

-- sign with provided subkey/nonce
sign'
  :: Params
  -> Key
  -> Natural
  -> BS.ByteString
  -> Sig
sign' ps@Params {..} key k msg = case key of
  Pub {} -> error "sign: need secret key"
  Sec x  ->
    let r = DH.modexp dsag k p `rem` dsaq
    in  if   r == 0
        then error "sign': invalid nonce (r)"
        else
          let h = fi . CS.integerDigest . CS.sha1 $ BL.fromStrict msg
              s = (RSA.modinv' k dsaq * (h + x * r)) `rem` dsaq
          in  if   s == 0
              then error "sign': invalid nonce (s)"
              else Sig r s

-- don't check for bad signature values
unsafeSign
  :: PrimMonad m
  => Params
  -> Key
  -> BS.ByteString
  -> MWC.Gen (PrimState m)
  -> m Sig
unsafeSign ps@Params {..} key msg gen = case key of
  Pub {} -> error "sign: need secret key"
  Sec x  -> do
    k <- MWC.uniformRM (1, dsaq - 1) gen
    let r = DH.modexp dsag k p `rem` dsaq
        h = fi . CS.integerDigest . CS.sha1 $ BL.fromStrict msg
        s = (RSA.modinv' k dsaq * (h + x * r)) `rem` dsaq
    pure (Sig r s)

verify
  :: Params
  -> Key
  -> BS.ByteString
  -> Sig
  -> Bool
verify Params {..} key msg Sig {..} = case key of
  Sec {} -> error "verify: need public key"
  Pub y
    | or [sigr == 0, sigr >= dsaq, sigs == 0, sigs >= dsaq] -> False
    | otherwise ->
        let w  = RSA.modinv' sigs dsaq
            h  = fi . CS.integerDigest . CS.sha1 $ BL.fromStrict msg
            u1 = (h * w) `rem` dsaq
            u2 = (sigr * w) `rem` dsaq
            v  = (((DH.modexp dsag u1 dsap) * (DH.modexp y u2 dsap)) `rem` dsap)
                   `rem` dsaq
        in  v == sigr

-- don't check for bad signature parameters
unsafeVerify
  :: Params
  -> Key
  -> BS.ByteString
  -> Sig
  -> Bool
unsafeVerify Params {..} key msg Sig {..} = case key of
  Sec {} -> error "verify: need public key"
  Pub y  ->
    let w  = RSA.modinv' sigs dsaq
        h  = fi . CS.integerDigest . CS.sha1 $ BL.fromStrict msg
        u1 = (h * w) `rem` dsaq
        u2 = (sigr * w) `rem` dsaq
        v  = (((DH.modexp dsag u1 dsap) * (DH.modexp y u2 dsap)) `rem` dsap)
               `rem` dsaq
    in  v == sigr

