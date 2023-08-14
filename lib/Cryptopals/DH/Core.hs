{-# LANGUAGE DeriveGeneric #-}

module Cryptopals.DH.Core (
    Group(..)
  , p
  , g

  , Keys(..)

  , modexp
  , genpair
  , derivekey
  ) where

import Control.Monad.Primitive
import qualified Cryptopals.Digest.Pure.SHA as CS
import Data.Binary as DB
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import GHC.Generics (Generic)
import Numeric.Natural
import qualified System.Random.MWC as MWC

data Group = Group Natural Natural
  deriving (Eq, Show, Generic)

instance DB.Binary Group

p :: Natural
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

g :: Natural
g = 2

data Keys = Keys {
    pub :: Natural
  , sec :: Natural
  }

-- modified from https://gist.github.com/trevordixon/6788535
modexp :: Natural -> Natural -> Natural -> Natural
modexp b e m
  | e == 0    = 1
  | otherwise =
      let t = if B.testBit e 0 then b `mod` m else 1
      in  t * modexp ((b * b) `mod` m) (B.shiftR e 1) m `mod` m

-- generate public, private keypair
genpair
  :: PrimMonad m
  => Group
  -> MWC.Gen (PrimState m)
  -> m Keys
genpair (Group p g) gen = do
  sk <- fmap (`mod` p) (MWC.uniformRM (1, p - 1) gen)
  let pk = modexp g sk p
  pure $ Keys pk sk

-- derive shared key from secret and other public
derivekey :: Group -> Keys -> Natural -> BS.ByteString
derivekey (Group p _) Keys {..} pk =
  let nat = modexp pk sec p
  in  BS.take 16 . BL.toStrict . CS.bytestringDigest $ CS.sha1 (DB.encode nat)

