module Cryptopals.AES.Mode where

import Control.Monad
import Control.Monad.Primitive
import qualified Data.ByteString as BS
import qualified System.Random.MWC as MWC

genKeyAES128 :: PrimMonad m => MWC.Gen (PrimState m) -> m BS.ByteString
genKeyAES128 gen = fmap BS.pack $ replicateM 16 (MWC.uniform gen)

