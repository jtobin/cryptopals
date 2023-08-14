{-# LANGUAGE RecordWildCards #-}

module Cryptopals.DH (
    p
  , g
  , modexp
  ) where

import Control.Monad.Primitive
import Control.Monad.Trans.State (StateT)
import qualified Control.Monad.Trans.State as S
import Cryptopals.DH.Core
import Cryptopals.DH.Session
import qualified Data.ByteString as BS
import qualified Data.Text as T
import GHC.Word (Word32)
import Numeric.Natural
import Pipes
import qualified Pipes.Binary as PB
import qualified Pipes.Network as PN
import qualified System.Random.MWC as MWC

-- await key exchange
bob :: MonadIO m => PN.ServiceName -> m a
bob port = PN.serve "localhost" port $ \(sock, _) -> do
  let sesh = Sesh {
          dhGroup = Nothing
        , dhKeys  = Nothing
        , dhKey   = Nothing
        , dhGen   = MWC.createSystemRandom
        }
  slog "bob" $ "listening.."
  void $ S.evalStateT (runEffect (session "bob" sock)) sesh

-- initiate key exchange
alice :: PN.ServiceName -> IO ()
alice port = PN.connect "localhost" port $ \(sock, _) -> do
  slog "alice" $ "session established"

  let grp = Group p g
  gen <- MWC.createSystemRandom
  per@Keys {..} <- genpair grp gen
  slog "alice" $ "sending group parameters and public key"
  runEffect $ do
        PB.encode (Just (SendParams grp pub))
    >-> PN.toSocket sock

  let sesh = Sesh {
          dhGroup = Just grp
        , dhKeys  = Just per
        , dhKey   = Nothing
        , dhGen   = pure gen
        }
  void $ S.runStateT (runEffect (session "alice" sock)) sesh

-- await key exchange
mallory :: MonadIO m => PN.ServiceName -> PN.ServiceName -> m a
mallory port bport =
  PN.serve "localhost" port $ \(asock, _) -> do
    slog "mallory" $ "LiSteNIng.."
    PN.connect "localhost" bport $ \(bsock, _) -> do
      let sesh = Sesh {
              dhGroup = Nothing
            , dhKeys  = Nothing
            , dhKey   = Nothing
            , dhGen   = MWC.createSystemRandom
            }
      slog "mallory" $ "eStabLisHed coNNecTion"
      void $ S.runStateT (runEffect (dance "mallory" asock bsock)) sesh

