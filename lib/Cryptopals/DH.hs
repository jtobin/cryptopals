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
import qualified Data.Binary as DB
import qualified Data.ByteString as BS
import qualified Data.Text as T
import GHC.Word (Word32)
import Numeric.Natural
import Pipes
import qualified Pipes.Binary as PB
import qualified Pipes.Network as PN
import qualified System.Random.MWC as MWC

-- await key exchange
bob
  :: (DB.Binary b, DB.Binary c)
  => PN.ServiceName
  -> Handler (StateT Sesh IO) b c
  -> IO ()
bob port eval = PN.serve "localhost" port $ \(sock, _) -> do
  let host = "bob"
      sesh = Sesh {
          dhGroup = Nothing
        , dhHost  = host
        , dhKeys  = Nothing
        , dhKey   = Nothing
        , dhGen   = MWC.createSystemRandom
        }
  blog host "listening.."
  void $ S.evalStateT (runEffect (session sock eval)) sesh

-- initiate key exchange
alice
  :: (DB.Binary b, DB.Binary c)
  => PN.ServiceName
  -> Handler (StateT Sesh IO) b c
  -> IO ()
alice port eval = PN.connect "localhost" port $ \(sock, _) -> do
  let host = "alice"
  blog host "session established"

  let grp = Group p g
  gen <- MWC.createSystemRandom
  per@Keys {..} <- genpair grp gen
  blog host "sending group parameters and public key"
  runEffect $ do
        PB.encode (Just (SendParams grp pub))
    >-> PN.toSocket sock

  let sesh = Sesh {
          dhGroup = Just grp
        , dhHost  = host
        , dhKeys  = Just per
        , dhKey   = Nothing
        , dhGen   = pure gen
        }
  void $ S.runStateT (runEffect (session sock eval)) sesh

-- await key exchange, initiate key exchange
mallory
  :: (DB.Binary b, DB.Binary c)
  => PN.ServiceName
  -> PN.ServiceName
  -> Handler (StateT Sesh IO) b c
  -> IO ()
mallory port bport eval = do
  let host = "mallory"
  PN.serve "localhost" port $ \(asock, _) -> do
    blog host  "LiSteNIng.."
    PN.connect "localhost" bport $ \(bsock, _) -> do
      let sesh = Sesh {
              dhGroup = Nothing
            , dhHost  = host
            , dhKeys  = Nothing
            , dhKey   = Nothing
            , dhGen   = MWC.createSystemRandom
            }
      blog host "eStabLisHed coNNecTion"
      void $ S.runStateT (runEffect (dance asock bsock eval)) sesh

