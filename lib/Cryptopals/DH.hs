{-# LANGUAGE RecordWildCards #-}

module Cryptopals.DH (
    p
  , g
  , modexp
  , encodekey
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
  -> PN.Protocol (StateT Sesh IO) b c
  -> IO ()
bob port eval = PN.serve "localhost" port $ \(sock, _) -> do
  let host = "bob"
      sesh = open sock host
  blog host "listening.."
  void $ S.evalStateT (runEffect (PN.session sock eval)) sesh

-- initiate key exchange
alice
  :: (DB.Binary b, DB.Binary c)
  => PN.ServiceName
  -> PN.Protocol (StateT Sesh IO) b c
  -> StateT Sesh IO Command
  -> IO ()
alice port eval knit = PN.connect "localhost" port $ \(sock, _) -> do
  let host = "alice"
      sesh = open sock host
  blog host "session established"

  (cmd, nex) <- S.runStateT knit sesh

  runEffect $
        PB.encode (Just cmd)
    >-> PN.toSocket sock

  void $ S.runStateT (runEffect (PN.session sock eval)) nex

-- await key exchange
mallory
  :: (DB.Binary b, DB.Binary c)
  => PN.ServiceName
  -> PN.ServiceName
  -> PN.Protocol (StateT Sesh IO) b c
  -> IO ()
mallory port bport eval = do
  let host = "mallory"
  PN.serve "localhost" port $ \(asock, _) -> do
    let sesh = open asock host
    blog host  "LiSteNIng.."
    PN.connect "localhost" bport $ \(bsock, _) -> do
      blog host "eStabLisHed MiTm coNNecTion"
      void $ S.runStateT (runEffect (PN.dance asock bsock eval)) sesh

-- initialize session with basic stuff
open :: PN.Socket -> T.Text -> Sesh
open sock host = Sesh {
    dhGroup = Nothing
  , dhHost  = host
  , dhSock  = sock
  , dhKeys  = Nothing
  , dhKey   = Nothing
  , dhGen   = MWC.createSystemRandom
  }

sendParams :: StateT Sesh IO Command
sendParams = do
  grp <- genGroup p g
  Keys {..} <- genKeypair
  slog "sending group parameters and public key"
  pure (SendParams grp pub)

sendGroup :: StateT Sesh IO Command
sendGroup = do
  grp <- genGroup p g
  slog "sending group parameters"
  pure (SendGroup grp)
