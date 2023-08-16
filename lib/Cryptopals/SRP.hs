{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}

module Cryptopals.SRP where

import Control.Concurrent (threadDelay)
import Control.Monad
import Control.Monad.Primitive
import Control.Monad.IO.Class
import Control.Monad.Trans.Class
import Control.Monad.Trans.Reader
import Control.Monad.Trans.State
import qualified Cryptopals.Digest.Pure.SHA as CS
import qualified Cryptopals.DH as DH (modexp)
import qualified Data.Binary as DB
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import GHC.Generics (Generic)
import GHC.Word (Word64)
import Numeric.Natural
import Pipes
import qualified Pipes.Binary as PB
import qualified Pipes.Network as PN
import qualified System.Exit as SE
import qualified System.Random.MWC as MWC

-- common parameters
data Env = Env {
    en :: Natural
  , eg :: Natural
  , ek :: Natural
  , ei :: BS.ByteString
  , ep :: BS.ByteString
  } deriving (Eq, Show, Generic)

defaultEnv :: Env
defaultEnv = Env {
    en = p192
  , eg = 2
  , ek = 3
  , ei = "l33th4x0r@hotmail.com"
  , ep = "hunter2"
  }

instance DB.Binary Env

data Command =
    Auth BS.ByteString Natural
  | AckAuth BS.ByteString Natural
  | SendMAC BS.ByteString
  | End
  deriving (Eq, Show, Generic)

instance DB.Binary Command

-- generic state
data Sesh = Sesh {
    shost    :: T.Text
  , ssalt    :: Maybe BS.ByteString
  , skey     :: Natural
  , sourpub  :: Natural
  , sherpub  :: Maybe Natural
  , sv       :: Maybe Natural
  , sgen     :: IO (MWC.Gen RealWorld)
  }

type SRP m = StateT Sesh (ReaderT Env m)

server
  :: (DB.Binary b, DB.Binary c)
  => PN.ServiceName
  -> PN.Protocol (SRP IO) b c
  -> IO ()
server port eval = PN.serve "localhost" port $ \(sock, _) -> do
  sesh <- initServer defaultEnv
  blog "server" "listening.."
  let saction = runEffect (PN.session sock eval)
  void $ runReaderT (evalStateT saction sesh) defaultEnv

client
  :: (DB.Binary b, DB.Binary c)
  => PN.ServiceName
  -> PN.Protocol (SRP IO) b c
  -> SRP IO Command
  -> IO ()
client port eval knit = PN.connect "localhost" port $ \(sock, _) -> do
  sesh <- initClient defaultEnv
  blog "client" "session established"

  (cmd, nex) <- runReaderT (runStateT knit sesh) defaultEnv

  runEffect $
        PB.encode cmd
    >-> PN.toSocket sock

  let saction = runEffect (PN.session sock eval)
  void $ runReaderT (runStateT saction nex) defaultEnv

auth :: SRP IO Command
auth = do
  Env {..} <- lift ask
  pub <- gets sourpub
  slog "sending authentication request"
  pure (Auth ei pub)

-- basic log
blog :: T.Text -> T.Text -> IO ()
blog host msg = do
  TIO.putStrLn $ "(cryptopals) " <> host <> ": " <> msg
  suspense

-- session log
slog :: MonadIO m => T.Text -> StateT Sesh m ()
slog msg = do
  host <- gets shost
  liftIO . TIO.putStrLn $ "(cryptopals) " <> host <> ": " <> msg
  liftIO suspense

-- dramatic effect
suspense :: IO ()
suspense = threadDelay 1000000

-- 2 ^ 192 - 2 ^ 64 - 1
p192 :: Natural
p192 = 6277101735386680763835789423207666416083908700390324961279

initServer :: Env -> IO Sesh
initServer Env {..} = do
  gen <- MWC.createSystemRandom
  skey <- MWC.uniformRM (1, en - 1) gen
  salt <- fmap DB.encode (MWC.uniform gen :: IO Word64)
  let xH      = CS.sha256 (salt <> BL.fromStrict ep)
      x       = fromIntegral (CS.integerDigest xH)
      v       = DH.modexp eg x en
      strsalt = BL.toStrict salt
      sourpub = ek * v + DH.modexp eg skey en
  pure Sesh {
      sgen    = pure gen
    , ssalt   = pure strsalt
    , sv      = pure v
    , sherpub = Nothing
    , shost   = "server"
    , ..
    }

initClient :: Env -> IO Sesh
initClient Env {..} = do
  gen <- MWC.createSystemRandom
  skey <- MWC.uniformRM (1, en - 1) gen
  let sourpub = DH.modexp eg skey en
  pure Sesh {
      sgen    = pure gen
    , sherpub = Nothing
    , ssalt   = Nothing
    , sv      = Nothing
    , shost   = "client"
    , ..
    }

-- secure remote password protocol
srp :: MonadIO m => PN.Protocol (SRP m) Command Command
srp cmd = do
  Env {..} <- lift ask
  case cmd of
    Auth i herpub -> do
      let li = TE.decodeLatin1 i
      slog $ "received authentication request for " <> li
      if   i /= ei
      then do
        slog $ "unknown user " <> li
        pure End
      else do
        sesh@Sesh {..} <- get
        put sesh {
            sherpub = Just herpub
          }
        case ssalt of
          Nothing -> do
            slog "missing required parameters"
            pure End
          Just salt -> do
            slog $ "acking authentication request for " <> li
            pure (AckAuth salt sourpub)

    AckAuth salt herpub -> do
      slog "received authentication request ack"
      sesh@Sesh {..} <- get
      put sesh {
          ssalt   = Just salt
        , sherpub = Just herpub
        }
      let u = hashpubs sourpub herpub
          x = fromIntegral
            . CS.integerDigest
            . CS.sha256
            $ BL.fromStrict (salt <> ep)
          s = DH.modexp
                (herpub - ek * DH.modexp eg x en)
                (skey + u * x)
                en
          k = CS.bytestringDigest
            . CS.sha256
            . DB.encode
            $ s
      let mac = BL.toStrict
              . CS.bytestringDigest
              $ CS.hmacSha256 k (BL.fromStrict salt)
      slog $ "sending MAC " <> B64.encodeBase64 mac
      pure (SendMAC mac)

    SendMAC mac -> do
      slog $ "received MAC " <> B64.encodeBase64 mac
      sesh@Sesh {..} <- get
      case (,,) <$> ssalt <*> sv <*> sherpub of
        Nothing -> do
          slog "missing required parameters"
          pure End
        Just (salt, v, herpub) -> do
          let u = hashpubs herpub sourpub
              s = DH.modexp (herpub * DH.modexp v u en) skey en
              k = CS.bytestringDigest
                . CS.sha256
                . DB.encode
                $ s
              hmac = BL.toStrict
                   . CS.bytestringDigest
                   $ CS.hmacSha256 k (BL.fromStrict salt)
          if   hmac == mac
          then do
            slog "OK"
            pure End
          else do
            slog "couldn't verify MAC"
            pure End

    End -> do
      slog "ending session"
      liftIO SE.exitSuccess -- XX close the socket

hashpubs :: Natural -> Natural -> Natural
hashpubs a b =
    fromIntegral
  . CS.integerDigest
  . CS.sha256
  $ DB.encode a <> DB.encode b

