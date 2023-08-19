module Cryptopals.SRP.Simple where

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
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as BL8
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

data Word128 = Word128 !Word64 !Word64
  deriving (Eq, Show, Generic)

instance DB.Binary Word128

genWord128 :: PrimMonad m => MWC.Gen (PrimState m) -> m Word128
genWord128 gen = Word128 <$> MWC.uniform gen <*> MWC.uniform gen

word128toNat :: Word128 -> Natural
word128toNat w = foldr alg 0 . BS.unpack . BL.toStrict $ bs where
  bs = DB.encode w
  alg b a = a `B.shiftL` 8 B..|. fromIntegral b

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

genPassword :: MWC.Gen RealWorld -> IO BS.ByteString
genPassword gen = do
  idx <- MWC.uniformR (0, 235885) gen
  dict <- BL8.readFile "/usr/share/dict/words"
  let ls = BL8.lines dict
  pure . BL.toStrict $ ls !! idx

initEnv :: MWC.Gen RealWorld -> IO Env
initEnv gen = do
  ep <- genPassword gen
  pure Env {
      en = p192
    , eg = 2
    , ek = 3
    , ei = "l33th4x0r@hotmail.com"
    , ..
    }

instance DB.Binary Env

data Command =
    Auth BS.ByteString Natural
  | AckAuth BS.ByteString Natural Natural
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
  , su       :: Maybe Natural
  , sgen     :: IO (MWC.Gen RealWorld)
  }

instance Show Sesh where
  show Sesh {..} = mconcat [
      "Sesh {\n"
    , "  shost    = " <> show shost <> "\n"
    , "  ssalt    = " <> show ssalt <> "\n"
    , "  skey     = " <> show skey <> "\n"
    , "  sourpub  = " <> show sourpub <> "\n"
    , "  sherpub  = " <> show sherpub <> "\n"
    , "  sv       = " <> show sv <> "\n"
    , "  su       = " <> show su <> "\n"
    , "  sgen     = <MWC.Gen>\n"
    , "}"
    ]

type SRP m = StateT Sesh (ReaderT Env m)

server
  :: (DB.Binary b, DB.Binary c)
  => PN.ServiceName
  -> PN.Protocol (SRP IO) b c
  -> IO ()
server port eval = PN.serve "localhost" port $ \(sock, _) -> do
  gen <- MWC.createSystemRandom
  env <- initEnv gen
  sesh <- initServer env gen
  blog "server" "listening.."
  let saction = runEffect (PN.session sock eval)
  void $ runReaderT (evalStateT saction sesh) defaultEnv

mallory
  :: (DB.Binary b, DB.Binary c)
  => PN.ServiceName
  -> PN.Protocol (SRP IO) b c
  -> IO ()
mallory port eval = PN.serve "localhost" port $ \(sock, _) -> do
  gen <- MWC.createSystemRandom
  env <- initEnv gen
  sesh <- initMallory env gen
  blog "mallory" "LiSteNiNG.."
  let saction = runEffect (PN.session sock eval)
  void $ runReaderT (evalStateT saction sesh) defaultEnv

client
  :: (DB.Binary b, DB.Binary c)
  => PN.ServiceName
  -> PN.Protocol (SRP IO) b c
  -> SRP IO Command
  -> IO ()
client port eval knit = PN.connect "localhost" port $ \(sock, _) -> do
  gen <- MWC.createSystemRandom
  env <- initEnv gen
  sesh <- initClient defaultEnv gen
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

initServer :: Env -> MWC.Gen RealWorld -> IO Sesh
initServer Env {..} gen = do
  skey <- MWC.uniformRM (1, en - 1) gen
  u <- word128toNat <$> genWord128 gen
  salt <- DB.encode <$> (MWC.uniform gen :: IO Word64)
  let xH      = CS.sha256 (salt <> BL.fromStrict ep)
      x       = fromIntegral (CS.integerDigest xH)
      v       = DH.modexp eg x en
      strsalt = BL.toStrict salt
      sourpub = DH.modexp eg skey en
  pure Sesh {
      sgen    = pure gen
    , ssalt   = pure strsalt
    , sv      = pure v
    , su      = pure u
    , sherpub = Nothing
    , shost   = "server"
    , ..
    }

initMallory :: Env -> MWC.Gen RealWorld -> IO Sesh
initMallory Env {..} gen = do
  let skey = 1
      u    = 1
      sourpub = 2
  pure Sesh {
      sgen    = pure gen
    , ssalt   = pure mempty
    , sv      = Nothing
    , su      = pure u
    , sherpub = Nothing
    , shost   = "mallory"
    , ..
    }

initClient :: Env -> MWC.Gen RealWorld -> IO Sesh
initClient Env {..} gen = do
  skey <- MWC.uniformRM (1, en - 1) gen
  let sourpub = DH.modexp eg skey en
  pure Sesh {
      sgen    = pure gen
    , sherpub = Nothing
    , ssalt   = Nothing
    , sv      = Nothing
    , su      = Nothing
    , shost   = "client"
    , ..
    }

-- simple secure remote password protocol
srpsimple :: MonadIO m => PN.Protocol (SRP m) Command Command
srpsimple cmd = do
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
        case (,) <$> ssalt <*> su of
          Nothing -> do
            slog "missing required parameters"
            pure End
          Just (salt, u) -> do
            slog $ "acking authentication request for " <> li
            pure (AckAuth salt sourpub u)

    AckAuth salt herpub u -> do
      slog "received authentication request ack"
      sesh@Sesh {..} <- get
      put sesh {
          ssalt   = Just salt
        , sherpub = Just herpub
        , su      = Just u
        }
      let x = fromIntegral
            . CS.integerDigest
            . CS.sha256
            $ BL.fromStrict (salt <> ep)
          s = DH.modexp herpub (skey + u * x) en
          k = CS.bytestringDigest
            . CS.sha256
            . DB.encode
            $ s
      let mac = BL.toStrict
              . CS.bytestringDigest
              $ CS.hmacSha256 k (BL.fromStrict salt)
      slog $ "sending MAC " <> B16.encodeBase16 mac
      pure (SendMAC mac)

    SendMAC mac -> do
      slog $ "received MAC " <> B16.encodeBase16 mac
      sesh@Sesh {..} <- get
      case (,,,) <$> ssalt <*> sv <*> sherpub <*> su of
        Nothing -> do
          slog "missing required parameters"
          pure End
        Just (salt, v, herpub, u) -> do
          let s = DH.modexp (herpub * DH.modexp v u en) skey en
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

-- MITM on simple secure remote password protocol
mitm :: MonadIO m => PN.Protocol (SRP m) Command Command
mitm cmd = do
  Env {..} <- lift ask
  case cmd of
    Auth i herpub -> do
      let li = TE.decodeLatin1 i
      slog $ "rECeIvEd aUTheNtICaTioN ReQUesT fOr " <> li
      slog $ "wiTh PuBLiC kEy " <> (T.pack . show) herpub
      if   i /= ei
      then do
        slog $ "unknown user " <> li
        pure End
      else do
        sesh@Sesh {..} <- get
        put sesh {
            sherpub = Just herpub
          }
        case (,) <$> ssalt <*> su of
          Nothing -> do
            slog "missing required parameters"
            pure End
          Just (salt, u) -> do
            slog $ "aCKiNg AuTheNTicAtIon ReQueST FOr " <> li
            pure (AckAuth salt sourpub u)

    SendMAC mac -> do
      slog $ "rECeIvEd MAC " <> B16.encodeBase16 mac
      sesh@Sesh {..} <- get

      case sherpub of
        Nothing -> do
          slog "missing required parameters"
          pure End
        Just (T.pack . show -> herpub) -> do
          slog $ "USiNg PaRaMeTeRs " <> herpub
              <> " aNd " <> B16.encodeBase16 mac
          slog "GoINg ofFLinE.."
          pure End

    _ -> srpsimple cmd

