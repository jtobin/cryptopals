module Cryptopals.DH.Session (
    Command(..)
  , genGroup
  , genKeypair

  , Sesh(..)

  , blog
  , slog

  , dh
  , dhng

  , dhmitm
  , dhngmitm
  ) where

import Control.Concurrent (threadDelay)
import Control.Monad.Primitive
import Control.Monad.IO.Class
import Control.Monad.Trans.State (StateT)
import qualified Control.Monad.Trans.State as S
import qualified Cryptopals.AES as AES
import Cryptopals.DH.Core
import qualified Cryptopals.Digest.Pure.SHA as CS
import qualified Cryptopals.Util as CU
import qualified Data.Binary as DB
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as B8
import qualified Data.Char as C
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import GHC.Generics (Generic)
import GHC.Word (Word32)
import qualified Network.Socket.ByteString as NB
import Numeric.Natural
import Pipes
import qualified Pipes.Binary as PB
import qualified Pipes.Network as PN
import qualified Pipes.Parse as PP
import qualified Pipes.Prelude as P
import qualified System.Exit as SE
import qualified System.Random.MWC as MWC

data Command =
    SendGroup Group                   -- group only
  | AckGroup                          -- ack receipt of group params
  | SendParams Group Natural          -- group + public key
  | SendPublic Natural                -- public key only
  | SendMessage BS.ByteString         -- send initial ciphertext
  | SendTerminal BS.ByteString        -- send final ciphertext
  deriving (Eq, Show, Generic)

instance DB.Binary Command

-- session state
data Sesh = Sesh {
    dhGroup       :: Maybe Group
  , dhHost        :: T.Text
  , dhSock        :: PN.Socket
  , dhKeys        :: Maybe Keys
  , dhKey         :: Maybe BS.ByteString
  , dhGen         :: IO (MWC.Gen RealWorld)
  }

-- basic log
blog :: T.Text -> T.Text -> IO ()
blog host msg = TIO.putStrLn $ "(cryptopals) " <> host <> ": " <> msg

-- session log
slog :: T.Text -> StateT Sesh IO ()
slog msg = do
  host <- S.gets dhHost
  liftIO $ TIO.putStrLn $ "(cryptopals) " <> host <> ": " <> msg
  liftIO suspense

-- dramatic effect
suspense :: IO ()
suspense = threadDelay 1000000

-- generic session evaluator
seval
  :: (Command -> StateT Sesh IO a)
  -> Maybe Command
  -> StateT Sesh IO a
seval cont = \case
  Nothing -> do
    slog "ending session"
    liftIO $ SE.exitSuccess -- XX should really just close the socket
  Just cmd -> do
    liftIO suspense
    cont cmd

-- basic dh evaluation
dh :: PN.Protocol (StateT Sesh IO) (Maybe Command) (Maybe Command)
dh = seval dheval

-- mitm dh evaluation
dhmitm :: PN.Protocol (StateT Sesh IO) (Maybe Command) (Maybe Command)
dhmitm = seval mitmeval

-- negotiated-group dh evaluation
dhng :: PN.Protocol (StateT Sesh IO) (Maybe Command) (Maybe Command)
dhng = seval ngeval

-- mitm negotiated-group dh evaluation
dhngmitm
  :: Natural
  -> PN.Protocol (StateT Sesh IO) (Maybe Command) (Maybe Command)
dhngmitm = seval . malgeval

-- diffie-hellman protocol eval
dheval
  :: Command
  -> StateT Sesh IO (Maybe Command)
dheval = \case
  SendGroup _ -> do
    slog "missing public key, aborting.."
    pure Nothing

  AckGroup -> do
    slog "didn't send group, aborting.."
    pure Nothing

  SendParams grp pk -> do
    slog $ "received group parameters and public key " <> renderkey pk
    S.modify (\sesh -> sesh { dhGroup = Just grp })
    Keys {..} <- genKeypair
    deriveKey pk
    slog $ "sending public key " <> renderkey pk
    pure $ Just (SendPublic pub)

  SendPublic pk -> do
    slog $ "received public key " <> renderkey pk
    sesh@Sesh {..} <- S.get
    k <- deriveKey pk
    cip <- encrypt "attack at 10pm"
    S.put sesh { dhKey = Just k }
    slog $ "sending ciphertext " <> B64.encodeBase64 cip
    pure $ Just (SendMessage cip)

  SendMessage cip -> do
    slog $ "received ciphertext " <> B64.encodeBase64 cip
    sesh@Sesh {..} <- S.get
    msg <- decrypt cip
    slog $ "decrypted ciphertext: \"" <> TE.decodeLatin1 msg <> "\""
    ncip <- encrypt $ "confirmed, attacking at 10pm"
    slog $ "replying with ciphertext " <> B64.encodeBase64 ncip
    pure $ Just (SendTerminal ncip)

  SendTerminal cip -> do
    slog $ "received ciphertext " <> B64.encodeBase64 cip
    sesh@Sesh {..} <- S.get
    msg <- decrypt cip
    slog $ "decrypted ciphertext: \"" <> TE.decodeLatin1 msg <> "\""
    pure Nothing

-- man-in-the-middle protocol eval
mitmeval
  :: Command
  -> StateT Sesh IO (Maybe Command)
mitmeval = \case
  SendParams grp pk -> do
    slog $ "reCEiVed GRoUp pArAmeTErs And pUBliC kEy " <> renderkey pk
    sesh@Sesh {..} <- S.get
    let key = derivekey grp (Keys p 1) p
        nex = sesh { dhKey = Just key }
    S.put nex
    slog $ "sEnDinG BOguS paRaMeTeRs wIth PuBLiC kEy " <> renderkey p
    pure $ Just (SendParams grp p)

  SendPublic pk -> do
    slog $ "REceIvED pUBlic keY " <> renderkey pk
    slog $ "seNDINg boGus kEy " <> renderkey p
    pure $ Just (SendPublic p)

  SendMessage cip -> do
    slog $ "rECeIveD CiPHeRTexT " <> B64.encodeBase64 cip
    sesh@Sesh {..} <- S.get
    mmsg <- decryptLenient cip
    case mmsg of
      Nothing ->
        slog "couLdN'T DeCRyPt CiPHertExT"
      Just msg ->
        slog $ "DEcRyptEd cIPheRTeXt: \"" <> TE.decodeLatin1 msg <> "\""
    slog "reLayINg cIpheRtExt"
    pure $ Just (SendMessage cip)

  SendTerminal cip -> do
    slog $ "reCeiVeD CipHeRtExt " <> B64.encodeBase64 cip
    sesh@Sesh {..} <- S.get
    mmsg <- decryptLenient cip
    case mmsg of
      Nothing ->
        slog "couLdN'T DeCRyPt CiPHertExT"
      Just msg ->
        slog $ "DeCrYpteD cIphErteXt: \"" <> TE.decodeLatin1 msg <> "\""
    slog "ReLaYINg CiPHeRTexT"
    pure (Just (SendTerminal cip))

  cmd -> do
    slog "RelAyInG coMmaNd"
    pure (Just cmd)

-- negotiated-group protocol eval
ngeval
  :: Command
  -> StateT Sesh IO (Maybe Command)
ngeval = \case
  SendGroup grp -> do
    slog "received group parameters"
    sesh@Sesh {..} <- S.get
    S.put sesh { dhGroup = Just grp }
    slog "acking group parameters"
    pure (Just AckGroup)

  AckGroup -> do
    slog "received ack"
    sesh@Sesh {..} <- S.get
    Keys {..} <- genKeypair
    slog $ "sending public key " <> renderkey pub
    pure $ Just (SendPublic pub)

  SendParams {} -> do
    slog "not expecting group parameters and public key"
    pure Nothing

  SendPublic pk -> do
    slog $ "received public key " <> renderkey pk
    sesh@Sesh {..} <- S.get
    case dhKeys of
      Nothing -> do
        Keys {..} <- genKeypair
        key <- deriveKey pk
        slog "sending public key"
        pure (Just (SendPublic pub))
      Just Keys {..} -> do
        key <- deriveKey pk
        cip <- encrypt "attack at 10pm"
        slog $ "sending ciphertext " <> B64.encodeBase64 cip
        pure (Just (SendMessage cip))

  cmd -> dheval cmd

-- negotiated-group mitm protocol eval
malgeval
  :: Natural
  -> Command
  -> StateT Sesh IO (Maybe Command)
malgeval malg = \case
  SendGroup grp -> do
    slog "reCEiVed GRoUp pArAmeTErs"
    sesh <- S.get
    let key = derivekey grp (Keys p malg) malg
    S.put sesh {
        dhGroup = Just grp
      , dhKey   = Just key
      }
    let malgrp = Group p malg
    slog "sEnDinG BOguS GRoUp paRaMeTeRs"
    pure $ Just (SendGroup malgrp)

  AckGroup -> do
    slog "rECeiVed aCK"
    slog "ReLaYINg ACk"
    pure (Just AckGroup)

  SendParams grp pk -> do
    slog "nOt eXPecTinG gRoUp and PublIc KeY"
    pure Nothing

  SendPublic pk -> do
    slog $ "REceIvED pUBlic keY " <> renderkey pk
    slog $ "SeNDing BoGuS kEy " <> renderkey malg
    pure $ Just (SendPublic malg)

  cmd -> mitmeval cmd

genGroup :: Natural -> Natural -> StateT Sesh IO Group
genGroup p g = do
  sesh <- S.get
  let grp = Group p g
  S.put sesh {
      dhGroup = Just grp
    }
  pure grp

genKeypair :: StateT Sesh IO Keys
genKeypair = do
  sesh@Sesh {..} <- S.get
  case dhGroup of
    Nothing -> do
      slog "missing group parameters"
      liftIO SE.exitFailure
    Just grp -> do
      gen <- liftIO dhGen
      per <- liftIO $ genpair grp gen
      S.put sesh {
          dhKeys = Just per
        }
      pure per

deriveKey :: Natural -> StateT Sesh IO BS.ByteString
deriveKey pk = do
  sesh@Sesh {..} <- S.get
  let params = do
        grp <- dhGroup
        per <- dhKeys
        pure (grp, per)
  case params of
    Nothing -> do
      slog "missing group parameters or keypair"
      liftIO SE.exitFailure
    Just (grp, per) -> do
      let key = derivekey grp per pk
      S.put sesh {
          dhKey = Just key
        }
      pure key

encrypt :: BS.ByteString -> StateT Sesh IO BS.ByteString
encrypt msg = do
  sesh@Sesh {..} <- S.get
  case dhKey of
    Nothing -> do
      slog "missing shared key"
      liftIO SE.exitFailure
    Just k -> do
      gen <- liftIO dhGen
      iv <- liftIO $ CU.bytes 16 gen
      let pad = CU.lpkcs7 msg
      pure $ AES.encryptCbcAES128 iv k pad

decrypt :: BS.ByteString -> StateT Sesh IO BS.ByteString
decrypt cip = do
  sesh@Sesh {..} <- S.get
  case dhKey of
    Nothing -> do
      slog "missing shared key"
      liftIO SE.exitFailure
    Just k -> do
      case CU.unpkcs7 (AES.decryptCbcAES128 k cip) of
        Nothing -> do
          slog "couldn't decrypt ciphertext"
          liftIO SE.exitFailure
        Just msg -> pure msg

decryptLenient :: BS.ByteString -> StateT Sesh IO (Maybe BS.ByteString)
decryptLenient cip = do
  sesh@Sesh {..} <- S.get
  case dhKey of
    Nothing -> do
      slog "missing shared key"
      liftIO SE.exitFailure
    Just k -> do
      case CU.unpkcs7 (AES.decryptCbcAES128 k cip) of
        Nothing -> do
          slog "couldn't decrypt ciphertext"
          pure Nothing
        Just msg -> pure (Just msg)

renderkey :: Natural -> T.Text
renderkey =
    B16.encodeBase16
  . BL.toStrict
  . CS.bytestringDigest
  . CS.sha1
  . DB.encode
