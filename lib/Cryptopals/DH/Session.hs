{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RankNTypes #-}

module Cryptopals.DH.Session (
    Command(..)
  , Sesh(..)

  , slog
  , beval
  , meval

  , session
  , dance
  ) where

import Control.Concurrent (threadDelay)
import Control.Monad.Primitive
import Control.Monad.IO.Class
import Control.Monad.Trans.State (StateT)
import qualified Control.Monad.Trans.State as S
import qualified Cryptopals.AES as AES
import Cryptopals.DH.Core
import qualified Cryptopals.Util as CU
import qualified Data.Binary as DB
import qualified Data.ByteString as BS
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
    SendParams Group Natural
  | SendPublic Natural
  | SendMessage BS.ByteString
  | SendTerminal BS.ByteString
  deriving (Eq, Show, Generic)

instance DB.Binary Command

-- session state
data Sesh = Sesh {
    dhGroup       :: Maybe Group
  , dhKeys        :: Maybe Keys
  , dhKey         :: Maybe BS.ByteString
  , dhGen         :: IO (MWC.Gen RealWorld)
  }

-- session log
slog :: T.Text -> T.Text -> IO ()
slog host msg = TIO.putStrLn $ "(cryptopals) " <> host <> ": " <> msg

-- generic session evaluator
geval
  :: MonadIO m
  => (T.Text -> Command -> m a)
  -> T.Text
  -> Maybe Command
  -> m a
geval cont host = \case
  Nothing -> liftIO $ do
    slog host "ending session"
    SE.exitSuccess -- XX should really just close the socket
  Just cmd -> do
    liftIO $ threadDelay 1000000
    cont host cmd

-- basic dh evaluation
beval :: T.Text -> Maybe Command -> StateT Sesh IO (Maybe Command)
beval = geval dheval

-- mitm dh evaluation
meval :: T.Text -> Maybe Command -> StateT Sesh IO (Maybe Command)
meval = geval mitmeval

-- diffie-hellman protocol eval
dheval
  :: T.Text
  -> Command
  -> StateT Sesh IO (Maybe Command)
dheval host = \case
  SendParams grp pk -> do
    sesh@Sesh {..} <- S.get
    liftIO $ slog host "received group parameters and public key"
    gen <- liftIO dhGen
    per@Keys {..} <- liftIO $ genpair grp gen
    let key = derivekey grp per pk
        nex = sesh {
                  dhGroup = Just grp
                , dhKeys  = Just per
                , dhKey   = Just key
                }
    S.put nex
    liftIO $ slog host "sending public key"
    pure $ Just (SendPublic pub)

  SendPublic pk -> do
    sesh@Sesh {..} <- S.get
    liftIO $ slog host "received public key"
    let key = do
          per@Keys {..} <- dhKeys
          grp <- dhGroup
          pure $ derivekey grp per pk
    case key of
      Nothing -> do
        liftIO $ slog host "key derivation failed"
        pure Nothing
      Just k -> do
        gen <- liftIO dhGen
        iv  <- liftIO $ CU.bytes 16 gen
        let msg = CU.lpkcs7 "attack at 10pm"
            cip = AES.encryptCbcAES128 iv k msg
            cod = B64.encodeBase64 cip
        liftIO . slog host $ "sending ciphertext " <> cod
        let rep = Just (SendMessage cip)
            nex = sesh { dhKey = key }
        S.put nex
        pure rep

  SendMessage cip -> do
    sesh@Sesh {..} <- S.get
    let cod = B64.encodeBase64 cip
    liftIO $ slog host $ "received ciphertext " <> cod
    case dhKey of
      Nothing -> do
        liftIO $ slog host "shared key not established"
        pure Nothing
      Just k -> do
        let Just msg = CU.unpkcs7 (AES.decryptCbcAES128 k cip)
            cod = TE.decodeLatin1 msg
        liftIO $ slog host $ "decrypted ciphertext: \"" <> cod <> "\""

        let hourOfDestiny = case B8.findIndex C.isDigit msg of
              Nothing -> error "did i fat-finger a digit?"
              Just j  -> BS.drop j msg

        gen <- liftIO dhGen
        iv  <- liftIO $ CU.bytes 16 gen
        let nmsg = CU.lpkcs7 $ "confirmed, attacking at " <> hourOfDestiny
            ncip = AES.encryptCbcAES128 iv k nmsg
            ncod = B64.encodeBase64 ncip
        liftIO $ slog host $ "replying with ciphertext " <> ncod
        pure $ Just (SendTerminal ncip)

  SendTerminal cip -> do
    sesh@Sesh {..} <- S.get
    let cod = B64.encodeBase64 cip
    liftIO $ slog host $ "received ciphertext " <> cod
    case dhKey of
      Nothing -> do
        liftIO $ slog host "shared key not established"
        pure Nothing
      Just k -> do
        let Just msg = CU.unpkcs7 (AES.decryptCbcAES128 k cip)
            cod = TE.decodeLatin1 msg
        liftIO $ slog host $ "decrypted ciphertext: \"" <> cod <> "\""
        pure Nothing

-- man-in-the-middle protocol eval
mitmeval
  :: T.Text
  -> Command
  -> StateT Sesh IO (Maybe Command)
mitmeval host = \case
  SendParams grp pk -> do
    sesh@Sesh {..} <- S.get
    liftIO $ slog host "reCEiVed GRoUp pArAmeTErs And pUBliC kEy"
    let key = derivekey grp (Keys p 1) p
        nex = sesh { dhKey = Just key }
    S.put nex
    liftIO $ slog host "sEnDinG BOguS paRaMeTeRs"
    pure $ Just (SendParams grp p)

  SendPublic pk -> do
    liftIO $ slog host "REceIvED pUBlic keY"
    liftIO $ slog host "seNDINg boGus kEy"
    pure $ Just (SendPublic p)

  SendMessage cip -> do
    sesh@Sesh {..} <- S.get
    let cod = B64.encodeBase64 cip
    liftIO $ slog host $ "rECeIveD CiPHeRTexT " <> cod
    case dhKey of
      Nothing -> error "mallory knows key"
      Just k -> do
        let Just msg = CU.unpkcs7 (AES.decryptCbcAES128 k cip)
            cod = TE.decodeLatin1 msg
        liftIO $ slog host $ "DEcRyptEd cIPheRTeXt: \"" <> cod <> "\""
        liftIO $ slog host $ "reLayINg cIpheRtExt"
        pure $ Just (SendMessage cip)

  SendTerminal cip -> do
    sesh@Sesh {..} <- S.get
    let cod = B64.encodeBase64 cip
    liftIO $ slog host $ "reCeiVeD CipHeRtExt " <> cod
    case dhKey of
      Nothing -> error "mallory knows key"
      Just k -> do
        let Just msg = CU.unpkcs7 (AES.decryptCbcAES128 k cip)
            cod = TE.decodeLatin1 msg
        liftIO $ slog host $ "DeCrYpteD cIphErteXt: \"" <> cod <> "\""
        liftIO $ slog host $ "ReLaYINg CiPHeRTexT"
        pure $ Just (SendTerminal cip)

-- basic TCP coordination
session host sock =
        deco
    >-> P.mapM eval
    >-> for cat PB.encode
    >-> send
  where
    recv = PN.fromSocket sock 4096
    deco = PP.parsed PB.decode recv
    send = PN.toSocket sock
    eval = beval host

-- MITM TCP coordination
dance host asock bsock =
        PP.parsed PB.decode recv
    >-> P.mapM (meval host)
    >-> for cat PB.encode
    >-> PN.foxtrot bsock asock
  where
    recv = PN.rhumba asock bsock 4096

