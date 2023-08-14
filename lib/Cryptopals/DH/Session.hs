{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RankNTypes #-}

module Cryptopals.DH.Session (
    Command(..)
  , Sesh(..)
  , Handler

  , blog
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
    SendGroup Group                   -- group only
  | AckGroup                          -- ack receipt of group params
  | SendParams Group Natural          -- group + public key
  | SendPublic Natural                -- public key only
  | SendMessage BS.ByteString         -- send initial ciphertext
  | SendTerminal BS.ByteString        -- send final ciphertext
  deriving (Eq, Show, Generic)

instance DB.Binary Command

type Handler m b c = b -> m c

-- session state
data Sesh = Sesh {
    dhGroup       :: Maybe Group
  , dhHost        :: T.Text
  -- , dhSock        :: PN.Socket     -- XX add me
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

-- basic TCP coordination
session
  :: (MonadIO m, DB.Binary b, DB.Binary c)
  => PN.Socket
  -> Handler m b c
  -> Effect m (PB.DecodingError, Producer BS.ByteString m ())
session sock eval =
        deco
    >-> P.mapM eval
    >-> for cat PB.encode
    >-> send
  where
    recv = PN.fromSocket sock 4096
    deco = PP.parsed PB.decode recv
    send = PN.toSocket sock

-- MITM TCP coordination
dance
  :: (MonadIO m, DB.Binary b, DB.Binary c)
  => PN.Socket
  -> PN.Socket
  -> Handler m b c
  -> Effect m (PB.DecodingError, Producer BS.ByteString m ())
dance asock bsock eval =
        PP.parsed PB.decode recv
    >-> P.mapM eval
    >-> for cat PB.encode
    >-> PN.foxtrot bsock asock
  where
    recv = PN.rhumba asock bsock 4096

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
    liftIO $ threadDelay 3000000
    cont cmd

-- basic dh evaluation
beval :: Maybe Command -> StateT Sesh IO (Maybe Command)
beval = seval dheval

-- mitm dh evaluation
meval :: Maybe Command -> StateT Sesh IO (Maybe Command)
meval = seval mitmeval

-- negotiated-group dh evaluation
geval :: Maybe Command -> StateT Sesh IO (Maybe Command)
geval = seval ngeval

-- XX refactor some common actions, e.g. assembling ciphertexts

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
    sesh@Sesh {..} <- S.get
    slog "received group parameters and public key"
    gen <- liftIO dhGen
    per@Keys {..} <- liftIO $ genpair grp gen
    let key = derivekey grp per pk
        nex = sesh {
                  dhGroup = Just grp
                , dhKeys  = Just per
                , dhKey   = Just key
                }
    S.put nex
    slog "sending public key"
    pure $ Just (SendPublic pub)

  SendPublic pk -> do
    sesh@Sesh {..} <- S.get
    slog "received public key"
    let key = do
          per@Keys {..} <- dhKeys
          grp <- dhGroup
          pure $ derivekey grp per pk
    case key of
      Nothing -> do
        slog "key derivation failed"
        pure Nothing
      Just k -> do
        gen <- liftIO dhGen
        iv  <- liftIO $ CU.bytes 16 gen
        let msg = CU.lpkcs7 "attack at 10pm"
            cip = AES.encryptCbcAES128 iv k msg
            cod = B64.encodeBase64 cip
        slog $ "sending ciphertext " <> cod
        let rep = Just (SendMessage cip)
            nex = sesh { dhKey = key }
        S.put nex
        pure rep

  SendMessage cip -> do
    sesh@Sesh {..} <- S.get
    let cod = B64.encodeBase64 cip
    slog $ "received ciphertext " <> cod
    case dhKey of
      Nothing -> do
        slog "shared key not established"
        pure Nothing
      Just k -> do
        let Just msg = CU.unpkcs7 (AES.decryptCbcAES128 k cip)
            cod = TE.decodeLatin1 msg
        slog $ "decrypted ciphertext: \"" <> cod <> "\""

        let hourOfDestiny = case B8.findIndex C.isDigit msg of
              Nothing -> error "did i fat-finger a digit?"
              Just j  -> BS.drop j msg

        gen <- liftIO dhGen
        iv  <- liftIO $ CU.bytes 16 gen
        let nmsg = CU.lpkcs7 $ "confirmed, attacking at " <> hourOfDestiny
            ncip = AES.encryptCbcAES128 iv k nmsg
            ncod = B64.encodeBase64 ncip
        slog $ "replying with ciphertext " <> ncod
        pure $ Just (SendTerminal ncip)

  SendTerminal cip -> do
    sesh@Sesh {..} <- S.get
    let cod = B64.encodeBase64 cip
    slog $ "received ciphertext " <> cod
    case dhKey of
      Nothing -> do
        slog "shared key not established"
        pure Nothing
      Just k -> do
        let Just msg = CU.unpkcs7 (AES.decryptCbcAES128 k cip)
            cod = TE.decodeLatin1 msg
        slog $ "decrypted ciphertext: \"" <> cod <> "\""
        pure Nothing

-- man-in-the-middle protocol eval
mitmeval
  :: Command
  -> StateT Sesh IO (Maybe Command)
mitmeval = \case
  SendParams grp pk -> do
    sesh@Sesh {..} <- S.get
    slog "reCEiVed GRoUp pArAmeTErs And pUBliC kEy"
    let key = derivekey grp (Keys p 1) p
        nex = sesh { dhKey = Just key }
    S.put nex
    slog "sEnDinG BOguS paRaMeTeRs"
    pure $ Just (SendParams grp p)

  SendPublic pk -> do
    slog "REceIvED pUBlic keY"
    slog "seNDINg boGus kEy"
    pure $ Just (SendPublic p)

  SendMessage cip -> do
    sesh@Sesh {..} <- S.get
    let cod = B64.encodeBase64 cip
    slog $ "rECeIveD CiPHeRTexT " <> cod
    case dhKey of
      Nothing -> error "mallory knows key"
      Just k -> do
        let Just msg = CU.unpkcs7 (AES.decryptCbcAES128 k cip)
            cod = TE.decodeLatin1 msg
        slog $ "DEcRyptEd cIPheRTeXt: \"" <> cod <> "\""
        slog "reLayINg cIpheRtExt"
        pure $ Just (SendMessage cip)

  SendTerminal cip -> do
    sesh@Sesh {..} <- S.get
    let cod = B64.encodeBase64 cip
    slog $ "reCeiVeD CipHeRtExt " <> cod
    case dhKey of
      Nothing -> error "mallory knows key"
      Just k -> do
        let Just msg = CU.unpkcs7 (AES.decryptCbcAES128 k cip)
            cod = TE.decodeLatin1 msg
        slog $ "DeCrYpteD cIphErteXt: \"" <> cod <> "\""
        slog "ReLaYINg CiPHeRTexT"
        pure $ Just (SendTerminal cip)

-- negotiated-group protocol eval
ngeval
  :: Command
  -> StateT Sesh IO (Maybe Command)
ngeval = \case
  SendGroup grp -> do
    sesh@Sesh {..} <- S.get
    slog "received group parameters"
    let nex = sesh { dhGroup = Just grp }
    S.put nex
    slog "ACK"
    pure (Just AckGroup)

  AckGroup -> do
    sesh@Sesh {..} <- S.get
    slog "ACK ACK"
    gen <- liftIO dhGen
    case dhGroup of
      Nothing -> do
        slog "haven't generated group yet"
        pure Nothing
      Just grp -> do
        per@Keys {..} <- liftIO $ genpair grp gen
        let nex = sesh { dhKeys = Just per }
        S.put nex
        slog "sending public key"
        pure $ Just (SendPublic pub)

  SendParams grp pk -> do
    slog "not expecting group parameters and public key"
    pure Nothing

  SendPublic pk -> do
    sesh@Sesh {..} <- S.get
    slog "received public key"
    case dhGroup of
      Nothing -> do
        slog "don't have group parameters"
        pure Nothing
      Just grp -> case dhKeys of
        Nothing -> do
          gen <- liftIO dhGen
          per@Keys {..} <- liftIO $ genpair grp gen
          let nex = sesh { dhKeys = Just per }
          S.put nex
          slog "sending public key"
          pure (Just (SendPublic pub))
        Just per@Keys {..} -> do
          let key = derivekey grp per pk
              nex = sesh { dhKey = Just key }
          S.put nex
          gen <- liftIO dhGen
          iv  <- liftIO $ CU.bytes 16 gen
          let msg = CU.lpkcs7 "attack at 10pm"
              cip = AES.encryptCbcAES128 iv key msg
              cod = B64.encodeBase64 cip
          slog $ "sending ciphertext " <> cod
          pure $ Just (SendMessage cip)

  SendMessage cip -> do
    sesh@Sesh {..} <- S.get
    let cod = B64.encodeBase64 cip
    slog $ "received ciphertext " <> cod
    case dhKey of
      Nothing -> do
        slog "shared key not established"
        pure Nothing
      Just k -> do
        let Just msg = CU.unpkcs7 (AES.decryptCbcAES128 k cip)
            cod = TE.decodeLatin1 msg
        slog $ "decrypted ciphertext: \"" <> cod <> "\""

        let hourOfDestiny = case B8.findIndex C.isDigit msg of
              Nothing -> error "did i fat-finger a digit?"
              Just j  -> BS.drop j msg

        gen <- liftIO dhGen
        iv  <- liftIO $ CU.bytes 16 gen
        let nmsg = CU.lpkcs7 $ "confirmed, attacking at " <> hourOfDestiny
            ncip = AES.encryptCbcAES128 iv k nmsg
            ncod = B64.encodeBase64 ncip
        slog $ "replying with ciphertext " <> ncod
        pure $ Just (SendTerminal ncip)

  SendTerminal cip -> do
    sesh@Sesh {..} <- S.get
    let cod = B64.encodeBase64 cip
    slog $ "received ciphertext " <> cod
    case dhKey of
      Nothing -> do
        slog "shared key not established"
        pure Nothing
      Just k -> do
        let Just msg = CU.unpkcs7 (AES.decryptCbcAES128 k cip)
            cod = TE.decodeLatin1 msg
        slog $ "decrypted ciphertext: \"" <> cod <> "\""
        pure Nothing

