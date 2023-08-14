{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}

module Cryptopals.DH (
    p
  , g
  , modexp
  ) where

import Control.Concurrent (threadDelay)
import Control.Monad.Primitive
import Control.Monad.Trans.State (StateT)
import qualified Control.Monad.Trans.State as S
import qualified Cryptopals.AES as AES
import qualified Cryptopals.Digest.Pure.SHA as CS
import qualified Cryptopals.Util as CU
import Data.Binary as DB
import qualified Data.Binary.Get as BG
import qualified Data.Binary.Put as BP
import Data.Bits ((.|.))
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy as BL
import qualified Data.Char as C
import qualified Data.List as L
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import GHC.Generics (Generic)
import GHC.Word (Word16)
import qualified Network.Simple.TCP as N
import qualified Network.Socket.ByteString as NB
import Numeric.Natural
import Pipes
import qualified Pipes.Binary as PB
import qualified Pipes.Network as PN
import qualified Pipes.Prelude as P
import qualified Pipes.Parse as PP
import qualified System.Exit as SE
import qualified System.Random.MWC as MWC

data Group = Group Natural Natural
  deriving (Eq, Show, Generic)

instance DB.Binary Group

data Command =
    SendParams Group Natural
  | SendPublic Natural
  | SendMessage BS.ByteString
  | SendTerminal BS.ByteString
  deriving (Eq, Show, Generic)

instance DB.Binary Command

data Keys = Keys {
    pub :: Natural
  , sec :: Natural
  }

-- session state
data Sesh = Sesh {
    dhGroup       :: Maybe Group
  , dhKeys        :: Maybe Keys
  , dhKey         :: Maybe BS.ByteString
  , dhGen         :: IO (MWC.Gen RealWorld)
  }

p :: Natural
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

g :: Natural
g = 2

-- XX i should really put this somewhere instead of copying it every time
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
    SE.exitSuccess
  Just cmd -> do
    liftIO $ threadDelay 1000000
    cont host cmd

seval :: T.Text -> Maybe Command -> StateT Sesh IO (Maybe Command)
seval = geval dheval

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
    eval = seval host

-- MITM TCP coordination
dance host asock bsock =
        PP.parsed PB.decode recv
    >-> P.mapM (meval host)
    >-> for cat PB.encode
    >-> foxtrot bsock asock
  where
    recv = rhumba asock bsock 4096

-- receive on alternate sockets
rhumba
  :: MonadIO m
  => N.Socket
  -> N.Socket
  -> Word32
  -> Producer' BS.ByteString m ()
rhumba a b n = loop True where
  loop lip = do
    let s = if lip then a else b
    b <- liftIO (NB.recv s (fromIntegral n))
    if   BS.null b
    then pure ()
    else do
      yield b
      loop (not lip)

-- send on alternate sockets
foxtrot
  :: MonadIO m
  => N.Socket
  -> N.Socket
  -> Consumer BS.ByteString m b
foxtrot asock bsock = loop True where
  loop lip = do
    b <- await
    let s = if lip then asock else bsock
    liftIO $ PN.send s b
    loop (not lip)

