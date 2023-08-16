module Pipes.Network (
    N.Socket(..)
  , N.SockAddr(..)
  , NT.HostPreference(..)
  , N.ServiceName
  , Protocol

  , fromSocket
  , toSocket
  , session
  , dance

  , NT.connect
  , NT.serve
  , NT.send
  , NT.recv
  , NT.closeSock
  ) where

import Control.Monad.IO.Class
import qualified Data.Binary as DB
import qualified Data.ByteString as BS
import Pipes
import qualified Pipes.Binary as PB
import qualified Pipes.Parse as PP
import qualified Pipes.Prelude as P
import qualified Network.Simple.TCP as NT
import qualified Network.Socket as N
import qualified Network.Socket.ByteString as NB
import GHC.Word (Word32)

type Protocol m b c = b -> m c

-- receive on socket
fromSocket
  :: MonadIO m
  => N.Socket
  -> Word32
  -> Producer' BS.ByteString m ()
fromSocket s n = loop where
  loop = do
    b <- liftIO (NB.recv s (fromIntegral n))
    if   BS.null b
    then pure ()
    else do
      yield b
      loop

-- send on socket
toSocket
  :: MonadIO m
  => N.Socket
  -> Consumer' BS.ByteString m r
toSocket s = for cat (NT.send s)

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
    liftIO $ NT.send s b
    loop (not lip)

-- basic TCP coordination
session
  :: (MonadIO m, DB.Binary b, DB.Binary c)
  => N.Socket
  -> Protocol m b c
  -> Effect m (PB.DecodingError, Producer BS.ByteString m ())
session sock eval =
        deco
    >-> P.mapM eval
    >-> for cat PB.encode
    >-> send
  where
    recv = fromSocket sock 4096
    deco = PP.parsed PB.decode recv
    send = toSocket sock

-- MITM TCP coordination
dance
  :: (MonadIO m, DB.Binary b, DB.Binary c)
  => N.Socket
  -> N.Socket
  -> Protocol m b c
  -> Effect m (PB.DecodingError, Producer BS.ByteString m ())
dance asock bsock eval =
        PP.parsed PB.decode recv
    >-> P.mapM eval
    >-> for cat PB.encode
    >-> foxtrot bsock asock
  where
    recv = rhumba asock bsock 4096

