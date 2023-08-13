{-# LANGUAGE RankNTypes #-}

module Pipes.Network (
    N.Socket(..)
  , N.SockAddr(..)
  , NT.HostPreference(..)
  , N.ServiceName

  , fromSocket
  , toSocket

  , NT.connect
  , NT.serve
  , NT.send
  , NT.recv
  , NT.closeSock
  ) where

import Control.Monad.IO.Class
import qualified Data.ByteString as BS
import qualified Pipes as P
import qualified Network.Simple.TCP as NT
import qualified Network.Socket as N
import qualified Network.Socket.ByteString as NB
import GHC.Word (Word32)

fromSocket
  :: MonadIO m
  => N.Socket
  -> Word32
  -> P.Producer' BS.ByteString m ()
fromSocket s n = loop where
  loop = do
    b <- liftIO (NB.recv s (fromIntegral n))
    if   BS.null b
    then pure ()
    else do
      P.yield b
      loop

toSocket
  :: MonadIO m
  => N.Socket
  -> P.Consumer' BS.ByteString m r
toSocket s = P.for P.cat (NT.send s)

