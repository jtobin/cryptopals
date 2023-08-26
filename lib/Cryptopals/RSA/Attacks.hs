module Cryptopals.RSA.Attacks (
    e3BroadcastAttack
  ) where

import Control.Monad (forever, when)
import Control.Monad.Primitive
import Control.Monad.IO.Class
import Control.Monad.Trans.Class
import Control.Monad.Trans.State
import qualified Cryptopals.DH as DH
import Cryptopals.RSA
import qualified Cryptopals.Digest.Pure.SHA as CS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy as BL
import qualified Data.Maybe as M
import qualified Data.HashSet as HS
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import qualified Math.NumberTheory.Roots as R
import Numeric.Natural
import Pipes
import qualified Pipes.Prelude as P
import qualified System.Random.MWC as MWC

-- e=3 broadcast attack

e3BroadcastAttack
  :: (BS.ByteString, Key)   -- ciphertext / pubkey
  -> (BS.ByteString, Key)   -- ciphertext / pubkey
  -> (BS.ByteString, Key)   -- ciphertext / pubkey
  -> BS.ByteString          -- plaintext
e3BroadcastAttack (c0, p0) (c1, p1) (c2, p2) = case (p0, p1, p2) of
  (Pub _ n0, Pub _ n1, Pub _ n2) ->
    let ms0 = n1 * n2
        ms1 = n0 * n2
        ms2 = n0 * n1

        s   = roll c0 * ms0 * modinv' ms0 n0
            + roll c1 * ms1 * modinv' ms1 n1
            + roll c2 * ms2 * modinv' ms2 n2

        c   = s `mod` (n0 * n1 * n2)

    in  unroll (R.integerCubeRoot c)

  _ -> error "e3BroadcastAttack: require public keys"

-- unpadded message recovery oracle

type Digests = HS.HashSet Integer

umrClient :: MonadIO m => Key -> Producer BS.ByteString m ()
umrClient pub = case pub of
  Sec {} -> error "umrClient: need public key"
  Pub {} -> do
    liftIO $ do
      TIO.putStrLn "(cryptopals) umr-oracle: running with public key"
      TIO.putStrLn (T.pack $ show pub)
    forever $ do
      lin <- liftIO $ do
        TIO.putStrLn "(cryptopals) umr-oracle: awaiting hex-encoded input"
        BS.getLine
      yield (B16.decodeBase16Lenient lin)

umrServer :: Key -> Consumer BS.ByteString (StateT Digests IO) ()
umrServer sec = case sec of
  Pub {} -> error "umrServer: need secret key"
  Sec {} -> forever $ do
    cip <- await
    digests <- lift get

    let has = CS.integerDigest . CS.sha512 $ BL.fromStrict cip

    if   HS.member has digests
    then liftIO $ TIO.putStrLn "(cryptopals) umr-oracle: rejecting request"
    else do
      lift $ modify (HS.insert has)
      let msg = decrypt sec cip
      liftIO $ do
        TIO.putStrLn "(cryptopals) umr-oracle: decrypted text"
        TIO.putStrLn (B16.encodeBase16 msg)

umrOracle :: Keypair -> Effect (StateT Digests IO) ()
umrOracle (Keypair sec pub) = umrClient pub >-> umrServer sec

umrperturb
  :: Key
  -> BS.ByteString                   -- original ciphertext
  -> MWC.Gen RealWorld
  -> IO (Natural, BS.ByteString)     -- (random s, perturbed ciphertext)
umrperturb key cip gen = case key of
  Sec {}  -> error "umrperturb: need public key"
  Pub e n -> do
    s <- MWC.uniformRM (1, n - 1) gen
    let c  = roll cip
        c' = (DH.modexp s e n * c) `mod` n
    pure (s, unroll c')

umrrecover
  :: Key
  -> Natural
  -> BS.ByteString
  -> BS.ByteString
umrrecover key s msg = case key of
  Sec {}  -> error "umrrecover: need public key"
  Pub e n -> unroll $ (roll msg `mod` n * modinv' s n) `mod` n

-- bleichenbacher's e=3 signature forgery

fencode :: Natural -> BS.ByteString -> BS.ByteString
fencode mod msg =
  let has = BL.toStrict $ CS.bytestringDigest (CS.sha512 (BL.fromStrict msg))
      len = bitl mod `quot` 8
      pad =
          BS.cons 0x00
        . BS.cons 0x01
        . BS.cons 0xff
        $ BS.cons 0x00 asnSha512
      vil = pad <> has
  in  vil <> BS.replicate (len - BS.length vil) 0

forge :: Natural -> BS.ByteString -> BS.ByteString
forge mod msg =
  let f = fencode mod msg
  in  unroll $ R.integerCubeRoot (roll f) + 1

