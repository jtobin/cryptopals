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
import qualified Data.Bits as B
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

-- parity attack

consistentKey :: Keypair
consistentKey = Keypair {
    sec = Sec 17123352828014333155624438024036760971684155055395178750326166116221921534834757334258805831433671108747515574930784033716009753162288853697798226497143603784063672293784689339725292980717759302559416192505022202607060043180747993307152813641965271101487768850534996446308519974161336757521350033549104638323502861457159133823648406287066941450810841565848911430015280485845523895713183178201477186740322834886881520321163855222966200390877773389398001466822114489027189069065611644814402176315409188376507981912063223328698296264072987777394439869807029983108333829414790214696124608366420616926584028341835718008171 25685029242021499733436657036055141457526232583092768125489249174332882302252136001388208747150506663121273362396176050574014629743433280546697339745715405676095508440677034009587939471076638953839124288757533303910590064771121989960729220462947906652231653275802494669462779961242005136282025050323656957485575104768964364403120315473688233575506565199853941740698324759332741496556795318816219056943528386602087313223192513906581768759460447708758904161995531418020160091893731652698334419244087283089646693366368274960752450233540634283787034263316102286260474903106332924146000298152373432597583736507887518612367
  , pub = Pub 3 25685029242021499733436657036055141457526232583092768125489249174332882302252136001388208747150506663121273362396176050574014629743433280546697339745715405676095508440677034009587939471076638953839124288757533303910590064771121989960729220462947906652231653275802494669462779961242005136282025050323656957485575104768964364403120315473688233575506565199853941740698324759332741496556795318816219056943528386602087313223192513906581768759460447708758904161995531418020160091893731652698334419244087283089646693366368274960752450233540634283787034263316102286260474903106332924146000298152373432597583736507887518612367
  }

-- true if odd
parityOracle :: BS.ByteString -> Bool
parityOracle cip =
  let msg = decrypt (sec consistentKey) cip
  in  B.testBit (roll msg) 0

parityAttack :: Key -> BS.ByteString -> IO BS.ByteString
parityAttack (Pub e n) cip = loop 0 n (roll cip) where
  loop i j c
    | j == i || j - i == 1 = pure (unroll j)
    | otherwise = do
        B8.putStrLn (unroll j)
        let d = (c * DH.modexp 2 e n) `mod` n
        if   parityOracle (unroll d)
        then loop (i + (j - i) `quot` 2) j d
        else loop i (j - (j - i) `quot` 2) d

