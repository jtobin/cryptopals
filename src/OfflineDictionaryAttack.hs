{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Cryptopals.SRP.Simple (Env(..), defaultEnv)
import qualified Cryptopals.Digest.Pure.SHA as CS
import qualified Cryptopals.DH as DH
import qualified Data.Binary as DB
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as BL8
import qualified Data.HashMap.Lazy as HML
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import Numeric.Natural
import qualified Options.Applicative as O

populate :: Natural -> IO (HML.HashMap BL.ByteString BL.ByteString)
populate herpub = do
  let Env {..} = defaultEnv
  dict <- BL8.readFile "/usr/share/dict/words"
  let derive x = ((herpub `mod` en) * (DH.modexp eg x en)) `mod` en

  let ls = BL8.lines dict
      ns = fmap (fromIntegral . CS.integerDigest . CS.sha256) ls :: [Natural]
      ss = fmap derive ns
      hs = fmap (CS.bytestringDigest . CS.sha256 . DB.encode) ss
      ms = fmap (\s -> CS.bytestringDigest (CS.hmacSha256 s mempty)) hs

  pure . HML.fromList $ zip ms ls

data Args = Args {
    argsNat :: Natural
  , argsMAC :: T.Text
  }

ops :: O.Parser Args
ops = Args
  <$> O.argument O.auto (O.metavar "PUBLICKEY")
  <*> O.argument O.str (O.metavar "MAC")

crack :: Args -> IO ()
crack Args {..} = do
  let mac = BL.fromStrict . B16.decodeBase16Lenient $ TE.encodeUtf8 argsMAC
  dict <- populate argsNat
  case HML.lookup mac dict of
    Nothing -> TIO.putStrLn "(cryptopals) couldn't crack password"
    Just pw -> do
      let s = BL.toStrict pw
      B8.putStrLn "(cryptopals) success"
      B8.putStrLn $ "(cryptopals) password: " <> s

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "perform an offline dictionary attack"
        <> O.header "offline-dictionary-attack"

  args <- O.execParser pars

  crack args

