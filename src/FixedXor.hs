{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Cryptopals.Util as CU
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import qualified Options.Applicative as O
import qualified System.Exit as SE
import qualified System.IO as SIO

data Args = Args {
    argsKey :: T.Text
  , argsInp :: T.Text
  }

ops :: O.Parser Args
ops = Args
  <$> O.argument O.str (O.metavar "KEY")
  <*> O.argument O.str (O.metavar "INPUT")

fxor :: Args -> IO ()
fxor Args {..} = do
  let args = do
        k <- B16.decodeBase16 $ TE.encodeUtf8 argsKey
        v <- B16.decodeBase16 $ TE.encodeUtf8 argsInp
        if   BS.length k /= BS.length v
        then Left "fixed-xor: unequal-length inputs"
        else pure (k, v)

  case args of
    Left e -> do
      TIO.hPutStrLn SIO.stderr ("cryptopals: " <> e)
      SE.exitFailure

    Right (k, v) -> do
      let res = CU.fixedXor k v
      TIO.putStrLn . TE.decodeUtf8 . B16.encodeBase16' $ res

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "compute fixed-xor KEY on INPUT"
        <> O.header "fixed-xor"

  args <- O.execParser pars

  fxor args

