{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Cryptopals.Util as CU
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.Text.Encoding as TE
import qualified Options.Applicative as O
import qualified System.IO as SIO

data Args = Args {
    argsPad :: Int
  , argsInp :: T.Text
  }

ops :: O.Parser Args
ops = Args
  <$> O.argument O.auto (O.metavar "BYTES")
  <*> O.argument O.str (O.metavar "INPUT")

pkcs :: Args -> IO ()
pkcs Args {..} = do
  let b = CU.pkcs7 argsPad (TE.encodeUtf8 argsInp)
  TIO.putStr . TE.decodeUtf8 $ b

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "pad INPUT to BYTES via PKCS#7"
        <> O.header "pkcs7"

  args <- O.execParser pars

  pkcs args

