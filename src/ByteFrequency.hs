{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Cryptopals.Util as CU
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.Text.Encoding as TE
import qualified Options.Applicative as O
import qualified System.Exit as SE
import qualified System.IO as SIO

data Args = Args { argsInp :: T.Text }

ops :: O.Parser Args
ops = Args <$> O.argument O.str (O.metavar "INPUT")

freq :: Args -> IO ()
freq Args {..} = do
  let render :: Show a => a -> T.Text
      render = T.pack . show

      err = TIO.hPutStrLn SIO.stderr

      args = B16.decodeBase16 $ TE.encodeUtf8 argsInp

  case args of
    Left e -> do
      err $ "cryptopals: " <> e
      SE.exitFailure

    Right s -> do
      let freqs = take 3 $ CU.often s

      err $ "cryptopals: common bytes (" <> argsInp <> ")"
      err $ render freqs

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "produce byte frequencies"
        <> O.header "byte-frequency"

  args <- O.execParser pars

  freq args

