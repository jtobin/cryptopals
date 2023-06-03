{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Cryptopals.Util as CU
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import Data.Foldable (for_)
import qualified Options.Applicative as O
import qualified System.Exit as SE
import qualified System.IO as SIO

data Args = Args {
    argsSiz :: Int
  , argsInp :: T.Text
  }

ops :: O.Parser Args
ops = Args
  <$> O.argument O.auto (O.metavar "ROWS")
  <*> O.argument O.str (O.metavar "INPUT")

rot :: Args -> IO ()
rot Args {..} = do
  let args = do
        v <- B16.decodeBase16 $ TE.encodeUtf8 argsInp
        pure (argsSiz, v)

  case args of
    Left e -> do
      TIO.hPutStrLn SIO.stderr ("cryptopals: " <> e)
      SE.exitFailure

    Right (s, v) -> do
      let res = CU.rotate s v
      for_ res $ TIO.putStrLn . TE.decodeUtf8 . B16.encodeBase16'

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "transpose the target bytes"
        <> O.header "rotate"

  args <- O.execParser pars

  rot args

