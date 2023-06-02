{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Cryptopals.Util as CU
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import qualified Options.Applicative as O

data Args = Args {
    argsKey :: T.Text
  , argsInp :: T.Text
  }

ops :: O.Parser Args
ops = Args
  <$> O.argument O.str (O.metavar "KEY")
  <*> O.argument O.str (O.metavar "INPUT")

rxor :: Args -> IO ()
rxor Args {..} = do
  let (k, v) = (TE.encodeUtf8 argsKey, TE.encodeUtf8 argsInp)
      res    = CU.repeatingKeyXor k v

  TIO.putStrLn . TE.decodeUtf8 . B16.encodeBase16' $ res

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "compute repeating-key-xor KEY on INPUT"
        <> O.header "repeating-key-xor"

  args <- O.execParser pars

  rxor args

