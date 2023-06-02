{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Cryptopals.Util as CU
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as B8
import qualified Data.Foldable as F
import Data.Function (on)
import qualified Data.List as L
-- import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.Text.Encoding as TE
import qualified Options.Applicative as O
import qualified System.Exit as SE
import qualified System.IO as SIO

data Args = Args { argsFil :: SIO.FilePath }

ops :: O.Parser Args
ops = Args <$> O.argument O.str (O.metavar "FILE")

detect :: Args -> IO ()
detect Args {..} = do
  let err = TIO.hPutStrLn SIO.stderr
      out = TIO.hPutStrLn SIO.stdout

  contents <- B8.readFile argsFil

  let ls = B8.lines contents
      es = traverse B16.decodeBase16 ls

  case es of
    Left e -> do
      err $ "cryptopals: " <> e
      SE.exitFailure

    Right bs -> do
      let fs = concatMap (\s -> [(head . CU.often $ s, s)]) bs -- XX hack
          sorted = L.sortBy (flip compare `on`  (snd . fst)) fs
          most   = take 3 sorted

      err "cryptopals: suspect inputs"
      F.for_ most $ \((_, _), s) -> do
        err $ "cryptopals: " <> (TE.decodeUtf8 . B16.encodeBase16' $ s)
        out . TE.decodeUtf8 . B16.encodeBase16' $ s

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "produce byte frequencies"
        <> O.header "detect-single-byte-xor"

  args <- O.execParser pars

  detect args

