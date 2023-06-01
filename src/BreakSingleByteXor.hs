{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Cryptopals.Util as CU
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.List (foldl')
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.Text.Encoding as TE
import GHC.Word (Word8)
import qualified Options.Applicative as O
import qualified System.Exit as SE
import qualified System.IO as SIO

data Args = Args { argsInp :: T.Text }

ops :: O.Parser Args
ops = Args <$> O.argument O.str (O.metavar "INPUT")

best :: BS.ByteString -> (Word8, Double, BS.ByteString)
best s = foldl' alg (0, CU.score s, s) [32..126] where
  alg acc@(_, asc, _) b =
    let xo = CU.singleByteXor b s
        sc = CU.score xo
    in  if   sc < asc
        then (b, sc, xo)
        else acc

decipher :: Args -> IO ()
decipher Args {..} = do
  let render :: Show a => a -> T.Text
      render = T.pack . show

      err = TIO.hPutStrLn SIO.stderr
      out = TIO.hPutStrLn SIO.stdout

      args = B16.decodeBase16 $ TE.encodeUtf8 argsInp

  case args of
    Left e -> do
      err $ "cryptopals: " <> e
      SE.exitFailure

    Right s -> do
      err $ "cryptopals: input similarity score is " <> render (CU.score s)

      let (byt, bsc, b) = best s

      err (
        "cryptopals: xor-ing with " <> render byt <>
        " yields " <> render bsc
        )

      err $ "cryptopals: result"
      out . TE.decodeUtf8 . B16.encodeBase16' $ b

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "attempt to break single-byte xor'd ciphertext"
        <> O.header "break-single-byte-xor"

  args <- O.execParser pars

  decipher args

