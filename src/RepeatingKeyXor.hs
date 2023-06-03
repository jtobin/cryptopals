{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Cryptopals.Util as CU
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import qualified Options.Applicative as O

data Encoding =
    Utf8
  | Utf16

data Args = Args {
    argsKey :: T.Text
  , argsInp :: T.Text
  , argsEnc :: Encoding
  }

ops :: O.Parser Args
ops = Args
  <$> O.argument O.str (O.metavar "KEY")
  <*> O.argument O.str (O.metavar "INPUT")
  <*> O.flag Utf8 Utf16 (
        O.long "hex" <>
        O.help "input is hex-encoded"
        )

rxor :: Args -> IO ()
rxor Args {..} = do
  let k = TE.encodeUtf8 argsKey
      v = case argsEnc of
            Utf8  -> pure $ TE.encodeUtf8 argsInp
            Utf16 -> B16.decodeBase16 (TE.encodeUtf8 argsInp)

  case v of
    Left e  -> error "FIXME"
    Right s ->
      TIO.putStrLn . TE.decodeUtf8 . B16.encodeBase16' $
        CU.repeatingKeyXor k s

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "compute repeating-key-xor KEY on INPUT"
        <> O.header "repeating-key-xor"

  args <- O.execParser pars

  rxor args

