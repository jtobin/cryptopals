{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Cryptopals.AES as AES
import qualified Data.ByteString.Base16 as B16
import qualified Data.Char as C
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import qualified Options.Applicative as O
import qualified System.Exit as SE
import qualified System.IO as SIO

data Operation =
    Encrypt
  | Decrypt

data Args = Args {
    argsOpr :: Operation
  , argsKey :: T.Text
  , argsInp :: T.Text
  }

ops :: O.Parser Args
ops = Args
  <$> operationParser
  <*> O.argument O.str (O.metavar "KEY")
  <*> O.argument O.str (O.metavar "INPUT")

operationParser :: O.Parser Operation
operationParser = O.argument op etc where
  op = O.eitherReader $ \input -> case fmap C.toLower input of
    "encrypt" -> pure Encrypt
    "decrypt" -> pure Decrypt
    _         -> Left ("invalid operation: " <> input)

  etc = O.metavar "OPERATION"
     <> O.help "{encrypt, decrypt}"

aes :: Args -> IO ()
aes Args {..} = do
  let args = do
        k <- B16.decodeBase16 $ TE.encodeUtf8 argsKey
        v <- B16.decodeBase16 $ TE.encodeUtf8 argsInp
        pure (k, v)

  case args of
    Left e -> do
      TIO.hPutStrLn SIO.stderr ("cryptopals: " <> e)
      SE.exitFailure

    Right (k, v) -> do
      case argsOpr of
        Encrypt -> TIO.putStrLn . TE.decodeUtf8 . B16.encodeBase16' $
          AES.encryptEcbAES128 k v

        Decrypt -> TIO.putStrLn . TE.decodeUtf8 . B16.encodeBase16' $
          AES.decryptEcbAES128 k v

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "AES encryption/decryption"
        <> O.header "aes"

  args <- O.execParser pars

  aes args

