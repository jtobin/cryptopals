{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Applicative (optional)
import qualified Cryptopals.AES as AES
import qualified Data.ByteString.Base16 as B16
import qualified Data.Char as C
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import GHC.Word (Word64)
import qualified Options.Applicative as O
import qualified System.Exit as SE
import qualified System.IO as SIO

data Operation =
    Encrypt
  | Decrypt

data Mode =
    ECB
  | CBC
  | CTR

data Args = Args {
    argsOpr   :: Operation
  , argsMod   :: Mode
  , argsIv    :: Maybe T.Text
  , argsKey   :: T.Text
  , argsNonce :: Maybe Word64
  , argsInp   :: T.Text
  }

ops :: O.Parser Args
ops = Args
  <$> operationParser
  <*> modeParser
  <*> optional (O.strOption (O.long "iv" <> O.metavar "IV"))
  <*> O.argument O.str (O.metavar "KEY")
  <*> optional (O.option O.auto (O.long "nonce" <> O.metavar "NONCE"))
  <*> O.argument O.str (O.metavar "INPUT")

operationParser :: O.Parser Operation
operationParser = O.argument op etc where
  op = O.eitherReader $ \input -> case fmap C.toLower input of
    "encrypt" -> pure Encrypt
    "decrypt" -> pure Decrypt
    _         -> Left ("invalid operation: " <> input)

  etc = O.metavar "OPERATION"
     <> O.help "{encrypt, decrypt}"

modeParser :: O.Parser Mode
modeParser = O.argument mode etc where
  mode = O.eitherReader $ \input -> case fmap C.toLower input of
    "ecb" -> pure ECB
    "cbc" -> pure CBC
    "ctr" -> pure CTR
    _     -> Left ("invalid mode: " <> input)

  etc = O.metavar "MODE"
     <> O.help "{ecb, cbc}"

aes :: Args -> IO ()
aes Args {..} = do
  let args = do
        k <- B16.decodeBase16 $ TE.encodeUtf8 argsKey
        v <- B16.decodeBase16 $ TE.encodeUtf8 argsInp
        pure (k, v)

      out = TIO.putStrLn . TE.decodeUtf8 . B16.encodeBase16'
      err = TIO.hPutStrLn SIO.stderr

  case args of
    Left e -> do
      TIO.hPutStrLn SIO.stderr ("cryptopals: " <> e)
      SE.exitFailure

    Right (k, v) -> do
      case argsOpr of
        Encrypt -> case argsMod of
          ECB -> out $ AES.encryptEcbAES128 k v

          CBC -> case argsIv of
            Nothing -> do
              err $ "cryptopals: must provide IV"
              SE.exitFailure

            Just miv -> case B16.decodeBase16 (TE.encodeUtf8 miv) of
              Left e -> do
                err $ "cryptopals: " <> e
                SE.exitFailure

              Right iv ->
                out $ AES.encryptCbcAES128 iv k v

          CTR -> case argsNonce of
            Nothing -> do
              err $ "cryptopals: must provide nonce"
              SE.exitFailure

            Just n -> out $ AES.encryptCtrAES128 n k v

        Decrypt -> case argsMod of
          ECB -> out $ AES.decryptEcbAES128 k v

          CBC -> case argsIv of
            Nothing -> do
              err $ "cryptopals: must provide IV"
              SE.exitFailure

            Just miv -> case B16.decodeBase16 (TE.encodeUtf8 miv) of
              Left e -> do
                err $ "cryptopals: " <> e
                SE.exitFailure

              Right iv ->
                out $ AES.decryptCbcAES128 k v

          CTR -> case argsNonce of
            Nothing -> do
              err $ "cryptopals: must provide nonce"
              SE.exitFailure

            Just n -> out $ AES.decryptCtrAES128 n k v

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "AES encryption/decryption"
        <> O.header "aes"

  args <- O.execParser pars

  aes args

