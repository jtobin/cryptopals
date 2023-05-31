{-# LANGUAGE RecordWildCards #-}

module Main where

import Cryptopals.Util (Hex(..))
import qualified Cryptopals.Util as CU
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.Text.Encoding as TE
import qualified Options.Applicative as O

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
  let k = Hex (TE.encodeUtf8 argsKey)
      v = Hex (TE.encodeUtf8 argsInp)
      r = CU.fixedXor k v

  case r of
    Left e        -> TIO.putStrLn e
    Right (Hex b) -> TIO.putStrLn (TE.decodeUtf8 b)

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "compute fixed-xor KEY on INPUT"
        <> O.header "fixed-xor"

  args <- O.execParser pars

  fxor args

