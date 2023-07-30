{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Cryptopals.Stream.RNG.MT19937 as MT
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Data.Foldable (for_)
import GHC.Word (Word32)
import qualified Options.Applicative as O

data Args = Args {
    argsSeed  :: Word32
  , argsBytes :: Word32
  }

ops :: O.Parser Args
ops = Args
  <$> O.argument O.auto (O.metavar "SEED")
  <*> O.argument O.auto (O.metavar "BYTES")

mt :: Args -> IO ()
mt Args {..} = do
  let gen        = MT.seed argsSeed
      (bytes, _) = MT.bytes (fromIntegral argsBytes) gen

  for_ bytes $ TIO.putStrLn . T.pack . show

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "generate random bytes from a Mersenne Twister"
        <> O.header "mt19937"

  args <- O.execParser pars

  mt args

