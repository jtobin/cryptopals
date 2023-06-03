{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Cryptopals.Util as CU
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.Text.Encoding as TE
import qualified Options.Applicative as O
import qualified System.Exit as SE
import qualified System.IO as SIO

data Args = Args { argsInp :: T.Text }

ops :: O.Parser Args
ops = Args <$> O.argument O.str (O.metavar "INPUT")

score :: BS.ByteString -> Maybe (Double, Int)
score b = loop Nothing 2 where
  loop acc siz
    | siz == 40 = acc
    | otherwise =
        let sc = CU.panhamming
               . filter (\s -> BS.length s == siz)
               . CU.chunks siz
               $ b
        in  case sc of
              Nothing -> loop acc (succ siz)
              Just s  ->
                let nacc = case acc of
                      Nothing -> Just (s, siz)
                      Just (r, _)  -> if   s < r
                                      then Just (s, siz)
                                      else acc
                in  loop nacc (succ siz)

guess :: Args -> IO ()
guess Args {..} = do
  let err = TIO.hPutStrLn SIO.stderr

      render :: Show a => a -> T.Text
      render = T.pack . show

      s = B64.decodeBase64Lenient $ TE.encodeUtf8 argsInp

  case score s of
    Nothing -> do
      err "cryptopals: couldn't guess keysize"
      SE.exitFailure

    Just (sc, siz) -> do
      err ("cryptopals: keysize of " <> render siz <>
           " yields minimum score of " <> render sc)

main :: IO ()
main = do
  let pars = O.info (O.helper <*> ops) $
           O.fullDesc
        <> O.progDesc "guess repeating-key-xor'd keysize"
        <> O.header "detect-repeating-key-xor-keysize"

  args <- O.execParser pars

  guess args

