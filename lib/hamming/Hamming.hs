{-# LANGUAGE OverloadedStrings #-}

import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import System.Environment
import System.Exit
import System.IO

-- | Hamming distance between bytestrings.
--
--   Returns Nothing if bytestrings are of unequal length.
distance :: B.ByteString -> B.ByteString -> Maybe Int
distance s0 s1
    | B.length s0 /= B.length s1 = Nothing
    | otherwise = Just (foldr alg 0 (B.zip s0 s1))
  where
    hamming (a, b) = popCount (xor a b)
    alg            = (+) . hamming

main :: IO ()
main = do
  args <- getArgs
  case args of
    (s0:s1:_) -> do
      let b0 = B8.pack s0
          b1 = B8.pack s1
          mhamming = distance b0 b1
      case mhamming of
        Nothing -> do
          hPutStrLn stderr "hamming: string lengths unequal"
          exitFailure

        Just hamming -> print hamming

    _ -> hPutStrLn stderr "USAGE: ./hamming STRING STRING"

