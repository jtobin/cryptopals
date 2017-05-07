{-# OPTIONS_GHC -Wall #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

import Control.Error (readMay)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import System.Environment
import System.IO

-- | Split a bytestring into chunks.
chunks :: Int -> B.ByteString -> [B.ByteString]
chunks size = loop mempty where
  loop !acc bs
    | B.null bs = reverse acc
    | otherwise = case B.splitAt size bs of
        (chunk, rest) -> loop (chunk : acc) rest

main :: IO ()
main = do
  args <- getArgs

  case args of
    (narg:_) -> case readMay narg :: Maybe Int of
       Nothing   -> hPutStrLn stderr "chunks: invalid keysize"
       Just size -> do
         hex <- B.getContents
         let (bs, _) = B16.decode hex
             chunked = chunks size bs
             rehexed = fmap B16.encode chunked
         mapM_ B8.putStrLn rehexed

    _ -> putStrLn "USAGE: echo FOO | ./chunks KEYSIZE"
