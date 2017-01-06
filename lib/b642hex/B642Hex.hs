{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base16 as B16
import System.IO

main :: IO ()
main = do
  bs <- B.getContents

  let decoded = B64.decodeLenient bs
      encoded = B16.encode decoded

  B8.hPutStrLn stdout encoded

