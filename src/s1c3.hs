{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import qualified Data.Map.Strict as MS
import GHC.Word

hash :: B.ByteString
hash = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

fromHex :: B.ByteString -> [Word8]
fromHex = B.unpack . fst . B16.decode

tally :: Ord a => [a] -> MS.Map a Int
tally = loop MS.empty where
  loop !acc []     = acc
  loop !acc (x:xs) =
    let nacc = case MS.lookup x acc of
          Nothing -> MS.insert x 1 acc
          Just _  -> MS.update (Just . succ) x acc
    in  loop nacc xs

mostFrequent :: MS.Map a Int -> Maybe a
mostFrequent ms = case MS.toList ms of
    []          -> Nothing
    ((k, v):xs) -> Just (loop k v xs)
  where
    loop mk _ []          = mk
    loop mk mv ((k, v):xs) = case compare v mv of
      GT -> loop k v xs
      _  -> loop mk mv xs

decrypt :: B8.ByteString -> B8.ByteString
decrypt bs = case mostFrequent (tally bytes) of
    Nothing -> bs
    Just c  ->
      let xored = fmap (`xor` c) bytes
      in  B.pack xored
  where
    bytes = fromHex bs

main :: IO ()
main = do
  B8.putStrLn hash
  B8.putStrLn (decrypt hash)
