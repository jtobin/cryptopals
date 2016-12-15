{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import qualified Data.Map.Strict as MS
import GHC.Word

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

mostFrequent :: MS.Map a Int -> Maybe (a, Int)
mostFrequent ms = case MS.toList ms of
    []          -> Nothing
    ((k, v):xs) -> Just (loop k v xs)
  where
    loop mk mv []          = (mk, mv)
    loop mk mv ((k, v):xs) = case compare v mv of
      GT -> loop k v xs
      _  -> loop mk mv xs

decrypt :: B8.ByteString -> B8.ByteString
decrypt bs = case mostFrequent (tally bytes) of
    Nothing     -> bs
    Just (c, _) ->
      let xored = filter printable $ fmap (`xor` c) bytes
      in  B.pack xored
  where
    bytes       = fromHex bs
    printable c = elem c [33..126]

prune :: [B8.ByteString] -> [B8.ByteString]
prune = filter highscoring where
  highscoring string = case mostFrequent (tally (fromHex string)) of
    Nothing     -> False
    Just (c, v) -> v > 4

display :: B8.ByteString -> IO ()
display string = do
  B8.putStrLn string
  B8.putStrLn (decrypt string)
  B8.putStrLn mempty

batchDecrypt :: FilePath -> IO ()
batchDecrypt file = do
  strings <- fmap B8.lines $ B.readFile file
  mapM_ display (prune strings)

