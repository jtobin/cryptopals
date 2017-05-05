{-# OPTIONS_GHC -Wall #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}

import Control.Error
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.IntPSQ as PSQ
import qualified Data.Map.Strict as MS
import GHC.Word
import System.IO

-- | Hamming distance between bytestrings.
--
--   Returns Nothing if bytestrings are of unequal length.
distance :: B.ByteString -> B.ByteString -> Maybe Int
distance s0 s1
    | B.length s0 /= B.length s1 = Nothing
    | otherwise = Just (foldr alg 0 (B.zip s0 s1))
  where
    hamming a b = popCount (xor a b)
    alg = (+) . uncurry hamming

-- | Score a keysize applied to a bytestring.
score :: Fractional a => B.ByteString -> Int -> Maybe a
score text size = do
  let (chunk0, rest) = B.splitAt size text
      chunk1         = B.take size rest
  hamming <- distance chunk0 chunk1
  return $ fromIntegral hamming / fromIntegral size

-- | More meticulously score a keysize applied to a bytestring.
altScore :: Fractional a => B.ByteString -> Int -> Maybe a
altScore text size = do
  let chunked = chunks size text
      leading = take 4 chunked

  chunk0 <- atMay leading 0
  chunk1 <- atMay leading 1
  chunk2 <- atMay leading 2
  chunk3 <- atMay leading 3

  hamming0 <- distance chunk0 chunk1
  hamming1 <- distance chunk0 chunk2
  hamming2 <- distance chunk0 chunk3

  let dsum = hamming0 + hamming1 + hamming2

  return $ fromIntegral dsum / (3 * fromIntegral size)

-- | Score keysizes 2-40 over a given bytestring.
scoreKeysizes
  :: (B.ByteString -> Int -> Maybe Double)
  -> B.ByteString
  -> PSQ.IntPSQ Double ()
scoreKeysizes scorer text = loop PSQ.empty 2 where
  plain = B64.decodeLenient text
  loop !acc size
    | size == 40 = acc
    | otherwise = case score plain size of
        Nothing   -> acc
        Just prio ->
          let nacc = PSQ.insert size prio () acc
          in  loop nacc (succ size)

-- | Return the best (smallest) n keys from a queue, by key..
best :: Ord p => Int -> PSQ.IntPSQ p v -> [(Int, p)]
best = loop mempty where
  loop !acc idx queue
    | idx <= 0  = reverse acc
    | otherwise = case PSQ.minView queue of
        Nothing -> reverse acc
        Just (key, prio, _, rest) ->
          let nacc = (key, prio) : acc
          in  loop nacc (pred idx) rest

-- | Split a bytestring into chunks.
chunks :: Int -> B.ByteString -> [B.ByteString]
chunks size = loop mempty where
  loop !acc bs
    | B.null bs = reverse acc
    | otherwise = case B.splitAt size bs of
        (chunk, rest) -> loop (chunk : acc) rest

tally :: Ord a => [a] -> MS.Map a Int
tally = loop MS.empty where
  loop !acc []     = acc
  loop !acc (x:xs) =
    let nacc = case MS.lookup x acc of
          Nothing    -> MS.insert x 1 acc
          Just count -> MS.update (Just . succ) x acc
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

main :: IO ()
main = do
  raw <- B.readFile "etc/data/6.txt"
  let mdecoded = B64.decode (B8.filter (/= '\n') raw)

  case mdecoded of
    Left msg      -> hPutStrLn stderr msg
    Right decoded -> do
      let hexed    = B16.encode decoded
          chunked  = chunks 3 hexed
          rotated  = B.transpose chunked
          unpacked = fmap B.unpack rotated

      return ()

  return ()
