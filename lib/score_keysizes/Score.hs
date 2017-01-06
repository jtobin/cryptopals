{-# OPTIONS_GHC -Wall #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

import Control.Error (readMay)
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base64 as B64
import qualified Data.IntPSQ as PSQ
import System.Environment

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

-- | Score keysizes 2-40 over a given bytestring.
scoreKeysizes :: B.ByteString -> PSQ.IntPSQ Double ()
scoreKeysizes text = loop PSQ.empty 2 where
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

main :: IO ()
main = do
  bs   <- B8.getContents
  args <- getArgs

  case args of
    (narg:_) -> do
      let n = case readMay narg :: Maybe Int of
                Nothing  -> PSQ.size scored
                Just val -> val

          scored = scoreKeysizes bs
          top    = best n scored

          render (k, v) = show k ++ ": " ++ show v

      putStrLn "keysize: score"
      mapM_ (putStrLn . render) top

    _ -> putStrLn "USAGE: echo BASE64 | ./score_keysizes NUM_RESULTS"
