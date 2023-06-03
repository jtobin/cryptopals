module Cryptopals.Util.ByteString (
    hamming
  , nhamming
  , panhamming
  , chunks
  , rotate
  ) where

import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.List as L
import qualified Data.List.NonEmpty as NE

-- | Hamming distance between bytestrings.
hamming :: BS.ByteString -> BS.ByteString -> Maybe Int
hamming l r
    | BS.length l /= BS.length r = Nothing
    | otherwise = Just (foldr alg 0 (BS.zip l r))
  where
    ham a b = B.popCount (B.xor a b)
    alg = (+) . uncurry ham

-- | Normalized Hamming distance between bytestrings.
nhamming :: BS.ByteString -> BS.ByteString -> Maybe Double
nhamming a b =
  let len = fromIntegral (BS.length a)
  in  fmap (\s -> fromIntegral s / len) (hamming a b)

-- | Average pairwise normalized Hamming distance between bytestrings.
panhamming:: [BS.ByteString] -> Maybe Double
panhamming bs = case bs of
  [] -> Nothing
  _  ->  do
    ps <- sequence [nhamming h b | (h:t) <- L.tails bs, b <- t]
    pure $ sum ps / fromIntegral (length ps)

chunks :: Int -> BS.ByteString -> [BS.ByteString]
chunks size = loop mempty where
  loop !acc bs
    | BS.null bs = reverse acc
    | otherwise = case BS.splitAt size bs of
        (chunk, rest) -> loop (chunk : acc) rest

rotate :: Int -> BS.ByteString -> [BS.ByteString]
rotate rows = BS.transpose . chunks rows
