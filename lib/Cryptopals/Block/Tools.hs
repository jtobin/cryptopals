module Cryptopals.Block.Tools (
    Mode(..)

  , detectMode
  ) where

import qualified Data.ByteString as BS
import qualified Data.Set as S

data Mode =
    ECB
  | CBC
  deriving (Eq, Show)

-- Assuming the ciphertext could only have been produced by AES
-- operating in ECB or CBC mode, guess the mode that was used.
detectMode :: BS.ByteString -> Mode
detectMode = loop mempty where
  loop !acc bs
    | BS.null bs = CBC
    | otherwise  =
        let (block, rest) = BS.splitAt 16 bs
        in  if   S.member block acc
            then ECB
            else loop (S.insert block acc) rest

