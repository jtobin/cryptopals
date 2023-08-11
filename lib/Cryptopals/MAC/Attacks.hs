{-# LANGUAGE ApplicativeDo #-}

module Cryptopals.MAC.Attacks where

import qualified Control.Monad.Trans.Reader as R
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Char8 as BL8
import qualified Data.Binary.Get as BG
import qualified Data.Binary.Put as BP
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Cryptopals.MAC as CM
import qualified Cryptopals.Digest.Pure.MD4 as M
import qualified Cryptopals.Digest.Pure.SHA as S
import GHC.Word (Word8, Word32, Word64)
import qualified System.Random.MWC as MWC

data SHA1Registers = SHA1Registers !Word32 !Word32 !Word32 !Word32 !Word32
  deriving (Eq, Show)

data MD4Registers = MD4Registers !Word32 !Word32 !Word32 !Word32
  deriving (Eq, Show)

sha1 :: SHA1Registers -> Word64 -> BSL.ByteString -> BSL.ByteString
sha1 (SHA1Registers a b c d e) n s =
  S.bytestringDigest $ S.sha1' a b c d e n s

md4 :: MD4Registers -> Word64 -> BSL.ByteString -> BSL.ByteString
md4 (MD4Registers a b c d) n s = M.md4' a b c d n s

raw :: BSL.ByteString
raw = mconcat [
    "comment1=cooking%20MCs;userdata=foo;"
  , "comment2=%20like%20a%20pound%20of%20bacon"
  ]

mal :: BSL.ByteString
mal = ";admin=true"

key :: IO BSL.ByteString
key = do
  gen <- MWC.createSystemRandom
  idx <- MWC.uniformR (0, 235885) gen
  dict <- BL8.readFile "/usr/share/dict/words"
  let ls = BL8.lines dict
  pure $ ls !! idx

-- pad a message using the specified message length
pad :: Word64 -> BSL.ByteString -> BSL.ByteString
pad n bs = bs <> padding n where
  padding n = BP.runPut $ do
    BP.putWord8 128
    loop (pred (pbytes n))

  loop l
    | l == 0    = BP.putWord64be (n * 8)
    | otherwise = do
        BP.putWord8 0
        loop (pred l)

  pbytes ((\k -> 64 - k `mod` 64) -> l)
    | l == 0    = l + 56
    | otherwise = l - 8

-- sha1-keyed MAC via length extension

injectSha1 :: BSL.ByteString -> SHA1Registers
injectSha1 = BG.runGet $ do
  a <- BG.getWord32be
  b <- BG.getWord32be
  c <- BG.getWord32be
  d <- BG.getWord32be
  e <- BG.getWord32be
  pure $ SHA1Registers a b c d e

extractSha1 :: SHA1Registers -> BSL.ByteString
extractSha1 (SHA1Registers a b c d e) = BP.runPut $ do
  BP.putWord32be a
  BP.putWord32be b
  BP.putWord32be c
  BP.putWord32be d
  BP.putWord32be e

leasha1
  :: BSL.ByteString
  -> BSL.ByteString
  -> BSL.ByteString
  -> R.Reader BSL.ByteString (BSL.ByteString, BSL.ByteString)
leasha1 input mac addl = loop 0 where
  loop j = do
    let len = fromIntegral $ BSL.length input
        evil = pad (len + j) input <> addl
        rs   = injectSha1 mac
        p    = fromIntegral (BSL.length evil) + j
        forged = sha1 rs p addl
    validates <- oracleValidates evil forged
    if   validates
    then pure (evil, forged)
    else loop (succ j)

  oracleValidates msg mac = do
    k <- R.ask
    pure $ CM.verifysha1mac k mac msg

-- md4-keyed MAC via length extension

-- little-endian 'pad'
padle :: Word64 -> BSL.ByteString -> BSL.ByteString
padle n bs = bs <> padding n where
  padding n = BP.runPut $ do
    BP.putWord8 128
    loop (pred (pbytes n))

  loop l
    | l == 0    = BP.putWord64le (n * 8)
    | otherwise = do
        BP.putWord8 0
        loop (pred l)

  pbytes ((\k -> 64 - k `mod` 64) -> l)
    | l == 0    = l + 56
    | otherwise = l - 8

injectMd4 :: BSL.ByteString -> MD4Registers
injectMd4 = BG.runGet $ do
  a <- BG.getWord32le
  b <- BG.getWord32le
  c <- BG.getWord32le
  d <- BG.getWord32le
  pure $ MD4Registers a b c d

extractMd4 :: MD4Registers -> BSL.ByteString
extractMd4 (MD4Registers a b c d) = BP.runPut $ do
  BP.putWord32le a
  BP.putWord32le b
  BP.putWord32le c
  BP.putWord32le d

leamd4
  :: BSL.ByteString
  -> BSL.ByteString
  -> BSL.ByteString
  -> R.Reader BSL.ByteString (BSL.ByteString, BSL.ByteString)
leamd4 input mac addl = loop 0 where
  loop j = do
    let len = fromIntegral $ BSL.length input
        evil = padle (len + j) input <> addl
        rs   = injectMd4 mac
        p    = fromIntegral (BSL.length evil) + j
        forged = md4 rs p addl
    validates <- oracleValidates evil forged
    if   validates
    then pure (evil, forged)
    else loop (succ j)

  oracleValidates msg mac = do
    k <- R.ask
    pure $ CM.verifymd4mac k mac msg

