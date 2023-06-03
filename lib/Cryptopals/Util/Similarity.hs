module Cryptopals.Util.Similarity (
    score
  , tally
  , often
  ) where

import qualified Data.ByteString as BS
import Data.Function (on)
import qualified Data.IntMap.Strict as IMS
import qualified Data.List as L

-- | Distance of the encoding from expected English plaintext.
score :: BS.ByteString -> Double
score = mse english . dist

mse :: IMS.IntMap Double -> IMS.IntMap Double -> Double
mse ref tar =
    let res = IMS.foldlWithKey' alg mempty ref
        siz = IMS.size res
    in  IMS.foldl' (\acc val -> acc + val / fromIntegral siz) 0 res
  where
    alg acc key val = case IMS.lookup key tar of
      Nothing  -> acc
      Just tal -> IMS.insert key ((tal - val) ^ 2) acc

dist :: BS.ByteString -> IMS.IntMap Double
dist = normalize . tally

often :: BS.ByteString -> [(Int, Int)]
often = L.sortBy (flip compare `on` snd) . IMS.toList . tally

tally :: BS.ByteString -> IMS.IntMap Int
tally = BS.foldl' alg mempty where
  alg acc (fromIntegral -> byt)
    | IMS.member byt acc = IMS.adjust succ byt acc
    | otherwise          = IMS.insert byt 1 acc

normalize :: IMS.IntMap Int -> IMS.IntMap Double
normalize m =
  let siz = fromIntegral $ IMS.foldl' (+) 0 m
  in  fmap (\val -> fromIntegral val / siz) m

-- | Observed frequency distribution of bytes in English corpora.
english :: IMS.IntMap Double
english = IMS.fromAscList [
    (9, 0.000057)
  , (23, 0.000000)
  , (32, 0.171662)
  , (33, 0.000072)
  , (34, 0.002442)
  , (35, 0.000179)
  , (36, 0.000561)
  , (37, 0.000160)
  , (38, 0.000226)
  , (39, 0.002447)
  , (40, 0.002178)
  , (41, 0.002233)
  , (42, 0.000628)
  , (43, 0.000215)
  , (44, 0.007384)
  , (45, 0.013734)
  , (46, 0.015124)
  , (47, 0.001549)
  , (48, 0.005516)
  , (49, 0.004594)
  , (50, 0.003322)
  , (51, 0.001847)
  , (52, 0.001348)
  , (53, 0.001663)
  , (54, 0.001153)
  , (55, 0.001030)
  , (56, 0.001054)
  , (57, 0.001024)
  , (58, 0.004354)
  , (59, 0.001214)
  , (60, 0.001225)
  , (61, 0.000227)
  , (62, 0.001242)
  , (63, 0.001474)
  , (64, 0.000073)
  , (65, 0.003132)
  , (66, 0.002163)
  , (67, 0.003906)
  , (68, 0.003151)
  , (69, 0.002673)
  , (70, 0.001416)
  , (71, 0.001876)
  , (72, 0.002321)
  , (73, 0.003211)
  , (74, 0.001726)
  , (75, 0.000687)
  , (76, 0.001884)
  , (77, 0.003529)
  , (78, 0.002085)
  , (79, 0.001842)
  , (80, 0.002614)
  , (81, 0.000316)
  , (82, 0.002519)
  , (83, 0.004003)
  , (84, 0.003322)
  , (85, 0.000814)
  , (86, 0.000892)
  , (87, 0.002527)
  , (88, 0.000343)
  , (89, 0.000304)
  , (90, 0.000076)
  , (91, 0.000086)
  , (92, 0.000016)
  , (93, 0.000088)
  , (94, 0.000003)
  , (95, 0.001159)
  , (96, 0.000009)
  , (97, 0.051880)
  , (98, 0.010195)
  , (99, 0.021129)
  , (100, 0.025071)
  , (101, 0.085771)
  , (102, 0.013725)
  , (103, 0.015597)
  , (104, 0.027444)
  , (105, 0.049019)
  , (106, 0.000867)
  , (107, 0.006753)
  , (108, 0.031750)
  , (109, 0.016437)
  , (110, 0.049701)
  , (111, 0.057701)
  , (112, 0.015482)
  , (113, 0.000747)
  , (114, 0.042586)
  , (115, 0.043686)
  , (116, 0.063700)
  , (117, 0.020999)
  , (118, 0.008462)
  , (119, 0.013034)
  , (120, 0.001950)
  , (121, 0.011330)
  , (122, 0.000596)
  , (123, 0.000026)
  , (124, 0.000007)
  , (125, 0.000026)
  , (126, 0.000003)
  , (131, 0.000000)
  , (149, 0.006410)
  , (183, 0.000010)
  , (223, 0.000000)
  , (226, 0.000000)
  , (229, 0.000000)
  , (230, 0.000000)
  , (237, 0.000000)
  ]

