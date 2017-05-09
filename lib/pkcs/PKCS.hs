
import Control.Error (readMay)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import GHC.Word
import System.Environment
import System.IO

main :: IO ()
main = do
  args <- getArgs

  case args of
    (narg:_) -> case readMay narg :: Maybe Int of
       Nothing    -> hPutStrLn stderr "pkcs: invalid length"
       Just padto -> do
         bytes <- B.getContents
         let len = B.length bytes
             npad :: Word8
             npad = fromIntegral $
               if   padto < len
               then 0
               else padto - len

             padded = B.append bytes (B.replicate (fromIntegral npad) npad)
         B8.putStrLn padded

    _ -> putStrLn "USAGE: echo STRING | ./pkcs LENGTH"


