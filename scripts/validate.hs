{-# language BangPatterns #-}
{-# language LambdaCase #-}

import Data.Primitive (ByteArray)
import Data.ByteString (ByteString)
import Data.Bool (bool)
import Control.Exception
import System.IO.Error (isEOFError)
import Foreign.C.Types (CChar)
import Panos.Syslog (decode)

import qualified Data.Primitive as PM
import qualified Data.Primitive.Ptr as PM
import qualified Data.ByteString as ByteString
import qualified Data.Bytes as Bytes

main :: IO ()
main = do
  let go !ix = catchJust (bool Nothing (Just ()) . isEOFError) (Just <$> ByteString.getLine) (\() -> pure Nothing) >>= \case
        Nothing -> pure ()
        Just b0 -> do
          b1 <- b2b b0
          case decode (Bytes.fromByteArray b1) of
            Left err -> fail $ "On line " ++ show ix ++ ", " ++ show err
            Right _ -> go (ix + 1)
  go 0

b2b :: ByteString -> IO ByteArray
b2b !b = ByteString.useAsCStringLen b $ \(ptr,len) -> do
  arr <- PM.newByteArray len
  PM.copyPtrToMutablePrimArray (castArray arr) 0 ptr len
  PM.unsafeFreezeByteArray arr

castArray :: PM.MutableByteArray s -> PM.MutablePrimArray s CChar
castArray (PM.MutableByteArray x) = PM.MutablePrimArray x
