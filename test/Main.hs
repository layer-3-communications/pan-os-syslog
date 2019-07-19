{-# language BangPatterns #-}
{-# language MultiWayIf #-}
{-# language ScopedTypeVariables #-}
{-# language TypeApplications #-}

import Panos.Syslog (Log(..),decodeLog)

import Control.Exception (throwIO)
import Data.Primitive (ByteArray)
import Data.Word (Word8)
import Data.Char (ord)
import Data.Bytes.Types (Bytes(Bytes))

import qualified Panos.Syslog.Traffic as Traffic
import qualified Data.Primitive as PM
import qualified GHC.Exts as Exts
import qualified Sample as S

main :: IO ()
main = do
  putStrLn "Start"
  putStrLn "8.1-A"
  testA
  putStrLn "Finished"

testA :: IO ()
testA = case decodeLog S.traffic_8_1_A of
  Left err -> throwIO err
  Right (LogTraffic t) ->
    if | Traffic.deviceName t /= bytes "MY-DEVICE-NAME" ->
           fail $
             "wrong device name:\nexpected: " ++
             show (bytes "MY-DEVICE-NAME") ++
             "\nactually: " ++
             show (Traffic.deviceName t)
       | Traffic.packetsReceived t /= 0 ->
           fail $
             "wrong packets received: expected 0 but got " ++
             show (Traffic.packetsReceived t)
       | Traffic.bytesReceived t /= 34 ->
           fail $
             "wrong bytes received: expected 34 but got " ++
             show (Traffic.bytesReceived t)
       | otherwise -> pure ()
  Right _ -> fail "wrong log type" 

bytes :: String -> Bytes
bytes s = let b = pack s in Bytes b 0 (PM.sizeofByteArray b)

pack :: String -> ByteArray
pack = Exts.fromList . map (fromIntegral @Int @Word8 . ord)

