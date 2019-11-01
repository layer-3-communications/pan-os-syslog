{-# language BangPatterns #-}
{-# language MultiWayIf #-}
{-# language ScopedTypeVariables #-}
{-# language TypeApplications #-}

import Panos.Syslog (Log(..),decodeLog)

import Control.Exception (throwIO)
import Data.Primitive (ByteArray)
import Data.Word (Word8)
import Data.Char (ord,chr)
import Data.Bytes.Types (Bytes(Bytes))

import qualified Panos.Syslog.Traffic as Traffic
import qualified Panos.Syslog.Threat as Threat
import qualified Panos.Syslog.System as System
import qualified Data.Primitive as PM
import qualified GHC.Exts as Exts
import qualified Sample as S

main :: IO ()
main = do
  putStrLn "Start"
  putStrLn "8.1-Traffic-A"
  testA
  putStrLn "8.1-Traffic-B"
  testTrafficB
  putStrLn "8.1-Threat-A"
  testB
  putStrLn "8.1-Threat-B"
  testC
  putStrLn "8.1-Threat-C"
  testD
  putStrLn "8.1-System-A"
  testSystemA
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

testB :: IO ()
testB = case decodeLog S.threat_8_1_A of
  Left err -> throwIO err
  Right (LogThreat t) ->
    if | Threat.contentVersion t /= bytes "AppThreat-1-6" -> fail $
           "wrong content version:\nExpected: AppThreat-1-6\nActually: " ++
           prettyBytes (Threat.contentVersion t)
       | Threat.miscellaneous t /= bytes "www.example.com/string/\"hello\"" -> fail $
           "wrong miscellaneous (URL):\nExpected: www.example.com\nActually: " ++
           prettyBytes (Threat.miscellaneous t)
       | otherwise -> pure ()
  Right _ -> fail "wrong log type" 

testTrafficB :: IO ()
testTrafficB = case decodeLog S.traffic_8_1_B of
  Left err -> throwIO err
  Right (LogTraffic t) ->
    if | Traffic.sourceUser t /= bytes "example\\jdoe" ->
           fail $
             "wrong source user:\nexpected: " ++
             show (bytes "MY-DEVICE-NAME") ++
             "\nactually: " ++
             show (Traffic.deviceName t)
       | otherwise -> pure ()
  Right _ -> fail "wrong log type" 

testC :: IO ()
testC = case decodeLog S.threat_8_1_B of
  Left err -> throwIO err
  Right (LogThreat t) ->
    if | Threat.miscellaneous t /= bytes "www.example.com/" -> fail $
           "wrong miscellaneous (URL):\nExpected: www.example.com/\nActually: " ++
           prettyBytes (Threat.miscellaneous t) ++ "\n"
       | Threat.virtualSystemName t /= bytes "the-vsys-name" -> fail $
           "wrong vsys name:\nExpected: the-vsys-name\nActually: " ++
           prettyBytes (Threat.virtualSystemName t) ++ "\n"
       | Threat.contentVersion t /= bytes "AppThreat-3-7" -> fail $
           "wrong content version:\nExpected: AppThreat-3-7\nActually: " ++
           prettyBytes (Threat.contentVersion t) ++ "\n"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type" 

testD :: IO ()
testD = case decodeLog S.threat_8_1_C of
  Left err -> throwIO err
  Right (LogThreat t) ->
    if | Threat.threatId t /= 30845 -> fail $
           "wrong threat id:\nExpected: 30845\nActually: " ++
           show (Threat.threatId t) ++ "\n"
       | Threat.threatName t /= bytes "Microsoft RPC Endpoint Mapper Detection" -> fail $
           "wrong threat name:\nExpected: Microsoft RPC Endpoint Mapper Detection\nActually: " ++
           prettyBytes (Threat.threatName t) ++ "\n"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type" 

testSystemA :: IO ()
testSystemA = case decodeLog S.system_8_1_A of
  Left err -> throwIO err
  Right (LogSystem t) ->
    if | System.deviceName t /= bytes "NY-DC-FW-2" -> fail $
           "wrong device name:\nexpected: NY-DC-FW-2\nactually: " ++
           show (System.deviceName t)
       | System.description t /= bytes
           ( concat
             [ "IKE protocol IPSec SA delete message "
             , "sent to peer. SPI:0xA1CD910F."
             ]
           ) -> fail $
             "wrong description:\nexpected something about IKE\nactually: " ++
             show (System.description t)
       | otherwise -> pure ()
  Right _ -> fail "wrong log type" 


bytes :: String -> Bytes
bytes s = let b = pack s in Bytes b 0 (PM.sizeofByteArray b)

pack :: String -> ByteArray
pack = Exts.fromList . map (fromIntegral @Int @Word8 . ord)

prettyBytes :: Bytes -> String
prettyBytes (Bytes arr off len) = if len > 0
  then
    let w = PM.indexByteArray arr off :: Word8
        c = if w > 31 && w < 127
              then chr (fromIntegral w)
              else 'X'
     in c : prettyBytes (Bytes arr (off + 1) (len - 1))
  else []
