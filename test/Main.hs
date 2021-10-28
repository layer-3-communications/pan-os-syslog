{-# language BangPatterns #-}
{-# language MultiWayIf #-}
{-# language ScopedTypeVariables #-}
{-# language TypeApplications #-}

import Panos.Syslog (Log(..),decode)

import Control.Exception (throwIO)
import Data.Primitive (ByteArray)
import Data.Word (Word8)
import Data.Char (ord,chr)
import Data.Bytes.Types (Bytes(Bytes))

import qualified Panos.Syslog.Traffic as Traffic
import qualified Panos.Syslog.Threat as Threat
import qualified Panos.Syslog.System as System
import qualified Panos.Syslog.User as User
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
  putStrLn "9.0-Traffic-A"
  testTraffic_9_0_A
  putStrLn "Prisma-Traffic-A"
  testPrismaTrafficA
  putStrLn "8.1-Threat-A"
  testB
  putStrLn "8.1-Threat-B"
  testC
  putStrLn "8.1-Threat-C"
  testD
  putStrLn "8.1-Threat-D"
  testThreatD
  putStrLn "8.1-Threat-E"
  testThreatE
  putStrLn "8.1-Threat-F"
  testThreatF
  putStrLn "8.1-Threat-G"
  testThreatG
  putStrLn "8.1-Threat-H"
  testThreatH
  putStrLn "8.1-Threat-I"
  testThreatI
  putStrLn "9.0-Threat-A"
  testThreat_9_0_A
  putStrLn "9.1-Threat-A"
  testThreat_9_1_A
  putStrLn "8.1-System-A"
  testSystemA
  putStrLn "User-A"
  testUserA
  putStrLn "Finished"

testA :: IO ()
testA = case decode S.traffic_8_1_A of
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
testB = case decode S.threat_8_1_A of
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

testTraffic_9_0_A :: IO ()
testTraffic_9_0_A = case decode S.traffic_9_0_A of
  Left err -> throwIO err
  Right (LogTraffic t) ->
    if | Traffic.deviceName t /= bytes "NY-PAN-FW-5" ->
           fail $
             "wrong device name:\nexpected: " ++
             show (bytes "NY-PAN-FW-5") ++
             "\nactually: " ++
             show (Traffic.deviceName t)
       | Traffic.actionSource t /= bytes "my-policy" ->
           fail $
             "wrong action source:\nexpected: " ++
             show (bytes "my-policy") ++
             "\nactually: " ++
             prettyBytes (Traffic.actionSource t)
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testPrismaTrafficA :: IO ()
testPrismaTrafficA = case decode S.traffic_prisma_A of
  Left err -> throwIO err
  Right (LogTraffic t) ->
    if | Traffic.deviceName t /= bytes "The-Device-Name" ->
           fail $
             "wrong device name:\nexpected: " ++
             show (bytes "NY-PAN-FW-5") ++
             "\nactually: " ++
             show (Traffic.deviceName t)
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testTrafficB :: IO ()
testTrafficB = case decode S.traffic_8_1_B of
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
testC = case decode S.threat_8_1_B of
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

testThreat_9_0_A :: IO ()
testThreat_9_0_A = case decode S.threat_9_0_A of
  Left err -> throwIO err
  Right (LogThreat t) ->
    if | Threat.miscellaneous t /= bytes "dt.adsafeprotected.com/" -> fail $
           "wrong miscellaneous (URL):\nExpected: dt.adsafeprotected.com/\nActually: " ++
           prettyBytes (Threat.miscellaneous t) ++ "\n"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testThreat_9_1_A :: IO ()
testThreat_9_1_A = case decode S.threat_9_1_A of
  Left err -> throwIO err
  Right (LogThreat t) ->
    if | Threat.miscellaneous t /= bytes "192.0.2.17_solarwinds_zero_configuration:5986/" -> fail $
           "wrong miscellaneous (URL):\nExpected: " ++
           "192.0.2.17_solarwinds_zero_configuration:5986/\nActually: " ++
           prettyBytes (Threat.miscellaneous t) ++ "\n"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testD :: IO ()
testD = case decode S.threat_8_1_C of
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

testThreatD :: IO ()
testThreatD = case decode S.threat_8_1_D of
  Left err -> throwIO err
  Right (LogThreat t) ->
    if | Threat.threatName t /= bytes "Email Link" -> fail $
           "wrong threat name:\nExpected: Email Link\nActually: " ++
           prettyBytes (Threat.threatName t) ++ "\n"
       | Threat.sender t /= bytes "From: \"John Doe\" <jdoe@example.com>" ->
           fail $ "wrong sender"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testThreatE :: IO ()
testThreatE = case decode S.threat_8_1_E of
  Left err -> throwIO err
  Right (LogThreat t) ->
    if | Threat.threatName t /= bytes "Windows Executable" -> fail $
           "wrong threat name:\nExpected: Windows Executable\nActually: " ++
           prettyBytes (Threat.threatName t) ++ "\n"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testThreatF :: IO ()
testThreatF = case decode S.threat_8_1_F of
  Left err -> throwIO err
  Right (LogThreat t) ->
    if | Threat.threatName t /= bytes "Temporary TMP File" ->
           fail "wrong threat name"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testThreatG :: IO ()
testThreatG = case decode S.threat_8_1_G of
  Left err -> throwIO err
  Right (LogThreat t) ->
    if | Threat.threatName t /= bytes "Hypertext Preprocessor PHP File" ->
           fail "wrong threat name"
       | Threat.httpHeaders t /= bytes "contextual.media.net/" ->
           fail "wrong http headers"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testThreatH :: IO ()
testThreatH = case decode S.threat_8_1_H of
  Left err -> throwIO err
  Right (LogThreat t) ->
    if | Threat.threatId t /= 9999 ->
           fail "wrong threat id"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testThreatI :: IO ()
testThreatI = case decode S.threat_8_1_I of
  Left err -> throwIO err
  Right (LogThreat t) ->
    if | Threat.threatId t /= 320511141 ->
           fail "wrong threat id"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testSystemA :: IO ()
testSystemA = case decode S.system_8_1_A of
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

testUserA :: IO ()
testUserA = case decode S.user_A of
  Left err -> throwIO err
  Right (LogUser t) ->
    if | User.subtype t /= bytes "login" -> fail $
           "wrong subtype name:\nexpected: login\nactually: " ++
           show (User.subtype t)
       | User.user t /= bytes "BIGDAWG10$@EXAMPLE.COM" -> fail "wrong user"
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
