{-# language TypeApplications #-}

module Sample
  ( traffic_8_1_A
  , threat_8_1_A
  , threat_8_1_B
  , threat_8_1_C
  ) where

import Data.Primitive (ByteArray)
import Data.Word (Word8)
import Data.Char (ord)
import qualified GHC.Exts as Exts

-- Sample Logs. If you add a sample log to this file, please
-- replace all information in the log that could possibly be
-- meaningful. At a bare minimum, this means:
--
-- * Replace any IP addresses with non-routable addresses 
--   from the TEST-NET-1 block (192.0.2.0/24).
-- * Replace any domain names with the reserved domain
--   name example.com.
-- * Replace any hostnames with something like MY-HOST
--   or NY-APP or SAMPLE-HOST.
-- * Replace rule names.

pack :: String -> ByteArray
pack = Exts.fromList . map (fromIntegral @Int @Word8 . ord)

-- Traffic Log 
traffic_8_1_A :: ByteArray
traffic_8_1_A = pack $ concat
  [ "<12> Jul 14 11:22:29 MY-HOST.example.com 1,2019/07/14 10:26:22,"
  , "003924147953,TRAFFIC,end,2057,2019/07/14 10:20:24,192.0.2.235,"
  , "192.0.2.251,0.0.0.0,0.0.0.0,Example-Rule-Name,,,incomplete,"
  , "vsys45,My-Source-Zone,My-Dest-Zone,eth-inbound.42,eth-outbound.43,"
  , "Example-Forwarding-Profile,2019/07/14 10:19:25,33651,1,59061,177,"
  , "0,0,0x19,tcp,deny,135,101,34,1,2019/07/14 10:18:15,0,my-category,"
  , "0,5384825641,0x8000000000000000,10.0.0.0-10.255.255.255,"
  , "10.0.0.0-10.255.255.255,0,1,0,policy-deny,174,0,0,0,MY-VSYS-NAME,"
  , "MY-DEVICE-NAME,from-policy,,,0,,0,,N/A,0,0,0,0"
  ]

-- Threat log for web browsing
threat_8_1_A :: ByteArray
threat_8_1_A = pack $ concat
  [ "<13> Jul 23 15:45:11 NY-APP-8.local 1,2019/07/23 15:45:11,"
  , "028191718331,THREAT,url,2056,2019/07/23 15:45:12,192.0.2.240,"
  , "192.0.2.243,192.0.2.54,192.0.2.13,MY-RULE-NAME,,,ssl,vsys79,"
  , "src-zone,dst-zone,eth3/2.7,eth6/4,Example-Forwarding-Policy,"
  , "2019/07/23 15:45:17,95963,2,59457,443,3984,443,0x400000,tcp,"
  , "alert,\"www.example.com/string/\"\"hello\"\"\",(9999),"
  , "the-category-name,informational,client-to-server,"
  , "97089310,0xa000000000000000,10.0.0.0-10.255.255.255,United States,"
  , "0,,0,,,0,,,,,,,,0,225,0,0,0,,NY-APP-8,,,,,0,,0,,N/A,unknown,"
  , "AppThreat-1-6,0x0,0,3176142484,"
  ]

-- Threat log for web browsing
threat_8_1_B :: ByteArray
threat_8_1_B = pack $ concat
  [ "<13> Jul 24 08:38:34 THE-FW-3.local 1,2019/07/24 08:38:34,"
  , "293471355489,THREAT,url,3179,2019/07/24 08:38:35,192.0.2.99,"
  , "192.0.2.57,192.0.2.53,192.0.2.11,MY-WEB-TRAFFIC-RULE,,,"
  , "web-browsing,vsys46,the-src-zone,the-dst-zone,ethernet13/6.721,"
  , "ethernet12/5,the-policy-name,2019/07/24 08:38:36,140720,1,39537,80,"
  , "55176,80,0x40b000,tcp,alert,\"www.example.com/\",(9999),"
  , "internet-communications-and-telephony,informational,client-to-server,"
  , "787958469,0xa000000000000000,10.0.0.0-10.255.255.255,United States,"
  , "0,text/html,0,,,107,"
  , "\"Mozilla/8.2 (Macintosh; Intel Mac OS X 10_19_7) AppleWebKit/943.87 "
  , "(KHTML, like Gecko) Chrome/95.17.6820.145 Safari/922.12\","
  , ",,,,,,"
  , "0,134,0,0,0,the-vsys-name,THE-FW-HOST,,,,get,0,,0,,N/A,unknown,"
  , "AppThreat-3-7,0x0,0,5323721019,"
  ]

-- Threat log for endpoint mapper detection
threat_8_1_C :: ByteArray
threat_8_1_C = pack $ concat
  [ "<14> Jul 24 12:12:23 THE-FW-4.local 1,2019/07/24 12:12:22,"
  , "012001011326,THREAT,vulnerability,2049,2019/07/24 12:12:35,"
  , "192.0.2.3,192.0.2.3,0.0.0.0,0.0.0.0,SOME-RULE,,,"
  , "msrpc-base,vsys413,my-src-zone,my-dst-zone,eth5/4.2,tunnel.2341,"
  , "Example-Forward-Policy,2019/07/24 12:12:39,60519,1,61242,142,0,"
  , "0,0x2000,tcp,alert,\"\",Microsoft RPC Endpoint Mapper Detection(30845),"
  , "any,informational,client-to-server,89814684,0xa000000000000000,"
  , "10.0.0.0-10.255.255.255,10.0.0.0-10.255.255.255,0,,0,,,0,,,,,,,,"
  , "0,225,0,0,0,,THE-FW-4-HOST,,,,,0,,0,,N/A,info-leak,AppThreat-8174-5569,"
  , "0x0,0,6279943187,"
  ]
