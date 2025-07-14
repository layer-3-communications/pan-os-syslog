{-# language TypeApplications #-}

module Sample
  ( correlation_A
  , traffic_8_1_A
  , traffic_8_1_B
  , traffic_9_0_A
  , traffic_prisma_A
  , traffic_ietf_A
  , threat_8_1_A
  , threat_8_1_B
  , threat_8_1_C
  , threat_8_1_D
  , threat_8_1_E
  , threat_8_1_F
  , threat_8_1_G
  , threat_8_1_H
  , threat_8_1_I
  , threat_9_0_A
  , threat_9_1_A
  , threat_9_1_B
  , threat_prisma_A
  , threat_prisma_B
  , threat_prisma_C
  , system_8_1_A
  , user_A
  ) where

import Data.Bytes (Bytes)
import Data.Word (Word8)
import Data.Char (ord)
import qualified Data.Bytes as Bytes
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

pack :: String -> Bytes
pack = Bytes.fromByteArray . Exts.fromList . map (fromIntegral @Int @Word8 . ord)

-- Traffic Log 
traffic_8_1_A :: Bytes
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

traffic_8_1_B :: Bytes
traffic_8_1_B = pack $ concat
  [ "<13> Nov 1 11:26:30 TX-PAN-FW-1.example.org 1,2019/10/01 11:29:30,001922410172,"
  , "TRAFFIC,end,2067,2019/11/01 11:26:30,192.0.2.165,192.0.2.100,"
  , "192.0.2.130,192.0.2.100,Some-Rule,example\\jdoe,,google-base,"
  , "vsys13,ORG-TX-Private,ORG-TX-Public,ethernet9/4.57,ethernet7/3,"
  , "Forward-Logs,2019/10/01 11:33:34,267134,1,59173,443,5532,443,0x400053,"
  , "tcp,allow,19421,2151,17270,39,2019/10/01 11:29:17,0,search-engines,0,"
  , "2176523185,0x8000000000000000,10.0.0.0-10.255.255.255,United States,0,"
  , "18,21,tcp-fin,134,0,0,0,Some-Name,TX-PAN-FW-1,my-policy,,,0,,0,,N/A,"
  , "0,0,0,0"
  ]

traffic_9_0_A :: Bytes
traffic_9_0_A = pack $ concat
  [ "<14> Mar 9 14:13:44 NY-PAN-FW-5.example.com 1,2020/03/09 14:13:44,"
  , "019624168632,TRAFFIC,end,2304,2020/03/09 14:13:44,192.0.2.73,"
  , "192.0.2.117,0.0.0.0,0.0.0.0,NEAR to FAR,,,insufficient-data,"
  , "vsys1,NEAR-ZONE,FAR-ZONE,tunnel.163,ethernet1/4,Forward-The-Logs,"
  , "2020/03/09 14:13:44,385404,1,56451,8475,0,0,0x401c,tcp,allow,1760,"
  , "1051,709,19,2020/03/09 14:13:24,16,any,0,6412095715,0x0,United States,"
  , "10.0.0.0-10.255.255.255,0,12,7,tcp-fin,11,0,0,0,,NY-PAN-FW-5,"
  , "my-policy,,,0,,0,,N/A,0,0,0,0,321ef4bf-801e-1c89-b341-efb2898ba2be,0"
  ]

-- This is PAN-OS 10.x.
traffic_prisma_A :: Bytes
traffic_prisma_A = pack $ concat
  [ "<14>1 2021-10-27T19:21:00.034Z stream-logfwd20-548106107-12876850-z5tm-harness-44k2 "
  , "logforwarder - panwlogs - 2021-10-27T19:20:59.000000Z,no-serial,TRAFFIC,"
  , "end,10.0,2021-10-27T19:20:40.000000Z,192.0.2.12,192.0.2.18,"
  , "192.0.2.112,192.0.2.118,INSIDE-TO-OUTSIDE,,,"
  , "web-browsing,vsys1,Zone-One,Zone-Two,tunnel.101,"
  , "ethernet1/1,Send-The-Logs,170172,1,42493,80,46254,80,tcp,"
  , "allow,892,818,74,12,2021-10-27T19:19:08.000000Z,1,low-risk,"
  , "9091497,10.0.0.0-10.255.255.255,JP,11,1,threat,28,31,0,0,,"
  , "The-Device-Name,from-policy,,,0,,0,"
  , "1970-01-01T00:00:00.000000Z,N/A,0,0,0,0,"
  , "89092ab0-606f-4c5a-b44c-c271420f3972,0,0,,,,,,,,,,,,,,,,,,,"
  , ",,,,,,,,,,,,,,,,2021-10-27T19:20:41.652000Z,,"
  ]

traffic_ietf_A :: Bytes
traffic_ietf_A = pack $ concat
  [ "<14>1 2025-07-14T09:50:36-04:00 the-hostname - - - -  1,2025/07/14 09:50:35,"
  , "025896414892,TRAFFIC,end,2562,2025/07/14 09:50:35,192.0.2.125,192.0.2.196,"
  , "192.0.2.66,192.0.2.2,Dev-Trust,,,ping,vsys1,Dev-Trust,Dev-Trust,ethernet1/4.13,"
  , "ethernet1/6,Global-Forward-Logs,2025/07/14 09:50:35,227554,1,0,0,0,0,0x500019,"
  , "icmp,allow,64,64,0,1,2025/07/14 09:50:25,0,any,,7470815214340870367,"
  , "0x8000000000000000,10.0.0.0-10.255.255.255,10.0.0.0-10.255.255.255,,1,0,"
  , "aged-out,241,173,0,0,,foo-bar,from-policy,,,0,,0,,N/A,0,0,0,0,"
  , "c7dc0e27-4795-4930-8ef8-541919a6ebcd,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
  , "2025-07-14T09:50:36.624-04:00,,,internet-utility,general-internet,"
  , "network-protocol,2,\"has-known-vulnerability,tunnel-other-application,pervasive-use\","
  , "untunneled,no,no,0"
  ]

-- Threat log for web browsing
threat_8_1_A :: Bytes
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
threat_8_1_B :: Bytes
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

-- Threat log for endpoint mapper detection, omitting syslog priority
-- from the header.
threat_8_1_C :: Bytes
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

-- Threat log for email
threat_8_1_D :: Bytes
threat_8_1_D = pack $ concat
  [ "<13>Nov  3 07:01:51 BIG-OL-PAN.example.com 1,2019/11/03 07:01:51,"
  , "008724449461,THREAT,file,2049,2019/11/03 07:01:51,192.0.2.105,"
  , "192.0.2.106,192.0.2.107,192.0.2.108,My-Email-Rule,,,smtp,vsys17,"
  , "MY-ZN,YOUR-ZN,ae2,ae13.5,Syslog,2019/11/03 07:01:51,206756,1,31532,"
  , "25,42813,25,0x406000,tcp,alert,\"\",Email Link(52143),any,low,"
  , "client-to-server,87562570,0xa000000000000000,United States,"
  , "United States,0,,0,,,1,,,,"
  , ",\"From: \"\"John Doe\"\" <jdoe@example.com>\",\"Sub: Hello, Worlds\","
  , "To: <foo@bar.org>;  ,0,11,0,0,0,,BIG-OL-PAN,,,,,0,,0,,N/A,unknown,"
  , "AppThreat-8194-5693,0x0,0,5382217271,"
  ]


-- Threat log for windows executable
threat_8_1_E :: Bytes
threat_8_1_E = pack $ concat
  [ "<13>Nov  3 07:28:05 bigbox.example.com 1,2019/11/03 07:28:04,"
  , "003942130261,THREAT,file,2049,2019/11/03 07:28:04,192.0.2.11,"
  , "192.0.2.12,0.0.0.0,0.0.0.0,Alpha-Rule,,,ms-ds-smbv2,vsys13,"
  , "Alpha-Zone,Beta-Zone,ae4.133,ae3,Syslog,2019/11/03 07:28:04,"
  , "187912,2,53181,445,0,0,0x6000,tcp,alert,\"SylinkDrop.exe\","
  , "Windows Executable (EXE)(52020),any,low,server-to-client,"
  , "96402817,0xa000000000000000,10.0.0.0-10.255.255.255,"
  , "10.0.0.0-10.255.255.255,0,,0,,,0,,,,,,,,0,11,0,0,0,,bigbox,"
  , ",,,,0,,0,,N/A,unknown,AppThreat-8217-3140,0x0,0,4794968105,"
  ]

-- Threat log for tmp file
threat_8_1_F :: Bytes
threat_8_1_F = pack $ concat
  [ "<13>Nov  3 07:37:10 fw-3.example.com 1,2019/11/03 07:37:09,001561170391,"
  , "THREAT,file,2049,2019/11/03 07:37:09,192.0.2.55,192.0.2.58,192.0.2.57,"
  , "192.0.2.56,Some-Rule,,,web-browsing,vsys51,ZONE-A,ZONE-B,ae5.67,ae8,"
  , "Syslog,2019/11/03 07:37:09,48536,2,49619,80,24617,80,0x406000,tcp,"
  , "alert,\"temp.tmp\",Temporary TMP File(52228),computer-and-internet-info,"
  , "low,server-to-client,78561201,0xa000000000000000,10.0.0.0-10.255.255.255,"
  , "United States,0,,0,,,1,,,,,,,,0,11,0,0,0,,fw-3,"
  , "download.garmin.com/garmindlm/temp.tmp,,,,0,,0,,N/A,unknown,"
  , "AppThreat-9311-6102,0x0,0,2694915680,"
  , "download.garmin.com/garmindlm/temp.tmp"
  ]

-- Threat log for PHP file
threat_8_1_G :: Bytes
threat_8_1_G = pack $ concat
  [ "<13>Nov  7 13:44:45 fw-4.example.com 1,2019/11/07 13:44:44,012301030273,"
  , "THREAT,file,2049,2019/11/07 13:44:44,192.0.2.3,192.0.2.4,192.0.2.5,"
  , "192.0.2.6,My-Rule,example\\jdoe,,web-browsing,vsys34,A-Zone,B-Zone,"
  , "ethernet1/1.201,ethernet1/6,Forward-Logs,2019/11/07 13:44:44,257969,"
  , "6,57863,80,29036,80,0x402000,tcp,alert,\"checksync.php\","
  , "Hypertext Preprocessor PHP File(52256),web-advertisements,low,"
  , "server-to-client,241048149,0xa000000000000000,10.0.0.0-10.255.255.255,"
  , "United States,0,,0,,,2,,,,,,,,0,134,0,0,0,Staging,fw-4,\"contextual."
  , "media.net/checksync.php?&vsSync=1&cs=1&hb=1&cv=37&ndec=1&cid=8HBJW752U"
  , "&prvid=41,108,141,181,192,3007,3008&refUrl=http://www.msn.com&"
  , "rtime=4\",,,,0,,0,,N/A,unknown,AppThreat-8307-9861,0x0,0,"
  , "4294967295,\"contextual.media.net/\""
  ]

-- URL threat log. Regression test. Also, the serial number in this
-- log has non-numeric characters.
threat_8_1_H :: Bytes
threat_8_1_H = pack $ concat
  [ "<14>Dec 10 19:11:09 fw-4.example.com 1,2019/12/10 19:11:08,002926C74589,"
  , "THREAT,url,2049,2019/12/10 19:11:08,192.0.2.123,192.0.2.125,192.0.2.126,"
  , "192.0.2.127,Some-Rule,example\\mbjordan,,web-browsing,vsys1,"
  , "X-Zone,Y-Zone,ethernet2/4.234,ethernet6/7,Forward-Logs,"
  , "2019/12/10 19:11:08,241982,1,59055,80,2039,80,0x403000,tcp,"
  , "alert,\"i.nflcdn.com/static/site/7.5/img/fonts/endzone-sans/"
  , "medium-cond.woff\",(9999),content-delivery-networks,informational,"
  , "client-to-server,257316637,0xa000000000000000,10.0.0.0-10.255.255.255,"
  , "United States,0,,0,,,1,\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
  , "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/"
  , "537.36\",,,\"http://combine.nflcdn.com/yui/min2/index.php?7.5"
  , "hotfix-7.5.146&b=yui3%2Fstatic%2F7.5%2Fscripts%2Fmodules&f=font-"
  , "endzonesans-condmedium/font-endzonesans-condmedium.css,font-"
  , "endzoneslab-medium/font-endzoneslab-medium.css,font-endzoneslab-"
  , "bold/font-endzoneslab-bold.css,font-endzonetech-medium/font-"
  , "endzonetech-medium.css,font-endzonetech-bold/font-endzonetech-"
  , "bold.css,font-endzonesans-bold/font-endzonesans-bold.css\",,,,"
  , "0,134,0,0,0,Production,GA-PA-FW-1,,,,get,0,,0,,N/A,unknown,"
  , "AppThreat-0-0,0x0,0,4380241866,"
  ]

-- Spyware threat log.
threat_8_1_I :: Bytes
threat_8_1_I = pack $ concat
  [ "<12>Jan 10 01:56:39 NY-PA-FW-1.example 1,2020/01/10 01:56:38,"
  , "012862319694,THREAT,spyware,2049,2020/01/10 01:56:38,192.0.2.15,"
  , "192.0.2.30,192.0.2.31,192.0.2.32,Some-Rule,,,dns,vsys1,Src-Zone,"
  , "Dst-Zone,ethernet1/9.255,ethernet1/1,Forward-Logs,"
  , "2020/01/10 01:56:38,146414,1,45476,53,15021,53,0x80402000,udp,"
  , "sinkhole,\"\",Suspicious DNS Query (generic:comparetvs.net)(320511141),"
  , "any,medium,client-to-server,267287993,0xa000000000000000,"
  , "10.0.0.0-10.255.255.255,United States,0,,1315498975425810792,,,"
  , "0,,,,,,,,0,134,0,0,0,Production,GA-PA-FW-1,,,,,0,,0,,N/A,dns,"
  , "AppThreat-3218-3729,0x0,0,4294967295,"
  ]

-- Web browsing threat log from PAN-OS 9.0
threat_9_0_A :: Bytes
threat_9_0_A = pack $ concat
  [ "Mar 9 14:47:44 firewall1.example.com 1,2020/03/09 14:47:44,001701012545,"
  , "THREAT,url,2304,2020/03/09 14:47:44,192.0.2.101,192.0.2.102,"
  , "192.0.2.103,192.0.2.104,FOO to BAR,example\\jdoe,,ssl,vsys1,FOO,BAR,"
  , "ethernet1/6,ethernet1/7,My-Log-Forwarding,2020/03/09 14:47:44,455102,"
  , "1,62475,443,31963,443,0x40f000,tcp,alert,\"dt.adsafeprotected.com/\","
  , "(9999),web-advertisements,informational,client-to-server,2314781488,"
  , "0x2000000000000000,United States,United States,0,,0,,,0,,,,,,,,0,11,"
  , "0,0,0,,firewall1,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,"
  , ",\"web-advertisements,low-risk\",edd29e10-d927-1753-867f-0108b01b80de,0"
  ]

threat_prisma_A :: Bytes
threat_prisma_A = pack $ concat
  [ "<14>1 2021-10-28T02:58:53.586Z stream-foobar-baz logforwarder - "
  , "panwlogs - 2021-10-28T02:58:52.000000Z,no-serial,THREAT,url,"
  , "10.0,2021-10-28T02:58:50.000000Z,192.0.2.99,190.0.2.100,192.0.2.101,"
  , "192.0.2.102,IN-TO-OUT,,,google-play,vsys1,trust,untrust,tunnel.105,"
  , "ethernet1/1,The-Forward,28182,1,59580,443,3502,443,tcp,block-url,"
  , "play.google.com/,shopping,Informational,client to server,2719193,"
  , "10.0.0.0-10.255.255.255,US,,0,0,,,,28,31,0,0,,big-ol-device,,,"
  , "unknown,0,,0,1970-01-01T00:00:00.000000Z,N/A,unknown,0,0,,"
  , "\"shopping,low-risk\",89ea2a40-656e-4c5a-b44c-c27b52de3982,0,"
  , ",,,,,,,,,,,,,,,,,,,,,,,,,,,2021-10-28T02:58:50.719000Z,"
  ]

threat_prisma_B :: Bytes
threat_prisma_B = pack $ concat
  [ "<14>1 2021-11-01T15:14:08.069Z stream-logfwd-xyz logforwarder - panwlogs "
  , "- 2021-11-01T15:14:06.000000Z,no-serial,THREAT,spyware,10.0,"
  , "2021-11-01T15:13:56.000000Z,192.0.2.20,8.8.8.8,192.0.2.111,8.8.8.8,"
  , "in-to-out-dns,domain\\exampleuser,,dns,vsys1,ZoneA,ZoneB,tunnel.101,"
  , "ethernet1/1,My-Forwarding,1355037,1,55517,53,45783,53,udp,drop,"
  , "example.com,Phishing:example.com(109010001),Low,client-to-server,"
  , "12088427,10.0.0.0-10.255.255.255,US,1152921504606899096,,,0,,,,,0,"
  , "28,31,0,0,,Big-Firewall,,,0,,0,1970-01-01T00:00:00.000000Z,N/A,"
  , "dns-phishing,0,0x0,ceb0229f-7a4a-5c62-8960-f66b27e2e01e,0,"
  , ",,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2021-11-01T15:13:57.399000Z,"
  ]

threat_prisma_C :: Bytes
threat_prisma_C = pack $ concat
  [ "<14>1 2021-11-02T00:53:49.421Z stream-logfwd-xyz logforwarder - panwlogs "
  , "- 2021-11-02T00:53:48.000000Z,no-serial,THREAT,wildfire,10.0,"
  , "2021-11-02T00:53:37.000000Z,192.0.2.20,192.0.2.21,192.0.2.22,192.0.2.23,"
  , "in-to-out,foo\\bar,,office365-enterprise-access,vsys1,trust,"
  , "untrust,tunnel.101,ethernet1/1,My-Forwarding,1294093,1,"
  , "64810,443,32485,443,tcp,allow,Exchange.asmx,"
  , "Adobe Portable Document Format (PDF)(52021),Informational,"
  , "server to client,13548583,10.0.0.0-10.255.255.255,US,0,"
  , "85dde742f22216725f0ff6b172ca68f4f30f02029f08b3079cec34da804db793,"
  , "wildfire.paloaltonetworks.com,69,pdf,,,,47136308381,28,31,0,0,,"
  , "Big-Firewall,,,0,,0,1970-01-01T00:00:00.000000Z,"
  , "N/A,unknown,0,0x0,f0ebabfb-ef45-451a-89a5-30f87238d62b,"
  , "0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2021-11-02T00:53:37.797000Z,"
  ]


-- This is a log from a firewall whose license had expired.
threat_9_1_A :: Bytes
threat_9_1_A = pack $ concat
  [ "<14>Mar  2 11:30:47 MY-PA-5250-3 1,2021/03/02 11:30:47,012911492893,"
  , "THREAT,url,2305,2021/03/02 11:30:47,192.0.2.22,192.0.2.17,0.0.0.0,"
  , "0.0.0.0,rule99,foo\\_bar,,ssl,vsys1,MY-trust,MY-dmz,ethernet1/1,"
  , "ethernet1/2,My-Log-Forwarding,2021/03/02 11:30:47,38578210,1,63421,"
  , "5986,0,0,0x10b000,tcp,allow,\"192.0.2.17_solarwinds_zero_configuration:5986/\","
  , "(9999),license-expired,informational,client-to-server,4901795984744840635,"
  , "0xa000000000000000,10.0.0.0-10.255.255.255,10.0.0.0-10.255.255.255,0,,0,,,0,"
  , ",,,,,,,0,56,0,0,0,,MY-PA-5250-1,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,"
  , "4196987195,,\"license-expired\",9871ab80-6061-4f07-a06e-0036b0206f73,0,"
  ]

-- System log (IKE delete)
system_8_1_A :: Bytes
system_8_1_A = pack $ concat
  [ "<14>Nov  9 19:53:08 NY-DC-FW-2.example.com 1,2019/10/06 15:46:26,"
  , "009732949126,SYSTEM,vpn,0,2019/10/19 15:39:29,,ike-send-p2-delete,"
  , "To-FOO-BAR-NET,0,0,general,informational,\"IKE protocol IPSec SA "
  , "delete message sent to peer. SPI:0xA1CD910F.\",18249042,"
  , "0x8000000000000000,0,0,0,0,,NY-DC-FW-2"
  ]

-- User ID log (login)
user_A :: Bytes
user_A = pack $ concat
  [ "1,2021/09/19 11:55:38,013201027000,USERID,login,2305,2021/09/19 11:55:38,"
  , "vsys1,192.0.2.112,BIGDAWG10$@EXAMPLE.COM,server.example.com,0,1,2700,0,0,"
  , "active-directory,,6991364276409747475,0x0,92,0,0,0,,MY-PA5220-A,1,,"
  , "2021/09/19 11:55:25,1,0x0,BIGDAWG10$@EXAMPLE.COM"
  ]

-- Correlation log
correlation_A :: Bytes
correlation_A = pack $ concat
  [ "<14>Mar 7 14:43:42 panorama.example.com 1,2022/03/07 14:43:17,013201019829,"
  , "CORRELATION,,,2022/03/07 14:43:17,192.0.2.75,,,compromised-host,medium,"
  , "146,0,0,0,,panorama,1869504768,Beacon Detection,6005,Host visited known "
  , "malware URL (11 times)."
  ]

-- Threat log
threat_9_1_B :: Bytes
threat_9_1_B = pack $ concat
  [ "<14>Jul 25 09:39:39 Panorama 1,2022/07/25 09:39:39,012801204178,"
  , "THREAT,url,2560,2022/07/25 09:40:03,192.0.2.254,192.0.2.201,"
  , "192.0.2.13,192.0.2.12,trust-to-untrust-allow-any,,,ssl,vsys1,"
  , "ABC-trust,ABC-untrust,ethernet1/2.14,ethernet1/3,"
  , "Forward_To_Panorama,2022/07/25 09:40:03,31669,1,53686,443,15492,"
  , "443,0x403400,tcp,block-url,\"t.co/\",(9999),social-networking,"
  , "informational,client-to-server,30720475,0xa000000000000000,"
  , "10.0.0.0-10.255.255.255,United States,,,0,,,0,,,,,,,,0,15,0,0,0,"
  , ",NYC-ABC-PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,"
  , "4294967295,,\"social-networking,low-risk\","
  , "a40f8ec5-109d-4dc5-b09d-33b848f5bd09,0,,0.0.0.0,"
  , ",,,,,,,,,,,,,,,,,,,,,,,,,,0,2022-07-25T09:40:03.909-04:00,"
  , ",,,encrypted-tunnel,networking,browser-based,"
  , "4,\"used-by-malware,able-to-transfer-file,"
  , "has-known-vulnerability,tunnel-other-application,pervasive-use\","
  , ",ssl,no,no"
  ]
