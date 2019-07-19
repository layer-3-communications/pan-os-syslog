{-# language TypeApplications #-}

module Sample
  ( traffic_8_1_A
  ) where

import Data.Primitive (ByteArray)
import Data.Word (Word8)
import Data.Char (ord)
import qualified GHC.Exts as Exts

pack :: String -> ByteArray
pack = Exts.fromList . map (fromIntegral @Int @Word8 . ord)

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
