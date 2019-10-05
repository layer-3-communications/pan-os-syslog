{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language DuplicateRecordFields #-}
{-# language NumericUnderscores #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}

module Panos.Syslog.Traffic
  ( bytes
  , bytesReceived
  , bytesSent
  , deviceName
  , packets
  , packetsReceived
  , packetsSent
  , sourceUser
  , destinationUser
  , sourcePort
  , destinationPort
  , natSourcePort
  , natDestinationPort
  , natSourceIp
  , natDestinationIp
  , sourceAddress
  , destinationAddress
  ) where

import Data.Bytes.Types (Bytes(..))
import Panos.Syslog.Unsafe (Traffic(Traffic),Bounds(Bounds))
import Data.Word (Word64,Word16)
import Net.Types (IP)
import qualified Panos.Syslog.Unsafe as U

deviceName :: Traffic -> Bytes
deviceName (Traffic{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

sourceUser :: Traffic -> Bytes
sourceUser (Traffic{sourceUser=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

destinationUser :: Traffic -> Bytes
destinationUser (Traffic{destinationUser=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

packetsReceived :: Traffic -> Word64
packetsReceived = U.packetsReceived

packetsSent :: Traffic -> Word64
packetsSent = U.packetsSent

sourcePort :: Traffic -> Word16
sourcePort = U.sourcePort

natSourcePort :: Traffic -> Word16
natSourcePort = U.natSourcePort

destinationPort :: Traffic -> Word16
destinationPort = U.destinationPort

natDestinationPort :: Traffic -> Word16
natDestinationPort = U.natDestinationPort

natSourceIp :: Traffic -> IP
natSourceIp = U.natSourceIp

natDestinationIp :: Traffic -> IP
natDestinationIp = U.natDestinationIp

sourceAddress :: Traffic -> IP
sourceAddress = U.sourceAddress

destinationAddress :: Traffic -> IP
destinationAddress = U.destinationAddress

packets :: Traffic -> Word64
packets = U.packets

bytesReceived :: Traffic -> Word64
bytesReceived = U.bytesReceived

bytesSent :: Traffic -> Word64
bytesSent = U.bytesSent

bytes :: Traffic -> Word64
bytes = U.bytes

