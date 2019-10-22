{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language DuplicateRecordFields #-}
{-# language NumericUnderscores #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}

module Panos.Syslog.Traffic
  ( action
  , application
  , bytes
  , bytesReceived
  , bytesSent
  , destinationAddress
  , destinationPort
  , destinationUser
  , deviceGroupHierarchyLevel1
  , deviceGroupHierarchyLevel2
  , deviceGroupHierarchyLevel3
  , deviceGroupHierarchyLevel4
  , deviceName
  , elapsedTime
  , inboundInterface
  , ipProtocol
  , logAction
  , natDestinationIp
  , natDestinationPort
  , natSourceIp
  , natSourcePort
  , outboundInterface
  , packets
  , packetsReceived
  , packetsSent
  , ruleName
  , sequenceNumber
  , serialNumber
  , sourceAddress
  , sourcePort
  , sourceUser
  , subtype
  , syslogHost
  ) where

import Data.Bytes.Types (Bytes(..))
import Panos.Syslog.Unsafe (Traffic(Traffic),Bounds(Bounds))
import Data.Word (Word64,Word16)
import Net.Types (IP)
import qualified Panos.Syslog.Unsafe as U

ipProtocol :: Traffic -> Bytes
ipProtocol (Traffic{ipProtocol=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

syslogHost :: Traffic -> Bytes
syslogHost (Traffic{syslogHost=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

subtype :: Traffic -> Bytes
subtype (Traffic{subtype=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

ruleName :: Traffic -> Bytes
ruleName (Traffic{ruleName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

inboundInterface :: Traffic -> Bytes
inboundInterface (Traffic{inboundInterface=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

outboundInterface :: Traffic -> Bytes
outboundInterface (Traffic{outboundInterface=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

logAction :: Traffic -> Bytes
logAction (Traffic{logAction=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

action :: Traffic -> Bytes
action (Traffic{action=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

application :: Traffic -> Bytes
application (Traffic{application=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

deviceName :: Traffic -> Bytes
deviceName (Traffic{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

elapsedTime :: Traffic -> Word64
elapsedTime = U.elapsedTime

sourceUser :: Traffic -> Bytes
sourceUser (Traffic{sourceUser=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

destinationUser :: Traffic -> Bytes
destinationUser (Traffic{destinationUser=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

packetsReceived :: Traffic -> Word64
packetsReceived = U.packetsReceived

packetsSent :: Traffic -> Word64
packetsSent = U.packetsSent

sourcePort :: Traffic -> Word16
sourcePort = U.sourcePort

sequenceNumber :: Traffic -> Word64
sequenceNumber = U.sequenceNumber

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

serialNumber :: Traffic -> Word64
serialNumber = U.serialNumber

deviceGroupHierarchyLevel1 :: Traffic -> Word64
deviceGroupHierarchyLevel1 = U.deviceGroupHierarchyLevel1

deviceGroupHierarchyLevel2 :: Traffic -> Word64
deviceGroupHierarchyLevel2 = U.deviceGroupHierarchyLevel2

deviceGroupHierarchyLevel3 :: Traffic -> Word64
deviceGroupHierarchyLevel3 = U.deviceGroupHierarchyLevel3

deviceGroupHierarchyLevel4 :: Traffic -> Word64
deviceGroupHierarchyLevel4 = U.deviceGroupHierarchyLevel4

