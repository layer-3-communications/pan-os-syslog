{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language DuplicateRecordFields #-}
{-# language NumericUnderscores #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}

module Panos.Syslog.Traffic
  ( -- * Fields
    action
  , application
  , bytes
  , bytesReceived
  , bytesSent
  , destinationAddress
  , destinationPort
  , destinationUser
  , destinationZone
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
  , sourceZone
  , subtype
  , syslogHost
  , virtualSystem
  , virtualSystemName
  -- * Device Group Hierarchy
  , deviceGroupHierarchyLevel1
  , deviceGroupHierarchyLevel2
  , deviceGroupHierarchyLevel3
  , deviceGroupHierarchyLevel4
  ) where

import Data.Bytes.Types (Bytes(..))
import Panos.Syslog.Unsafe (Traffic(Traffic),Bounds(Bounds))
import Data.Word (Word64,Word16)
import Net.Types (IP)
import qualified Panos.Syslog.Unsafe as U

-- | IP protocol associated with the session.
ipProtocol :: Traffic -> Bytes
ipProtocol (Traffic{ipProtocol=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | The hostname from the syslog header appended to the PAN-OS log.
-- This field is not documented by Palo Alto Network and technically
-- is not part of the log, but in practice, it is always present.
-- This is similar to @deviceName@.
syslogHost :: Traffic -> Bytes
syslogHost (Traffic{syslogHost=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Subtype of traffic log; values are @start@, @end@, @drop@, and @deny@.
--
-- * Start: session started
-- * End: session ended
-- * Drop: session dropped before the application is identified and
--   there is no rule that allows the session.
-- * Deny: session dropped after the application is identified and
--   there is a rule to block or no rule that allows the session.
subtype :: Traffic -> Bytes
subtype (Traffic{subtype=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Name of the rule that the session matched.
ruleName :: Traffic -> Bytes
ruleName (Traffic{ruleName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Interface that the session was sourced from.
inboundInterface :: Traffic -> Bytes
inboundInterface (Traffic{inboundInterface=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Interface that the session was destined to.
outboundInterface :: Traffic -> Bytes
outboundInterface (Traffic{outboundInterface=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Log Forwarding Profile that was applied to the session.
logAction :: Traffic -> Bytes
logAction (Traffic{logAction=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Action taken for the session; possible values are:
--
-- * allow: session was allowed by policy
-- * deny: session was denied by policy
-- * drop: session was dropped silently
-- * drop ICMP: session was silently dropped with an ICMP unreachable
--   message to the host or application
-- * reset both: session was terminated and a TCP reset is sent to
--   both the sides of the connection
-- * reset client: session was terminated and a TCP reset is sent to the client
-- * reset server: session was terminated and a TCP reset is sent to the server
action :: Traffic -> Bytes
action (Traffic{action=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Application associated with the session.
application :: Traffic -> Bytes
application (Traffic{application=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | The hostname of the firewall on which the session was logged.
deviceName :: Traffic -> Bytes
deviceName (Traffic{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Elapsed time of the session.
elapsedTime :: Traffic -> Word64
elapsedTime = U.elapsedTime

-- | Username of the user who initiated the session.
sourceUser :: Traffic -> Bytes
sourceUser (Traffic{sourceUser=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Username of the user to which the session was destined.
destinationUser :: Traffic -> Bytes
destinationUser (Traffic{destinationUser=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Number of server-to-client packets for the session.
packetsReceived :: Traffic -> Word64
packetsReceived = U.packetsReceived

-- | Number of client-to-server packets for the session.
packetsSent :: Traffic -> Word64
packetsSent = U.packetsSent

-- | Source port utilized by the session.
sourcePort :: Traffic -> Word16
sourcePort = U.sourcePort

-- | A 64-bit log entry identifier incremented sequentially;
-- each log type has a unique number space.
sequenceNumber :: Traffic -> Word64
sequenceNumber = U.sequenceNumber

-- | Post-NAT source port.
natSourcePort :: Traffic -> Word16
natSourcePort = U.natSourcePort

-- | Destination port utilized by the session.
destinationPort :: Traffic -> Word16
destinationPort = U.destinationPort

-- | Post-NAT destination port.
natDestinationPort :: Traffic -> Word16
natDestinationPort = U.natDestinationPort

-- | If Source NAT performed, the post-NAT Source IP address.
natSourceIp :: Traffic -> IP
natSourceIp = U.natSourceIp

-- | If Destination NAT performed, the post-NAT Destination IP address.
natDestinationIp :: Traffic -> IP
natDestinationIp = U.natDestinationIp

-- | Original session source IP address.
sourceAddress :: Traffic -> IP
sourceAddress = U.sourceAddress

-- | Original session destination IP address.
destinationAddress :: Traffic -> IP
destinationAddress = U.destinationAddress

-- | Number of total packets (transmit and receive) for the session.
packets :: Traffic -> Word64
packets = U.packets

-- | Number of bytes in the server-to-client direction of the session.
bytesReceived :: Traffic -> Word64
bytesReceived = U.bytesReceived

-- | Number of bytes in the client-to-server direction of the session.
bytesSent :: Traffic -> Word64
bytesSent = U.bytesSent

-- | Number of total bytes (transmit and receive) for the session.
bytes :: Traffic -> Word64
bytes = U.bytes

-- | Serial number of the firewall that generated the log.
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

-- | Virtual System associated with the session.
virtualSystem :: Traffic -> Bytes
virtualSystem (Traffic{virtualSystem=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | The name of the virtual system associated with the session; only valid
-- on firewalls enabled for multiple virtual systems.
virtualSystemName :: Traffic -> Bytes
virtualSystemName (Traffic{virtualSystemName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Zone the session was sourced from.
sourceZone :: Traffic -> Bytes
sourceZone (Traffic{sourceZone=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Zone the session was destined to.
destinationZone :: Traffic -> Bytes
destinationZone (Traffic{destinationZone=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}
