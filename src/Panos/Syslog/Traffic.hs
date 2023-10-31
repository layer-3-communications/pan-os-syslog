{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language DuplicateRecordFields #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
{-# language OverloadedRecordDot #-}

-- | Fields for traffic logs.
module Panos.Syslog.Traffic
  ( -- * Fields
    action
  , actionSource
  , application
  , bytes
  , bytesReceived
  , bytesSent
  , destinationAddress
  , destinationCountry
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
  , repeatCount
  , ruleName
  , ruleUuid
  , sequenceNumber
  , serialNumber
  , sessionEndReason
  , sessionId
  , sourceAddress
  , sourceCountry
  , sourcePort
  , sourceUser
  , sourceZone
  , subtype
  , syslogHost
  , timeGenerated
  , virtualSystem
  , virtualSystemName
  -- * Device Group Hierarchy
  , deviceGroupHierarchyLevel1
  , deviceGroupHierarchyLevel2
  , deviceGroupHierarchyLevel3
  , deviceGroupHierarchyLevel4
  ) where

import Chronos (Datetime)
import Data.Bytes.Types (Bytes(..))
import Panos.Syslog.Unsafe (Traffic(Traffic),Bounds(Bounds))
import Data.Word (Word64,Word16)
import Net.Types (IP)
import Data.WideWord (Word128)
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

-- | Specifies whether the action taken to allow or block an
-- application was defined in the application or in policy. The
-- actions can be @allow@, @deny@, @drop@, @reset-server@, @reset-client@
-- or @reset-both@ for the session.
actionSource :: Traffic -> Bytes
actionSource (Traffic{actionSource=Bounds off len,message=msg}) =
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
{-# inline sourcePort #-}
sourcePort u = u.sourcePort

-- | Time the log was generated on the dataplane.
timeGenerated :: Traffic -> Datetime
{-# inline timeGenerated #-}
timeGenerated u = u.timeGenerated

-- | A 64-bit log entry identifier incremented sequentially;
-- each log type has a unique number space.
sequenceNumber :: Traffic -> Word64
{-# inline sequenceNumber #-}
sequenceNumber u = u.sequenceNumber

-- | Post-NAT source port.
natSourcePort :: Traffic -> Word16
{-# inline natSourcePort #-}
natSourcePort u = u.natSourcePort

-- | The UUID that permanently identifies the rule.
ruleUuid :: Traffic -> Word128
{-# inline ruleUuid #-}
ruleUuid u = u.ruleUuid

-- | Destination port utilized by the session.
destinationPort :: Traffic -> Word16
{-# inline destinationPort #-}
destinationPort u = u.destinationPort

-- | Post-NAT destination port.
natDestinationPort :: Traffic -> Word16
{-# inline natDestinationPort #-}
natDestinationPort u = u.natDestinationPort

-- | If Source NAT performed, the post-NAT Source IP address.
natSourceIp :: Traffic -> IP
{-# inline natSourceIp #-}
natSourceIp u = u.natSourceIp

-- | If Destination NAT performed, the post-NAT Destination IP address.
natDestinationIp :: Traffic -> IP
{-# inline natDestinationIp #-}
natDestinationIp u = u.natDestinationIp

-- | Original session source IP address.
sourceAddress :: Traffic -> IP
{-# inline sourceAddress #-}
sourceAddress u = u.sourceAddress

-- | Original session destination IP address.
destinationAddress :: Traffic -> IP
{-# inline destinationAddress #-}
destinationAddress u = u.destinationAddress

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

-- | Number of total bytes (transmit and receive) for the session.
repeatCount :: Traffic -> Word64
{-# inline repeatCount #-}
repeatCount u = u.repeatCount

-- | Serial number of the firewall that generated the log. These
-- occassionally contain non-numeric characters, so do not attempt
-- to parse this as a decimal number.
serialNumber :: Traffic -> Bytes
serialNumber (Traffic{serialNumber=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

deviceGroupHierarchyLevel1 :: Traffic -> Word64
{-# inline deviceGroupHierarchyLevel1 #-}
deviceGroupHierarchyLevel1 u = u.deviceGroupHierarchyLevel1

deviceGroupHierarchyLevel2 :: Traffic -> Word64
{-# inline deviceGroupHierarchyLevel2 #-}
deviceGroupHierarchyLevel2 u = u.deviceGroupHierarchyLevel2

deviceGroupHierarchyLevel3 :: Traffic -> Word64
{-# inline deviceGroupHierarchyLevel3 #-}
deviceGroupHierarchyLevel3 u = u.deviceGroupHierarchyLevel3

deviceGroupHierarchyLevel4 :: Traffic -> Word64
{-# inline deviceGroupHierarchyLevel4 #-}
deviceGroupHierarchyLevel4 u = u.deviceGroupHierarchyLevel4

-- | The reason a session terminated.
sessionEndReason :: Traffic -> Bytes
sessionEndReason (Traffic{sessionEndReason=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

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

-- | Source country or Internal region for private addresses;
-- maximum length is 32 bytes.
sourceCountry :: Traffic -> Bytes
sourceCountry (Traffic{sourceCountry=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Destination country or Internal region for private addresses.
-- Maximum length is 32 bytes.
destinationCountry :: Traffic -> Bytes
destinationCountry (Traffic{destinationCountry=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | An internal numerical identifier applied to each session.
sessionId :: Traffic -> Word64
{-# inline sessionId #-}
sessionId u = u.sessionId
