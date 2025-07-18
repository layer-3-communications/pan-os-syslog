{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language DuplicateRecordFields #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
{-# language OverloadedRecordDot #-}

-- | Fields for threat logs.
module Panos.Syslog.Threat
  ( action
  , application
  , category
  , contentVersion
  , destinationAddress
  , destinationCountry
  , destinationPort
  , destinationUser
  , destinationZone
  , deviceName
  , fileDigest
  , httpHeaders
  , httpMethod
  , inboundInterface
  , ipProtocol
  , miscellaneous
  , natDestinationIp
  , natDestinationPort
  , natSourceIp
  , natSourcePort
  , outboundInterface
  , recipient
  , referer
  , repeatCount
  , ruleName
  , sender
  , sequenceNumber
  , serialNumber
  , sessionId
  , severity
  , sourceAddress
  , sourceCountry
  , sourcePort
  , sourceUser
  , sourceZone
  , subject
  , subtype
  , threatCategory
  , threatId
  , threatName
  , timeGenerated
  , urlCategoryList
  , virtualSystemName
  ) where

import Data.Bytes.Types (Bytes(..))
import Panos.Syslog.Internal.Common (Bounds(Bounds))
import Panos.Syslog.Internal.Threat (Threat(Threat))
import Data.Word (Word64,Word16)
import Chronos (Datetime)
import Net.Types (IP)

import qualified Data.Bytes as Bytes
import qualified Panos.Syslog.Internal.Threat as U

-- | Subtype of threat log. Values include: @data@, @file@, @flood@,
-- @packet@, @scan@, @spyware@, @url@, @virus@, @vulnerability@,
-- @wildfire@, @wildfire-virus@.
subtype :: Threat -> Bytes
subtype (Threat{subtype=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | Username of the user who initiated the session.
sourceUser :: Threat -> Bytes
sourceUser (Threat{sourceUser=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | Username of the user to which the session was destined.
destinationUser :: Threat -> Bytes
destinationUser (Threat{destinationUser=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | Interface that the session was sourced from.
inboundInterface :: Threat -> Bytes
inboundInterface (Threat{inboundInterface=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | Interface that the session was destined to.
outboundInterface :: Threat -> Bytes
outboundInterface (Threat{outboundInterface=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | Zone the session was sourced from.
sourceZone :: Threat -> Bytes
sourceZone (Threat{sourceZone=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | Zone the session was destined to.
destinationZone :: Threat -> Bytes
destinationZone (Threat{destinationZone=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | The hostname of the firewall on which the session was logged.
deviceName :: Threat -> Bytes
deviceName (Threat{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | The file digest string shows the binary hash of the file sent
-- to be analyzed by the WildFire service.
--
-- This is sometimes MD5 and sometimes SHA256. Rather than attempting
-- to decode it, it is just left as bytes.
fileDigest :: Threat -> Bytes
fileDigest (Threat{fileDigest=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | Palo Alto Networks identifier for the threat. It is a description
-- string followed by a 64-bit numerical identifier in parentheses for
-- some subtypes.
--
-- This field is just the description string. The numerical identifier
-- goes can be accessed with 'threatId'.
threatName :: Threat -> Bytes
threatName (Threat{threatName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | The numerical identifier for a threat. See 'threatName'.
threatId :: Threat -> Word64
threatId = U.threatId

-- | Time the log was generated on the dataplane.
timeGenerated :: Threat -> Datetime
{-# inline timeGenerated #-}
timeGenerated u = u.timeGenerated

-- | For URL Subtype, it is the URL Category; For WildFire subtype,
-- it is the verdict on the file and is either @malicious@, @grayware@,
-- or @benign@; For other subtypes, the value is @any@.
category :: Threat -> Bytes
category (Threat{category=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

contentVersion :: Threat -> Bytes
contentVersion (Threat{contentVersion=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | The name of the virtual system associated with the session;
-- only valid on firewalls enabled for multiple virtual systems.
virtualSystemName :: Threat -> Bytes
virtualSystemName (Threat{virtualSystemName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

threatCategory :: Threat -> Bytes
threatCategory (Threat{threatCategory=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

httpHeaders :: Threat -> Bytes
httpHeaders = U.httpHeaders

miscellaneous :: Threat -> Bytes
miscellaneous (Threat{miscellaneousBounds=Bounds off len,miscellaneousByteArray=m}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=m}

-- | A 64-bit log entry identifier incremented sequentially. Each log
-- type has a unique number space. This field is not supported on
-- PA-7000 Series firewalls.
sequenceNumber :: Threat -> Word64
{-# inline sequenceNumber #-}
sequenceNumber u = u.sequenceNumber

-- | Serial number of the firewall that generated the log. These
-- occassionally contain non-numeric characters, so do not attempt
-- to parse this as a decimal number.
serialNumber :: Threat -> Bytes
serialNumber (Threat{serialNumber=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Severity associated with the threat; values are informational,
-- low, medium, high, critical.
severity :: Threat -> Bytes
severity (Threat{severity=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

referer :: Threat -> Bytes
referer = U.referer

httpMethod :: Threat -> Bytes
httpMethod (Threat{httpMethod=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | Action taken for the session; values are @alert@, @allow@,
-- @deny@, @drop@, @drop-all-packets@, @reset-client@, @reset-server@,
-- @reset-both@, @block-url@.
action :: Threat -> Bytes
action (Threat{action=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | Application associated with the session.
application :: Threat -> Bytes
application (Threat{application=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | Name of the rule that the session matched.
ruleName :: Threat -> Bytes
ruleName (Threat{ruleName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

-- | Original session destination IP address.
destinationAddress :: Threat -> IP
{-# inline destinationAddress #-}
destinationAddress u = u.destinationAddress

-- | Original session source IP address.
sourceAddress :: Threat -> IP
{-# inline sourceAddress #-}
sourceAddress u = u.sourceAddress

-- | Source port utilized by the session.
sourcePort :: Threat -> Word16
{-# inline sourcePort #-}
sourcePort u = u.sourcePort

-- | Destination port utilized by the session.
destinationPort :: Threat -> Word16
{-# inline destinationPort #-}
destinationPort u = u.destinationPort

sender :: Threat -> Bytes
sender = U.sender

subject :: Threat -> Bytes
subject = U.subject

recipient :: Threat -> Bytes
recipient = U.recipient

-- | Post-NAT destination port.
natDestinationPort :: Threat -> Word16
{-# inline natDestinationPort #-}
natDestinationPort u = u.natDestinationPort

-- | If Source NAT performed, the post-NAT Source IP address.
natSourceIp :: Threat -> IP
{-# inline natSourceIp #-}
natSourceIp u = u.natSourceIp

-- | If Destination NAT performed, the post-NAT Destination IP address.
natDestinationIp :: Threat -> IP
{-# inline natDestinationIp #-}
natDestinationIp u = u.natDestinationIp

-- | Post-NAT source port.
natSourcePort :: Threat -> Word16
{-# inline natSourcePort #-}
natSourcePort u = u.natSourcePort

-- | Source country or Internal region for private addresses;
-- maximum length is 32 bytes.
sourceCountry :: Threat -> Bytes
sourceCountry (Threat{sourceCountry=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Destination country or Internal region for private addresses.
-- Maximum length is 32 bytes.
destinationCountry :: Threat -> Bytes
destinationCountry (Threat{destinationCountry=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Lists the URL Filtering categories that the firewall used to enforce policy.
--
-- This field only exists in PAN-OS 9.0 and up.
urlCategoryList :: Threat -> Maybe Bytes
{-# inline urlCategoryList #-}
urlCategoryList (Threat{urlCategoryList=x}) = case Bytes.length x of
  0 -> Nothing
  _ -> Just x

-- | IP protocol associated with the session.
ipProtocol :: Threat -> Bytes
ipProtocol (Threat{ipProtocol=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}


-- | Number of total bytes (transmit and receive) for the session.
repeatCount :: Threat -> Word64
{-# inline repeatCount #-}
repeatCount u = u.repeatCount

-- | An internal numerical identifier applied to each session.
sessionId :: Threat -> Word64
{-# inline sessionId #-}
sessionId u = u.sessionId
