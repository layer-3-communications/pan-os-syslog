{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language DuplicateRecordFields #-}
{-# language NumericUnderscores #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}

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
  , httpHeaders
  , httpMethod
  , inboundInterface
  , miscellaneous
  , natDestinationIp
  , natDestinationPort
  , natSourceIp
  , natSourcePort
  , outboundInterface
  , recipient
  , referer
  , ruleName
  , sender
  , sequenceNumber
  , serialNumber
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
  , virtualSystemName
  ) where

import Data.Bytes.Types (Bytes(..))
import Panos.Syslog.Unsafe (Threat(Threat),Bounds(Bounds))
import Data.Word (Word64,Word16)
import Chronos (Datetime)
import Net.Types (IP)
import qualified Panos.Syslog.Unsafe as U

subtype :: Threat -> Bytes
subtype (Threat{subtype=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

sourceUser :: Threat -> Bytes
sourceUser (Threat{sourceUser=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

destinationUser :: Threat -> Bytes
destinationUser (Threat{destinationUser=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

inboundInterface :: Threat -> Bytes
inboundInterface (Threat{inboundInterface=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

outboundInterface :: Threat -> Bytes
outboundInterface (Threat{outboundInterface=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

sourceZone :: Threat -> Bytes
sourceZone (Threat{sourceZone=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

destinationZone :: Threat -> Bytes
destinationZone (Threat{destinationZone=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

deviceName :: Threat -> Bytes
deviceName (Threat{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

threatName :: Threat -> Bytes
threatName (Threat{threatName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

threatId :: Threat -> Word64
threatId = U.threatId

-- | Time the log was generated on the dataplane.
timeGenerated :: Threat -> Datetime
timeGenerated = U.timeGenerated

category :: Threat -> Bytes
category (Threat{category=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

contentVersion :: Threat -> Bytes
contentVersion (Threat{contentVersion=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

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

sequenceNumber :: Threat -> Word64
sequenceNumber = U.sequenceNumber

-- | Serial number of the firewall that generated the log. These
-- occassionally contain non-numeric characters, so do not attempt
-- to parse this as a decimal number.
serialNumber :: Threat -> Bytes
serialNumber (Threat{serialNumber=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

severity :: Threat -> Bytes
severity (Threat{severity=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

referer :: Threat -> Bytes
referer = U.referer

httpMethod :: Threat -> Bytes
httpMethod (Threat{httpMethod=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

action :: Threat -> Bytes
action (Threat{action=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

application :: Threat -> Bytes
application (Threat{application=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

ruleName :: Threat -> Bytes
ruleName (Threat{ruleName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

destinationAddress :: Threat -> IP
destinationAddress = U.destinationAddress

sourceAddress :: Threat -> IP
sourceAddress = U.sourceAddress

sourcePort :: Threat -> Word16
sourcePort = U.sourcePort

destinationPort :: Threat -> Word16
destinationPort = U.destinationPort

sender :: Threat -> Bytes
sender = U.sender

subject :: Threat -> Bytes
subject = U.subject

recipient :: Threat -> Bytes
recipient = U.recipient

-- | Post-NAT destination port.
natDestinationPort :: Threat -> Word16
natDestinationPort = U.natDestinationPort

-- | If Source NAT performed, the post-NAT Source IP address.
natSourceIp :: Threat -> IP
natSourceIp = U.natSourceIp

-- | If Destination NAT performed, the post-NAT Destination IP address.
natDestinationIp :: Threat -> IP
natDestinationIp = U.natDestinationIp

-- | Post-NAT source port.
natSourcePort :: Threat -> Word16
natSourcePort = U.natSourcePort

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
