{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language DuplicateRecordFields #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
{-# language OverloadedRecordDot #-}

-- | Fields for correlation logs.
module Panos.Syslog.Correlation
  ( category
  , deviceGroupHierarchyLevel1
  , deviceGroupHierarchyLevel2
  , deviceGroupHierarchyLevel3
  , deviceGroupHierarchyLevel4
  , deviceName
  , evidence
  , objectId
  , objectName
  , serialNumber
  , severity
  , sourceAddress
  , sourceUser
  , syslogHost
  , timeGenerated
  ) where

import Chronos (Datetime)
import Data.Bytes.Types (Bytes(..))
import Data.Word (Word64)
import Net.Types (IP)
import Panos.Syslog.Internal.Common (Bounds(Bounds))
import Panos.Syslog.Internal.Correlation (Correlation(Correlation))

import qualified Panos.Syslog.Internal.Correlation

-- | The hostname of the firewall on which the session was logged.
deviceName :: Correlation -> Bytes
deviceName (Correlation{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

objectName :: Correlation -> Bytes
objectName (Correlation{objectName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

sourceUser :: Correlation -> Bytes
sourceUser (Correlation{sourceUser=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Time the log was generated on the dataplane.
timeGenerated :: Correlation -> Datetime
{-# inline timeGenerated #-}
timeGenerated u = u.timeGenerated

-- | Serial number of the firewall that generated the log. These
-- occassionally contain non-numeric characters, so do not attempt
-- to parse this as a decimal number.
serialNumber :: Correlation -> Bytes
serialNumber (Correlation{serialNumber=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | The hostname from the syslog header appended to the PAN-OS log.
-- This field is not documented by Palo Alto Network and technically
-- is not part of the log, but in practice, it is always present.
-- This is similar to @deviceName@.
syslogHost :: Correlation -> Bytes
syslogHost (Correlation{syslogHost=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

severity :: Correlation -> Bytes
severity (Correlation{severity=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

category :: Correlation -> Bytes
category (Correlation{category=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

evidence :: Correlation -> Bytes
evidence u = u.evidence

objectId :: Correlation -> Word64
objectId u = u.objectId

deviceGroupHierarchyLevel1 :: Correlation -> Word64
{-# inline deviceGroupHierarchyLevel1 #-}
deviceGroupHierarchyLevel1 u = u.deviceGroupHierarchyLevel1

deviceGroupHierarchyLevel2 :: Correlation -> Word64
{-# inline deviceGroupHierarchyLevel2 #-}
deviceGroupHierarchyLevel2 u = u.deviceGroupHierarchyLevel2

deviceGroupHierarchyLevel3 :: Correlation -> Word64
{-# inline deviceGroupHierarchyLevel3 #-}
deviceGroupHierarchyLevel3 u = u.deviceGroupHierarchyLevel3

deviceGroupHierarchyLevel4 :: Correlation -> Word64
{-# inline deviceGroupHierarchyLevel4 #-}
deviceGroupHierarchyLevel4 u = u.deviceGroupHierarchyLevel4

-- | Original session source IP address.
sourceAddress :: Correlation -> IP
sourceAddress u = u.sourceAddress


