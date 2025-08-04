{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language DuplicateRecordFields #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
{-# language OverloadedRecordDot #-}

-- | Fields for globalprotect logs.
module Panos.Syslog.GlobalProtect
  ( serialNumber
  , sourceUser
  , syslogHost
  , timeGenerated
  , virtualSystem
  , stage
  , authenticationMethod
  , tunnelType
  , machineName
  , publicIp
  , status
  , eventId
  ) where

import Chronos (Datetime)
import Data.Bytes.Types (Bytes(..))
import Net.Types (IPv4)
import Panos.Syslog.Internal.Common (Bounds(Bounds))
import Panos.Syslog.Internal.GlobalProtect (GlobalProtect(GlobalProtect))

import qualified Panos.Syslog.Internal.GlobalProtect

-- | Time the log was generated on the dataplane.
timeGenerated :: GlobalProtect -> Datetime
{-# inline timeGenerated #-}
timeGenerated u = u.timeGenerated

-- | Serial number of the firewall that generated the log. These
-- occassionally contain non-numeric characters, so do not attempt
-- to parse this as a decimal number.
serialNumber :: GlobalProtect -> Bytes
serialNumber (GlobalProtect{serialNumber=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | The hostname from the syslog header appended to the PAN-OS log.
-- This field is not documented by Palo Alto Network and technically
-- is not part of the log, but in practice, it is always present.
-- This is similar to @deviceName@.
syslogHost :: GlobalProtect -> Bytes
syslogHost (GlobalProtect{syslogHost=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

eventId :: GlobalProtect -> Bytes
eventId (GlobalProtect{eventId=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

status :: GlobalProtect -> Bytes
status (GlobalProtect{status=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

virtualSystem :: GlobalProtect -> Bytes
virtualSystem (GlobalProtect{virtualSystem=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

stage :: GlobalProtect -> Bytes
stage (GlobalProtect{stage=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

authenticationMethod :: GlobalProtect -> Bytes
authenticationMethod (GlobalProtect{authenticationMethod=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

tunnelType :: GlobalProtect -> Bytes
tunnelType (GlobalProtect{tunnelType=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

sourceUser :: GlobalProtect -> Bytes
sourceUser (GlobalProtect{sourceUser=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

machineName :: GlobalProtect -> Bytes
machineName (GlobalProtect{machineName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

publicIp :: GlobalProtect -> IPv4
publicIp u = u.publicIp
