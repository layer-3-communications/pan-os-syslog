{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language DuplicateRecordFields #-}
{-# language NumericUnderscores #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}

-- | Fields for system logs.
module Panos.Syslog.System
  ( description
  , deviceName
  , eventId
  , module_
  , object
  , sequenceNumber
  , serialNumber
  , severity
  , subtype
  , timeGenerated
  ) where

import Data.Bytes.Types (Bytes(..))
import Data.Word (Word64)
import Panos.Syslog.Unsafe (System(System),Bounds(Bounds))
import Chronos (Datetime)
import qualified Panos.Syslog.Unsafe as U

-- | Subtype of the system log; refers to the system daemon
-- generating the log; values are @crypto@, @dhcp@, @dnsproxy@,
-- @dos@, @general@, @global-protect@, @ha@, @hw@, @nat@, @ntpd@,
-- @pbf@, @port@, @pppoe@, @ras@, @routing@, @satd@, @sslmgr@,
-- @sslvpn@, @userid@, @url-filtering@, @vpn@.
subtype :: System -> Bytes
subtype (System{subtype=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | The hostname of the firewall on which the session was logged.
deviceName :: System -> Bytes
deviceName (System{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Name of the object associated with the system event.
object :: System -> Bytes
object (System{object=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | This field is valid only when the value of the @subtype@
-- field is @general@. It provides additional information about
-- the sub-system generating the log; values are @general@,
-- @management@, @auth@, @ha@, @upgrade@, @chassis@.
module_ :: System -> Bytes
module_ (System{module_=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Severity associated with the event; values are @informational@,
-- @low@, @medium@, @high@, @critical@.
severity :: System -> Bytes
severity (System{severity=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | String showing the name of the event.
eventId :: System -> Bytes
eventId (System{eventId=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Detailed description of the event, up to a maximum of 512 bytes.
description :: System -> Bytes
description (System{descriptionBounds=Bounds off len,descriptionByteArray=m}) =
  Bytes{offset=off,length=len,array=m}

-- | Time the log was generated on the dataplane.
timeGenerated :: System -> Datetime
timeGenerated = U.timeGenerated

-- | A 64-bit log entry identifier incremented sequentially;
-- each log type has a unique number space.
sequenceNumber :: System -> Word64
sequenceNumber = U.sequenceNumber

-- | Serial number of the firewall that generated the log. These
-- occassionally contain non-numeric characters, so do not attempt
-- to parse this as a decimal number.
serialNumber :: System -> Bytes
serialNumber (System{serialNumber=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

