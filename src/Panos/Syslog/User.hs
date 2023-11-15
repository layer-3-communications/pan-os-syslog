{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language DuplicateRecordFields #-}
{-# language NumericUnderscores #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language OverloadedRecordDot #-}

-- | Fields for user logs.
module Panos.Syslog.User
  ( dataSource
  , dataSourceName
  , deviceGroupHierarchyLevel1
  , deviceGroupHierarchyLevel2
  , deviceGroupHierarchyLevel3
  , deviceGroupHierarchyLevel4
  , deviceName
  , sourceIp
  , repeatCount
  , sequenceNumber
  , serialNumber
  , subtype
  , syslogHost
  , timeGenerated
  , user
  , virtualSystem
  , virtualSystemName
  ) where

import Chronos (Datetime)
import Data.Bytes.Types (Bytes(..))
import Data.Word (Word64)
import Net.Types (IP)
import Panos.Syslog.Unsafe (User(User),Bounds(Bounds))

import qualified Panos.Syslog.Unsafe as U

-- | Subtype of the system log; refers to the system daemon
-- generating the log; values are @crypto@, @dhcp@, @dnsproxy@,
-- @dos@, @general@, @global-protect@, @ha@, @hw@, @nat@, @ntpd@,
-- @pbf@, @port@, @pppoe@, @ras@, @routing@, @satd@, @sslmgr@,
-- @sslvpn@, @userid@, @url-filtering@, @vpn@.
subtype :: User -> Bytes
subtype (User{subtype=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | The hostname of the firewall on which the session was logged.
deviceName :: User -> Bytes
deviceName (User{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Identifies the end user.
user :: User -> Bytes
user (User{user=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Source from which mapping information is collected.
dataSource :: User -> Bytes
dataSource (User{dataSource=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | User-ID source that sends the IP (Port)-User Mapping.
dataSourceName :: User -> Bytes
dataSourceName (User{dataSourceName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Time the log was generated on the dataplane.
timeGenerated :: User -> Datetime
{-# inline timeGenerated #-}
timeGenerated u = u.timeGenerated

-- | A 64-bit log entry identifier incremented sequentially;
-- each log type has a unique number space.
sequenceNumber :: User -> Word64
{-# inline sequenceNumber #-}
sequenceNumber u = u.sequenceNumber

-- | Serial number of the firewall that generated the log. These
-- occassionally contain non-numeric characters, so do not attempt
-- to parse this as a decimal number.
serialNumber :: User -> Bytes
serialNumber (User{serialNumber=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Virtual System associated with the session.
virtualSystem :: User -> Bytes
virtualSystem (User{virtualSystem=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | The name of the virtual system associated with the session; only valid
-- on firewalls enabled for multiple virtual systems.
virtualSystemName :: User -> Bytes
virtualSystemName (User{virtualSystemName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | The hostname from the syslog header appended to the PAN-OS log.
-- This field is not documented by Palo Alto Network and technically
-- is not part of the log, but in practice, it is always present.
-- This is similar to @deviceName@.
syslogHost :: User -> Bytes
syslogHost (User{syslogHost=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

-- | Number of total bytes (transmit and receive) for the session.
repeatCount :: User -> Word64
{-# inline repeatCount #-}
repeatCount u = u.repeatCount

deviceGroupHierarchyLevel1 :: User -> Word64
{-# inline deviceGroupHierarchyLevel1 #-}
deviceGroupHierarchyLevel1 u = u.deviceGroupHierarchyLevel1

deviceGroupHierarchyLevel2 :: User -> Word64
{-# inline deviceGroupHierarchyLevel2 #-}
deviceGroupHierarchyLevel2 u = u.deviceGroupHierarchyLevel2

deviceGroupHierarchyLevel3 :: User -> Word64
{-# inline deviceGroupHierarchyLevel3 #-}
deviceGroupHierarchyLevel3 u = u.deviceGroupHierarchyLevel3

deviceGroupHierarchyLevel4 :: User -> Word64
{-# inline deviceGroupHierarchyLevel4 #-}
deviceGroupHierarchyLevel4 u = u.deviceGroupHierarchyLevel4

-- | Original session source IP address.
sourceIp :: User -> IP
sourceIp = U.sourceIp

