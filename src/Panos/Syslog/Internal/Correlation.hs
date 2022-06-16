module Panos.Syslog.Internal.Correlation
  (
  ) where

-- | A PAN-OS system log. Read-only accessors are found in
-- @Panos.Syslog.System@.
data System = System
  { message :: {-# UNPACK #-} !ByteArray
    -- The original log
  , syslogHost :: {-# UNPACK #-} !Bounds
    -- The host as presented in the syslog preamble that
    -- prefixes the message.
  , receiveTime :: {-# UNPACK #-} !Datetime
    -- In log, presented as: 2019/06/18 15:10:20
  , serialNumber :: {-# UNPACK #-} !Bounds
    -- In log, presented as: 002610378847
  , subtype :: {-# UNPACK #-} !Bounds
    -- Presented as: dhcp, dnsproxy, dos, general, etc.
  , timeGenerated :: {-# UNPACK #-} !Datetime
    -- Presented as: 2019/11/04 08:39:05
  , virtualSystem :: {-# UNPACK #-} !Bounds
  , eventId :: {-# UNPACK #-} !Bounds
  , object :: {-# UNPACK #-} !Bounds
  , module_ :: {-# UNPACK #-} !Bounds
  , severity :: {-# UNPACK #-} !Bounds
  }
