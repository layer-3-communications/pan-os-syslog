{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language DuplicateRecordFields #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language LambdaCase #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
{-# language ScopedTypeVariables #-}
module Panos.Syslog.Internal.User
  ( User(..)
  , parserUser
  ) where

import Panos.Syslog.Internal.Common

import Chronos (Datetime)
import Data.Bytes.Parser (Parser)
import Data.Primitive (ByteArray)
import Data.Word (Word64)
import Net.Types (IP)

import qualified Data.Bytes.Parser as P
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe
import qualified Net.IP as IP

-- | A PAN-OS user id log. Read-only accessors are found in
-- @Panos.Syslog.User@.
data User = User
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
  , sourceIp :: {-# UNPACK #-} !IP
  , user :: {-# UNPACK #-} !Bounds
  , dataSourceName :: {-# UNPACK #-} !Bounds
  , repeatCount :: {-# UNPACK #-} !Word64
  , dataSource :: {-# UNPACK #-} !Bounds
  , sequenceNumber :: {-# UNPACK #-} !Word64
  , actionFlags :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel1 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel2 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel3 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel4 :: {-# UNPACK #-} !Word64
  , virtualSystemName :: {-# UNPACK #-} !Bounds
  , deviceName :: {-# UNPACK #-} !Bounds
  }

parserUser :: Bounds -> Datetime -> Bounds -> Parser Field s User
parserUser !syslogHost receiveTime !serialNumber = do
  subtype <- untilComma subtypeField -- login or logout
  skipThroughComma futureUseAField
  -- The datetime parser consumes the trailing comma
  timeGenerated <- parserDatetime timeGeneratedDateField timeGeneratedTimeField
  virtualSystem <- untilComma virtualSystemField
  sourceIp <- IP.parserUtf8Bytes sourceIpField
  Latin.char ipField ','
  user <- untilComma userField
  dataSourceName <- untilComma dataSourceNameField
  skipThroughComma eventIdField
  repeatCount <- w64Comma repeatCountField
  skipThroughComma timeoutField
  skipThroughComma sourcePortField
  skipThroughComma destinationPortField
  dataSource <- untilComma dataSourceField
  skipThroughComma dataSourceTypeField
  sequenceNumber <- w64Comma sequenceNumberField
  -- TODO: handle action flags
  Latin.char actionFlagsField '0'
  Latin.char actionFlagsField 'x'
  _ <- untilComma actionFlagsField
  let actionFlags = 0
  deviceGroupHierarchyLevel1 <- w64Comma deviceGroupHierarchyLevel1Field
  deviceGroupHierarchyLevel2 <- w64Comma deviceGroupHierarchyLevel2Field
  deviceGroupHierarchyLevel3 <- w64Comma deviceGroupHierarchyLevel3Field
  deviceGroupHierarchyLevel4 <- w64Comma deviceGroupHierarchyLevel4Field
  virtualSystemName <- untilComma virtualSystemNameField
  deviceName <- untilComma deviceNameField
  -- Ignore all fields after device name since they are low-value.
  _ <- P.remaining
  message <- Unsafe.expose
  pure User
    { subtype
    , timeGenerated
    , sourceIp
    , sequenceNumber 
    , deviceGroupHierarchyLevel1 , deviceGroupHierarchyLevel2 
    , deviceGroupHierarchyLevel3 , deviceGroupHierarchyLevel4 
    , virtualSystemName , deviceName , receiveTime
    , serialNumber, actionFlags, message
    , syslogHost, virtualSystem
    , dataSourceName, dataSource, user, repeatCount
    }
