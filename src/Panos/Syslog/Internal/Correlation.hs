{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language DuplicateRecordFields #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language LambdaCase #-}
{-# language MagicHash #-}
{-# language MultiWayIf #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
{-# language ScopedTypeVariables #-}

module Panos.Syslog.Internal.Correlation
  ( Correlation(..)
  , parserCorrelation
  ) where

import Chronos (Datetime)
import Data.Bytes.Parser (Parser)
import Data.Bytes.Types (Bytes(..))
import Data.Primitive (ByteArray)
import Data.Word (Word64)
import Panos.Syslog.Internal.Common
import Net.Types (IP)

import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe
import qualified Net.IP as IP

-- | A PAN-OS correlation log. Read-only accessors are found in
-- @Panos.Syslog.Correlation@.
data Correlation = Correlation
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
  , sourceAddress :: {-# UNPACK #-} !IP
  , sourceUser :: {-# UNPACK #-} !Bounds
  , virtualSystem :: {-# UNPACK #-} !Bounds
  , category :: {-# UNPACK #-} !Bounds
  , severity :: {-# UNPACK #-} !Bounds
  , deviceGroupHierarchyLevel1 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel2 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel3 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel4 :: {-# UNPACK #-} !Word64
  , deviceName :: {-# UNPACK #-} !Bounds
  , objectName :: {-# UNPACK #-} !Bounds
  , objectId :: {-# UNPACK #-} !Word64
  , evidence :: {-# UNPACK #-} !Bytes
  }

parserCorrelation :: Bounds -> Datetime -> Bounds -> Parser Field s Correlation
parserCorrelation !syslogHost receiveTime !serialNumber = do
  !message <- Unsafe.expose
  subtype <- untilComma subtypeField -- usually empty for correlations
  skipThroughComma futureUseAField
  -- The datetime parser consumes the trailing comma
  timeGenerated <- parserDatetime timeGeneratedDateField timeGeneratedTimeField
  sourceAddress <- IP.parserUtf8Bytes sourceIpField
  Latin.char sourceAddressField ','
  sourceUser <- untilComma sourceUserField
  virtualSystem <- untilComma virtualSystemField
  category <- untilComma categoryField
  severity <- untilComma severityField
  deviceGroupHierarchyLevel1 <- w64Comma deviceGroupHierarchyLevel1Field
  deviceGroupHierarchyLevel2 <- w64Comma deviceGroupHierarchyLevel2Field
  deviceGroupHierarchyLevel3 <- w64Comma deviceGroupHierarchyLevel3Field
  deviceGroupHierarchyLevel4 <- w64Comma deviceGroupHierarchyLevel4Field
  skipThroughComma virtualSystemNameField
  deviceName <- untilComma deviceNameField
  skipThroughComma virtualSystemIdField
  objectName <- untilComma objectNameField
  objectId <- w64Comma objectIdField
  evidence <- finalOptionallyQuoted evidenceField
  pure Correlation
    { message
    , syslogHost
    , receiveTime
    , serialNumber
    , subtype
    , timeGenerated
    , virtualSystem
    , category
    , severity
    , deviceGroupHierarchyLevel1
    , deviceGroupHierarchyLevel2
    , deviceGroupHierarchyLevel3
    , deviceGroupHierarchyLevel4
    , deviceName
    , objectName
    , objectId
    , evidence
    , sourceAddress
    , sourceUser
    }
