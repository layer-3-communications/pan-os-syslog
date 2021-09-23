{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language DuplicateRecordFields #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language LambdaCase #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
{-# language ScopedTypeVariables #-}
module Panos.Syslog.Internal.System
  ( System(..)
  , parserSystem
  ) where

import Panos.Syslog.Internal.Common

import Chronos (Datetime)
import Data.Bytes.Parser (Parser)
import Data.Bytes.Types (Bytes(..))
import Data.Primitive (ByteArray)
import Data.Word (Word64)

import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe

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
  , descriptionBounds :: {-# UNPACK #-} !Bounds
  , descriptionByteArray :: {-# UNPACK #-} !ByteArray
  , sequenceNumber :: {-# UNPACK #-} !Word64
  , actionFlags :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel1 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel2 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel3 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel4 :: {-# UNPACK #-} !Word64
  , virtualSystemName :: {-# UNPACK #-} !Bounds
  , deviceName :: {-# UNPACK #-} !Bounds
  }

parserSystem :: Bounds -> Datetime -> Bounds -> Parser Field s System
parserSystem syslogHost receiveTime serialNumber = do
  subtype <- untilComma subtypeField
  skipThroughComma futureUseAField
  -- The datetime parser consumes the trailing comma
  timeGenerated <- parserDatetime timeGeneratedDateField timeGeneratedTimeField
  virtualSystem <- untilComma virtualSystemField
  eventId <- untilComma eventIdField
  object <- untilComma objectField
  skipThroughComma futureUseBField
  skipThroughComma futureUseCField
  module_ <- untilComma moduleField
  severity <- untilComma severityField
  Bytes{array=descriptionByteArray,offset=descrOff,length=descrLen} <-
    parserOptionallyQuoted descriptionField
  let descriptionBounds = Bounds descrOff descrLen
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
  deviceName <- finalField
  message <- Unsafe.expose
  pure System
    { subtype , timeGenerated
    , sequenceNumber 
    , deviceGroupHierarchyLevel1 , deviceGroupHierarchyLevel2 
    , deviceGroupHierarchyLevel3 , deviceGroupHierarchyLevel4 
    , virtualSystemName , deviceName , receiveTime
    , serialNumber, actionFlags, message
    , syslogHost, virtualSystem, eventId, object, module_
    , severity, descriptionBounds, descriptionByteArray
    }

-- There should not be any more commas left in the input.
-- This takes until it finds a comma or until end of input
-- is reached.
finalField :: Parser e s Bounds
{-# inline finalField #-}
finalField = do
  start <- Unsafe.cursor
  Latin.skipUntil ','
  end <- Unsafe.cursor
  pure (Bounds start (end - start))
