{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language DuplicateRecordFields #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language LambdaCase #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
{-# language ScopedTypeVariables #-}
module Panos.Syslog.Internal.Traffic
  ( Traffic(..)
  , parserTraffic
  ) where

import Panos.Syslog.Internal.Common

import Chronos (Datetime)
import Data.Bytes.Parser (Parser)
import Data.Primitive (ByteArray)
import Data.Word (Word64,Word32,Word16)
import GHC.Exts (Ptr(Ptr))
import Net.Types (IP(IP),IPv6(IPv6))
import Data.WideWord (Word128)

import qualified Data.Bytes.Parser as P
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe
import qualified Net.IP as IP
import qualified UUID

-- | A PAN-OS traffic log. Read-only accessors are found in
-- @Panos.Syslog.Traffic@.
data Traffic = Traffic
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
    -- Presented as: start, end, drop, and deny
  , timeGenerated :: {-# UNPACK #-} !Datetime
    -- Presented as: 2018/04/11 23:19:22
  , sourceAddress :: {-# UNPACK #-} !IP
  , destinationAddress :: {-# UNPACK #-} !IP
  , natSourceIp :: {-# UNPACK #-} !IP
  , natDestinationIp :: {-# UNPACK #-} !IP
  , ruleName :: {-# UNPACK #-} !Bounds
  , sourceUser :: {-# UNPACK #-} !Bounds
  , destinationUser :: {-# UNPACK #-} !Bounds
  , application :: {-# UNPACK #-} !Bounds
  , virtualSystem :: {-# UNPACK #-} !Bounds
  , sourceZone :: {-# UNPACK #-} !Bounds
  , destinationZone :: {-# UNPACK #-} !Bounds
  , inboundInterface :: {-# UNPACK #-} !Bounds
  , outboundInterface :: {-# UNPACK #-} !Bounds
  , logAction :: {-# UNPACK #-} !Bounds
  , sessionId :: {-# UNPACK #-} !Word64
  , repeatCount :: {-# UNPACK #-} !Word64
  , sourcePort :: {-# UNPACK #-} !Word16
  , destinationPort :: {-# UNPACK #-} !Word16
  , natSourcePort :: {-# UNPACK #-} !Word16
  , natDestinationPort :: {-# UNPACK #-} !Word16
  , flags :: {-# UNPACK #-} !Word32
    -- Presented as: 0x400053
  , ipProtocol :: {-# UNPACK #-} !Bounds
    -- Presented as: tcp, udp, etc.
  , action :: {-# UNPACK #-} !Bounds
  , bytes :: {-# UNPACK #-} !Word64
  , bytesSent :: {-# UNPACK #-} !Word64
  , bytesReceived :: {-# UNPACK #-} !Word64
  , packets :: {-# UNPACK #-} !Word64
  , startTime :: {-# UNPACK #-} !Datetime
  , elapsedTime :: {-# UNPACK #-} !Word64
  , category :: {-# UNPACK #-} !Bounds
  , sequenceNumber :: {-# UNPACK #-} !Word64
  , actionFlags :: {-# UNPACK #-} !Word64
    -- Presented as: 0x8000000000000000
  , sourceCountry :: {-# UNPACK #-} !Bounds
  , destinationCountry :: {-# UNPACK #-} !Bounds
  , packetsSent :: {-# UNPACK #-} !Word64
  , packetsReceived :: {-# UNPACK #-} !Word64
  , sessionEndReason :: {-# UNPACK #-} !Bounds
  , deviceGroupHierarchyLevel1 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel2 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel3 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel4 :: {-# UNPACK #-} !Word64
  , virtualSystemName :: {-# UNPACK #-} !Bounds
  , deviceName :: {-# UNPACK #-} !Bounds
  , actionSource :: {-# UNPACK #-} !Bounds
  , ruleUuid :: {-# UNPACK #-} !Word128
  }


parserTraffic :: Bounds -> Datetime -> Bounds -> Parser Field s Traffic
parserTraffic !syslogHost receiveTime !serialNumber = do
  subtype <- untilComma subtypeField
  skipThroughComma futureUseAField
  -- The datetime parser consumes the trailing comma
  timeGenerated <- parserDatetime timeGeneratedDateField timeGeneratedTimeField
  sourceAddress <- IP.parserUtf8Bytes sourceAddressField
  Latin.char sourceAddressField ','
  destinationAddress <- IP.parserUtf8Bytes destinationAddressField
  Latin.char destinationAddressField ','
  -- Use the ip address zero when no NAT address is present.
  natSourceIp <- Latin.trySatisfy (==',') >>= \case
    True -> pure (IP (IPv6 0))
    False -> do
      natSourceIp <- IP.parserUtf8Bytes natSourceIpField
      Latin.char natSourceIpField ','
      pure natSourceIp
  natDestinationIp <- Latin.trySatisfy (==',') >>= \case
    True -> pure (IP (IPv6 0))
    False -> do
      natDestinationIp <- IP.parserUtf8Bytes natDestinationIpField
      Latin.char natDestinationIpField ','
      pure natDestinationIp
  ruleName <- untilComma ruleNameField
  sourceUser <- untilComma sourceUserField
  destinationUser <- untilComma destinationUserField
  application <- untilComma applicationField
  virtualSystem <- untilComma virtualSystemField
  sourceZone <- untilComma sourceZoneField
  destinationZone <- untilComma destinationZoneField
  inboundInterface <- untilComma inboundInterfaceField
  outboundInterface <- untilComma outboundInterfaceField
  logAction <- untilComma logActionField
  skipThroughComma futureUseBField
  sessionId <- w64Comma sessionIdField
  repeatCount <- w64Comma repeatCountField
  sourcePort <- w16Comma sourcePortField
  destinationPort <- w16Comma destinationPortField
  natSourcePort <- w16Comma natSourcePortField
  natDestinationPort <- w16Comma natDestinationPortField
  -- TODO: handle the flags
  Latin.char actionFlagsField '0'
  Latin.char actionFlagsField 'x'
  _ <- untilComma flagsField
  let flags = 0
  ipProtocol <- untilComma ipProtocolField
  action <- untilComma actionField
  bytes <- w64Comma bytesField
  bytesSent <- w64Comma bytesSentField
  bytesReceived <- w64Comma bytesReceivedField
  packets <- w64Comma packetsField
  startTime <- parserDatetime startTimeDateField startTimeTimeField
  elapsedTime <- w64Comma elapsedTimeField
  category <- untilComma categoryField
  skipThroughComma futureUseCField
  sequenceNumber <- w64Comma sequenceNumberField
  -- TODO: handle action flags
  Latin.char actionFlagsField '0'
  Latin.char actionFlagsField 'x'
  _ <- untilComma actionFlagsField
  let actionFlags = 0
  sourceCountry <- untilComma sourceCountryField
  destinationCountry <- untilComma destinationCountryField
  skipThroughComma futureUseEField
  packetsSent <- w64Comma packetsSentField
  packetsReceived <- w64Comma packetsReceivedField
  sessionEndReason <- untilComma sessionEndReasonField
  deviceGroupHierarchyLevel1 <- w64Comma deviceGroupHierarchyLevel1Field
  deviceGroupHierarchyLevel2 <- w64Comma deviceGroupHierarchyLevel2Field
  deviceGroupHierarchyLevel3 <- w64Comma deviceGroupHierarchyLevel3Field
  deviceGroupHierarchyLevel4 <- w64Comma deviceGroupHierarchyLevel4Field
  virtualSystemName <- untilComma virtualSystemNameField
  deviceName <- untilComma deviceNameField
  actionSource <- untilComma actionSourceField
  skipThroughComma sourceVmUuidField
  skipThroughComma destinationVmUuidField
  skipThroughComma tunnelIdField
  skipThroughComma monitorTagField
  skipThroughComma parentSessionIdField
  skipThroughComma parentStartTimeField
  skipThroughComma tunnelTypeField
  skipThroughComma sctpAssociationIdField
  skipDigitsThroughComma sctpChunksField
  skipDigitsThroughComma sctpChunksSentField
  Latin.skipDigits1 sctpChunksReceivedField
  message <- Unsafe.expose
  -- In PAN-OS 8.1, traffic logs end after SCTP chunks received.
  -- PAN-OS 9.0 adds two additional fields: rule uuid and a number
  -- that has something to do with HTTP/2.
  P.isEndOfInput >>= \case
    False -> do
      Latin.char ruleUuidField ','
      ruleUuid <- UUID.parserHyphenated ruleUuidField
      Latin.char http2ConnectionField ','
      Latin.skipDigits1 http2ConnectionField
      -- PAN-OS 9.1 adds several more fields (mostly SD-WAN) after the
      -- http 2 connection field. For the time being, we ignored all of
      -- these, failing if any are present.
      P.isEndOfInput >>= \case
        True -> pure ()
        False -> P.cstring linkChangeCountField (Ptr ",0,,,,,,,"#)
      pure Traffic
        { subtype , timeGenerated , sourceAddress , destinationAddress 
        , natSourceIp , natDestinationIp , ruleName , sourceUser 
        , destinationUser , application , virtualSystem , sourceZone 
        , destinationZone , inboundInterface , outboundInterface , logAction 
        , sessionId , repeatCount , sourcePort , destinationPort 
        , natSourcePort , natDestinationPort , ipProtocol 
        , action , bytes , bytesSent , bytesReceived 
        , packets , startTime , elapsedTime , category 
        , sequenceNumber , sourceCountry , destinationCountry 
        , packetsSent , sessionEndReason 
        , deviceGroupHierarchyLevel1 , deviceGroupHierarchyLevel2 
        , deviceGroupHierarchyLevel3 , deviceGroupHierarchyLevel4 
        , virtualSystemName , deviceName , actionSource , receiveTime
        , serialNumber, packetsReceived, actionFlags, flags, message
        , syslogHost, ruleUuid
        }
    True -> pure Traffic
      { subtype , timeGenerated , sourceAddress , destinationAddress 
      , natSourceIp , natDestinationIp , ruleName , sourceUser 
      , destinationUser , application , virtualSystem , sourceZone 
      , destinationZone , inboundInterface , outboundInterface , logAction 
      , sessionId , repeatCount , sourcePort , destinationPort 
      , natSourcePort , natDestinationPort , ipProtocol 
      , action , bytes , bytesSent , bytesReceived 
      , packets , startTime , elapsedTime , category 
      , sequenceNumber , sourceCountry , destinationCountry 
      , packetsSent , sessionEndReason 
      , deviceGroupHierarchyLevel1 , deviceGroupHierarchyLevel2 
      , deviceGroupHierarchyLevel3 , deviceGroupHierarchyLevel4 
      , virtualSystemName , deviceName , actionSource , receiveTime
      , serialNumber, packetsReceived, actionFlags, flags, message
      , syslogHost, ruleUuid = 0
      }
