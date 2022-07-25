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
module Panos.Syslog.Internal.Threat
  ( Threat(..)
  , parserThreat
  ) where

import Panos.Syslog.Internal.Common

import Chronos (Datetime)
import Control.Monad (when)
import Data.Bytes.Parser (Parser)
import Data.Bytes.Types (Bytes(..))
import Data.Char (isAsciiUpper,isAsciiLower)
import Data.Primitive (ByteArray)
import Data.Word (Word64,Word32,Word16)
import GHC.Exts (Int(I#),Ptr(Ptr))
import Net.Types (IP(IP),IPv6(IPv6))
import Data.WideWord (Word128)

import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Parser as P
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe
import qualified Data.Primitive as PM
import qualified GHC.Exts as Exts
import qualified Net.IP as IP
import qualified UUID

-- | A PAN-OS threat log. Read-only accessors are found in
-- @Panos.Syslog.Threat@.
data Threat = Threat
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
    -- Presented as: data, file, flood, packet, scan, spyware, url,
    -- virus, vulnerability, wildfire, or wildfire-virus.
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
  , action :: {-# UNPACK #-} !Bounds
  , ipProtocol :: {-# UNPACK #-} !Bounds
  , flags :: {-# UNPACK #-} !Word32
  , miscellaneousBounds :: {-# UNPACK #-} !Bounds
  , miscellaneousByteArray :: {-# UNPACK #-} !ByteArray
  , threatName :: {-# UNPACK #-} !Bounds
  , threatId :: {-# UNPACK #-} !Word64
  , category :: {-# UNPACK #-} !Bounds
  , severity :: {-# UNPACK #-} !Bounds
  , direction :: {-# UNPACK #-} !Bounds
  , sequenceNumber :: {-# UNPACK #-} !Word64
  , actionFlags :: {-# UNPACK #-} !Word64
    -- Presented as: 0x8000000000000000
  , sourceCountry :: {-# UNPACK #-} !Bounds
  , destinationCountry :: {-# UNPACK #-} !Bounds
  , contentType :: {-# UNPACK #-} !Bounds
  , pcapId :: {-# UNPACK #-} !Word64
  , fileDigest :: {-# UNPACK #-} !Bounds
    -- Only used by wildfire subtype
    -- TODO: make the file digest a 128-bit or 256-bit word
  , cloud :: {-# UNPACK #-} !Bounds
    -- Only used by wildfire subtype
  , urlIndex :: {-# UNPACK #-} !Word64
    -- Only used by wildfire subtype
  , userAgentBounds :: {-# UNPACK #-} !Bounds
  , userAgentByteArray :: {-# UNPACK #-} !ByteArray
    -- Only used by url filtering subtype. This field may have
    -- escaped characters, so we include the possibility of
    -- using a byte array distinct from the original log.
  , fileType :: {-# UNPACK #-} !Bounds
    -- Only used by wildfire subtype
  , forwardedFor :: {-# UNPACK #-} !Bounds
    -- Only used by url filtering subtype
  , referer :: {-# UNPACK #-} !Bytes
    -- Only used by url filtering subtype
  , sender :: {-# UNPACK #-} !Bytes
    -- Only used by wildfire subtype
  , subject :: {-# UNPACK #-} !Bytes
    -- Only used by wildfire subtype
  , recipient :: {-# UNPACK #-} !Bytes
    -- Only used by wildfire subtype
  , reportId :: {-# UNPACK #-} !Bounds
    -- Only used by wildfire subtype
  , deviceGroupHierarchyLevel1 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel2 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel3 :: {-# UNPACK #-} !Word64
  , deviceGroupHierarchyLevel4 :: {-# UNPACK #-} !Word64
  , virtualSystemName :: {-# UNPACK #-} !Bounds
  , deviceName :: {-# UNPACK #-} !Bounds
    -- TODO: skipping over uuid fields for now
  , httpMethod :: {-# UNPACK #-} !Bounds
  , tunnelId :: {-# UNPACK #-} !Word64
  , parentSessionId :: {-# UNPACK #-} !Word64
    -- Only used by url subtype
  , threatCategory :: {-# UNPACK #-} !Bounds
  , contentVersion :: {-# UNPACK #-} !Bounds
    -- TODO: skipping some fields here
  , sctpAssociationId :: {-# UNPACK #-} !Word64
  , payloadProtocolId :: {-# UNPACK #-} !Word64
    -- TODO: skipping over other fields here
  , httpHeaders :: {-# UNPACK #-} !Bytes
  , urlCategoryList :: {-# UNPACK #-} !Bytes
  , ruleUuid :: {-# UNPACK #-} !Word128
  }


parserThreat :: Bounds -> Datetime -> Bounds -> Parser Field s Threat
parserThreat !syslogHost receiveTime !serialNumber = do
  !message <- Unsafe.expose
  subtype@(Bounds subtypeOff subtypeLen)  <- untilComma subtypeField
  let !subtypeB = Bytes message subtypeOff subtypeLen
  let !isWildfire =
        if | Bytes.equalsCString (Ptr "wildfire"# ) subtypeB -> 1 :: Int
           | otherwise -> 0 :: Int
  let !isUrl =
        if | Bytes.equalsCString (Ptr "url"# ) subtypeB -> 1 :: Int
           | otherwise -> 0 :: Int
  let !isSpyware =
        if | Bytes.equalsCString (Ptr "spyware"# ) subtypeB -> 1 :: Int
           | otherwise -> 0 :: Int
  Bounds futureUseAOff futureUseALen <- untilComma futureUseAField
  let !futureUseA = Bytes message futureUseAOff futureUseALen
  let !version =
        if | Bytes.equalsCString (Ptr "10.0"# ) futureUseA -> 100 :: Int
           | Bytes.equalsCString (Ptr "10.1"# ) futureUseA -> 101 :: Int
           | otherwise -> 0 :: Int
  -- the datetime parser also grabs the trailing comma
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
  -- According to Palo Alto's documentation, the field after log_action
  -- is a future use field. However, in some (possibly all) PAN-OS 10
  -- logs, this field is missing. In all other logs, it is a
  -- YYYY/MM/DD HH:mm:ss timestamp. If the field is exactly 19 bytes long,
  -- we assume that it is the unused field. Otherwise, we assume that the
  -- unused field is missing, and we try to interpret these bytes as the
  -- session_id.
  futureCursorB <- Unsafe.cursor
  Bounds _ futureLenB <- untilComma futureUseBField
  sessionId <- case futureLenB of
    19 -> w64Comma sessionIdField
    _ -> do
      Unsafe.jump futureCursorB
      w64Comma sessionIdField
  repeatCount <- w64Comma repeatCountField
  sourcePort <- w16Comma sourcePortField
  destinationPort <- w16Comma destinationPortField
  natSourcePort <- w16Comma natSourcePortField
  natDestinationPort <- w16Comma natDestinationPortField
  -- Note: Flags are ignored. Also, in either PAN-OS 10 or Prisma
  -- (not sure which one causes this), flags are missing.
  Latin.trySatisfy (=='0') >>= \case
    True -> do
      Latin.char flagsField 'x'
      _ <- untilComma flagsField
      pure ()
    False -> pure ()
  let flags = 0
  ipProtocol <- untilComma ipProtocolField
  action <- untilComma actionField
  Bytes{array=miscellaneousByteArray,offset=miscOff,length=miscLen} <-
    parserOptionallyQuoted miscellaneousField
  let miscellaneousBounds = Bounds miscOff miscLen
  -- Detect presence of threat name and id by looking for trailing
  -- close paren on field.
  threatIdCursor <- Unsafe.cursor
  Bounds threatIdOff threatIdLen <- untilComma threatIdField
  Unsafe.jump threatIdCursor
  (threatName,threatId) <- case Bytes.isByteSuffixOf 0x29 (Bytes message threatIdOff threatIdLen) of
    True -> parserThreatId
    False -> pure (Bounds threatIdOff 0, 0)
  category <-
    if | version < 100 || isUrl == 1 -> untilComma categoryField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bounds off 0)
  severity <- untilComma severityField
  direction <- untilComma directionField
  sequenceNumber <- w64Comma sequenceNumberField
  -- Note: Action flags are ignored. See note on Flags as well.
  Latin.trySatisfy (=='0') >>= \case
    True -> do
      Latin.char actionFlagsField 'x'
      _ <- untilComma actionFlagsField
      pure ()
    False -> pure ()
  let actionFlags = 0
  sourceCountry <- untilComma sourceCountryField
  destinationCountry <- untilComma destinationCountryField
  -- This future use is always either zero or empty before PAN-OS 10.x,
  -- and in newer versions it is suppressed entirely. However, the
  -- following field is content_type, which never starts with zero. 
  if | version >= 100, isUrl == 1 -> pure ()
     | version >= 100, isSpyware == 1 -> do
         -- I cannot figure out why, in PAN-OS 10, there is an extra field
         -- in spyware logs.
         Latin.skipDigits1 futureUseEField
         Latin.char2 futureUseEField ',' ','
     | otherwise -> do
         Latin.skipDigits
         Latin.char futureUseEField ','
  -- In PAN-OS 10.x, content_type only shows up in URL logs.
  -- I've added spyware here as well, but I'm not sure if this
  -- is correct. Content type definitely does not show up in
  -- wildfire logs.
  contentType <-
    if | version < 100 || isUrl == 1 || isSpyware == 1 -> untilComma contentTypeField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bounds off 0)
  -- Wildfire logs in PAN-OS 10.x do not have a pcap_id field.
  pcapId <-
    if | version < 100 || isUrl == 1 || isSpyware == 1 -> w64Comma pcapIdField
       | otherwise -> pure 0
  -- In PAN-OS 10.x, file_digest and cloud only show up in wildfire logs.
  fileDigest <-
    if | version < 100 || isWildfire == 1 || isSpyware == 1 -> untilComma fileDigestField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bounds off 0)
  cloud <-
    if | version < 100 || isWildfire == 1 || isSpyware == 1 -> untilComma cloudField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bounds off 0)
  urlIndex <-
    if | version < 100 || isUrl == 1 || isWildfire == 1 -> w64Comma urlIndexField
       | otherwise -> pure 0
  Bytes{array=userAgentByteArray,offset=uaOff,length=uaLen} <-
    if | version < 100 || isUrl == 1 -> parserOptionallyQuoted userAgentField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bytes message off 0)
  let userAgentBounds = Bounds uaOff uaLen
  fileType <-
    if | version < 100 || isWildfire == 1 || isSpyware == 1 -> untilComma fileTypeField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bounds off 0)
  forwardedFor <-
    if | version < 100 || isUrl == 1 -> untilComma forwardedForField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bounds off 0)
  referer <-
    if | version < 100 || isUrl == 1 -> parserOptionallyQuoted refererField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bytes message off 0)
  sender <-
    if | version < 100 || isWildfire == 1 -> parserOptionallyQuoted senderField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bytes message off 0)
  subject <-
    if | version < 100 || isWildfire == 1 -> parserOptionallyQuoted subjectField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bytes message off 0)
  recipient <-
    if | version < 100 || isWildfire == 1 -> parserOptionallyQuoted recipientField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bytes message off 0)
  reportId <-
    if | version < 100 || isWildfire == 1 || isSpyware == 1 -> untilComma reportIdField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bounds off 0)
  deviceGroupHierarchyLevel1 <- w64Comma deviceGroupHierarchyLevel1Field
  deviceGroupHierarchyLevel2 <- w64Comma deviceGroupHierarchyLevel2Field
  deviceGroupHierarchyLevel3 <- w64Comma deviceGroupHierarchyLevel3Field
  deviceGroupHierarchyLevel4 <- w64Comma deviceGroupHierarchyLevel4Field
  virtualSystemName <- untilComma virtualSystemNameField
  deviceName <- untilComma deviceNameField
  -- On PAN-OS 10+, this future use field is omitted.
  when (version < 100) (parserOptionallyQuoted_ futureUseFField)
  skipThroughComma sourceVmUuidField
  skipThroughComma destinationVmUuidField
  httpMethod <-
    if | version < 100 || isUrl == 1 || isSpyware == 1 -> untilComma httpMethodField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bounds off 0)
  tunnelId <- w64Comma tunnelIdField
  skipThroughComma monitorTagField
  parentSessionId <- w64Comma parentSessionIdField
  skipThroughComma parentStartTimeField
  skipThroughComma tunnelTypeField
  threatCategory <- untilComma threatCategoryField
  contentVersion <-
    if | version < 100 -> untilComma contentVersionField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bounds off 0)
  when (version < 100) (skipThroughComma futureUseGField)
  sctpAssociationId <- w64Comma sctpAssociationIdField
  payloadProtocolId <-
    if | version < 100 -> do
           w64Comma payloadProtocolField
       | isUrl == 1 -> do
           w64Comma payloadProtocolField
       | isSpyware == 1 || isWildfire == 1 -> do
           -- In PAN-OS 10.x, this field looks like it is always zero,
           -- represented in hexadecimal, in spyware logs.
           Latin.char4 payloadProtocolField '0' 'x' '0' ','
           pure 0
       | otherwise -> pure 0
  -- TODO: Escape or parse HTTP Headers correctly
  httpHeaders <-
    if | version < 100 || isUrl == 1 -> do
           finalOptionallyQuoted httpHeadersField
       | otherwise -> do
           off <- Unsafe.cursor
           pure (Bytes message off 0)
  -- In PAN-OS 8.1, threat logs end after http headers.
  -- PAN-OS 9.0 adds three more fields.
  P.isEndOfInput >>= \case
    False -> do
      !urlCategoryList <-
        if | version < 100 || isUrl == 1 -> do
               Latin.char urlCategoryListField ','
               parserOptionallyQuoted urlCategoryListField
           | otherwise -> do
               off <- Unsafe.cursor
               pure (Bytes message off 0)
      ruleUuid <- UUID.parserHyphenated ruleUuidField
      Latin.char http2ConnectionField ','
      Latin.skipDigits1 http2ConnectionField
      pure Threat
        { subtype , timeGenerated , sourceAddress , destinationAddress 
        , natSourceIp , natDestinationIp , ruleName , sourceUser 
        , destinationUser , application , virtualSystem , sourceZone 
        , destinationZone , inboundInterface , outboundInterface , logAction 
        , sessionId , repeatCount , sourcePort , destinationPort 
        , natSourcePort , natDestinationPort , ipProtocol 
        , action , category 
        , sequenceNumber , sourceCountry , destinationCountry 
        , deviceGroupHierarchyLevel1 , deviceGroupHierarchyLevel2 
        , deviceGroupHierarchyLevel3 , deviceGroupHierarchyLevel4 
        , virtualSystemName , deviceName , receiveTime
        , serialNumber, actionFlags, flags, message
        , syslogHost, threatId, severity, direction, threatName
        , contentType, pcapId
        , fileDigest, cloud, urlIndex
        , userAgentBounds, sctpAssociationId
        , userAgentByteArray, fileType
        , forwardedFor, referer
        , sender, subject, recipient
        , reportId, httpMethod, contentVersion
        , threatCategory, miscellaneousBounds, miscellaneousByteArray
        , payloadProtocolId, parentSessionId, tunnelId
        , httpHeaders, ruleUuid, urlCategoryList
        }
    True -> pure Threat
      { subtype , timeGenerated , sourceAddress , destinationAddress 
      , natSourceIp , natDestinationIp , ruleName , sourceUser 
      , destinationUser , application , virtualSystem , sourceZone 
      , destinationZone , inboundInterface , outboundInterface , logAction 
      , sessionId , repeatCount , sourcePort , destinationPort 
      , natSourcePort , natDestinationPort , ipProtocol 
      , action , category 
      , sequenceNumber , sourceCountry , destinationCountry 
      , deviceGroupHierarchyLevel1 , deviceGroupHierarchyLevel2 
      , deviceGroupHierarchyLevel3 , deviceGroupHierarchyLevel4 
      , virtualSystemName , deviceName , receiveTime
      , serialNumber, actionFlags, flags, message
      , syslogHost, threatId, severity, direction, threatName
      , contentType, pcapId
      , fileDigest, cloud, urlIndex
      , userAgentBounds, sctpAssociationId
      , userAgentByteArray, fileType
      , forwardedFor, referer
      , sender, subject, recipient
      , reportId, httpMethod, contentVersion
      , threatCategory, miscellaneousBounds, miscellaneousByteArray
      , payloadProtocolId, parentSessionId, tunnelId
      , httpHeaders
      , ruleUuid = 0
      , urlCategoryList = Bytes message 0 0
      }

-- Threat IDs are weird. There are three different kinds of
-- strings that can show up here:
--
-- * (9999)
-- * Microsoft RPC Endpoint Mapper Detection(30845)
-- * Windows Executable (EXE)(52020)
--
-- URL logs have a threat id of 9999, and there is no description.
-- Everything else has a human-readable description. Sometimes,
-- this description is suffixed by a space and a parenthesized
-- acronym (EXE, DLL, etc.).
parserThreatId :: Parser Field s (Bounds,Word64)
parserThreatId = Latin.any threatIdField >>= \case
  '(' -> do
    theId <- Latin.decWord64 threatIdField
    Latin.char threatIdField ')'
    Latin.char threatIdField ','
    pure (Bounds 0 0, theId)
  _ -> do
    startSucc <- Unsafe.cursor
    Latin.skipTrailedBy threatIdField '('
    end <- Latin.trySatisfy (\c -> isAsciiUpper c || isAsciiLower c) >>= \case
      True -> do
        endSuccSucc <- Unsafe.cursor
        Latin.skipTrailedBy threatIdField '('
        arr <- Unsafe.expose
        -- We go back an extra character to remove the trailing
        -- space. I do not believe this can lead to negative-length
        -- slices, but the line of reasoning is muddy.
        case indexCharArray arr (endSuccSucc - 3) of
          ' ' -> pure (endSuccSucc - 3)
          _ -> P.fail threatIdField
      False -> do
        endSucc <- Unsafe.cursor
        pure (endSucc - 1)
    theId <- Latin.decWord64 threatIdField
    Latin.char threatIdField ')'
    Latin.char threatIdField ','
    let start = startSucc - 1
    pure (Bounds start (end - start), theId)

indexCharArray :: ByteArray -> Int -> Char
indexCharArray (PM.ByteArray x) (I# i) =
  Exts.C# (Exts.indexCharArray# x i)

