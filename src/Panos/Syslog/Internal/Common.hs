{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language DuplicateRecordFields #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language LambdaCase #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
{-# language ScopedTypeVariables #-}
module Panos.Syslog.Internal.Common
  ( -- * Parsers
    untilComma
  , skipDigitsThroughComma
  , skipThroughComma
  , w64Comma
  , w16Comma
  , parserDatetime
  , parserOptionallyQuoted
  , parserOptionallyQuoted_
  , finalOptionallyQuoted
    -- * Types
  , Field(..)
  , Bounds(..)
    -- * Fields
  , actionField
  , actionFlagsField
  , actionSourceField
  , applicationField
  , bytesField
  , bytesReceivedField
  , bytesSentField
  , categoryField
  , cloudField
  , contentTypeField
  , contentVersionField
  , dataSourceField
  , dataSourceNameField
  , dataSourceTypeField
  , descriptionField
  , destinationAddressField
  , destinationCountryField
  , destinationPortField
  , destinationUserField
  , destinationVmUuidField
  , destinationZoneField
  , deviceGroupHierarchyLevel1Field
  , deviceGroupHierarchyLevel2Field
  , deviceGroupHierarchyLevel3Field
  , deviceGroupHierarchyLevel4Field
  , deviceNameField
  , directionField
  , elapsedTimeField
  , eventIdField
  , evidenceField
  , fileDigestField
  , fileTypeField
  , flagsField
  , forwardedForField
  , futureUseAField
  , futureUseBField
  , futureUseCField
  , futureUseDField
  , futureUseEField
  , futureUseFField
  , futureUseGField
  , http2ConnectionField
  , httpHeadersField
  , httpMethodField
  , inboundInterfaceField
  , ipField
  , ipProtocolField
  , leftoversField
  , linkChangeCountField
  , logActionField
  , miscellaneousField
  , moduleField
  , monitorTagField
  , natDestinationIpField
  , natDestinationPortField
  , natSourceIpField
  , natSourcePortField
  , objectField
  , objectIdField
  , objectNameField
  , outboundInterfaceField
  , packetsField
  , packetsReceivedField
  , packetsSentField
  , parentSessionIdField
  , parentStartTimeField
  , payloadProtocolField
  , pcapIdField
  , prismaDataField
  , receiveTimeDateField
  , receiveTimeTimeField
  , recipientField
  , refererField
  , repeatCountField
  , reportIdField
  , ruleNameField
  , ruleUuidField
  , sctpAssociationIdField
  , sctpChunksField
  , sctpChunksReceivedField
  , sctpChunksSentField
  , senderField
  , sequenceNumberField
  , serialNumberField
  , sessionEndReasonField
  , sessionIdField
  , severityField
  , sourceAddressField
  , sourceCountryField
  , sourceIpField
  , sourcePortField
  , sourceUserField
  , sourceVmUuidField
  , sourceZoneField
  , startTimeDateField
  , startTimeTimeField
  , subjectField
  , subtypeField
  , syslogDatetimeField
  , syslogHostField
  , syslogPriorityField
  , threatCategoryField
  , threatIdField
  , timeGeneratedDateField
  , timeGeneratedTimeField
  , timeoutField
  , tunnelIdField
  , tunnelTypeField
  , typeField
  , urlCategoryListField
  , urlIndexField
  , userAgentField
  , userField
  , virtualSystemField
  , virtualSystemIdField
  , virtualSystemNameField
  ) where

import Chronos (DayOfMonth(..),Date(..),Offset(..),OffsetDatetime(..))
import Chronos (Year(..),Month(..),Datetime(..),TimeOfDay(..))
import Control.Exception (Exception)
import Control.Monad.ST.Run (runByteArrayST)
import Data.Bytes.Parser (Parser)
import Data.Bytes.Types (Bytes(..),UnmanagedBytes(UnmanagedBytes))
import Data.Char (ord)
import Data.Primitive (ByteArray)
import Data.Primitive.Addr (Addr(Addr))
import Data.Word (Word64,Word16,Word8)
import GHC.Exts (Ptr(Ptr),Int(I#),Int#,Addr#)

import qualified Chronos
import qualified Control.Exception
import qualified Data.Primitive as PM
import qualified Data.Primitive.Ptr as PM
import qualified Data.Bytes.Parser as P
import qualified Data.Bytes.Parser.Unsafe as Unsafe
import qualified Data.Bytes.Parser.Latin as Latin
import qualified GHC.Pack

-- In PAN-OS 10, datetimes started being encoded with ISO-8601
-- rather than with the YYYY/MM/DD HH:mm:ss scheme. So, we
-- allow either.
parserDatetime :: e -> e -> Parser e s Datetime
{-# noinline parserDatetime #-}
parserDatetime edate etime = do
  _ <- P.take edate 4
  Latin.any edate >>= \case
    '-' -> do
      Unsafe.unconsume 5
      OffsetDatetime t (Offset f) <- P.orElse Chronos.parserUtf8BytesIso8601 (P.fail edate)
      Latin.char etime ','
      case f of
        0 -> pure t
        _ -> P.fail edate
    '/' -> do
      Unsafe.unconsume 5
      year <- Latin.decWord edate
      Latin.char edate '/'
      monthPlusOne <- Latin.decWord edate
      let month = monthPlusOne - 1
      if month > 11
        then P.fail edate
        else pure ()
      Latin.char edate '/'
      day <- Latin.decWord edate
      Latin.char etime ' '
      hour <- Latin.decWord etime
      Latin.char etime ':'
      minute <- Latin.decWord etime
      Latin.char etime ':'
      second <- Latin.decWord etime
      Latin.char etime ','
      pure $ Datetime
        (Date
          (Year (fromIntegral year))
          (Month (fromIntegral month))
          (DayOfMonth (fromIntegral day))
        )
        (TimeOfDay
          (fromIntegral hour)
          (fromIntegral minute)
          (1_000_000_000 * fromIntegral second)
        )
    _ -> P.fail edate

-- This does not require that any digits are
-- actually present.
skipDigitsThroughComma :: e -> Parser e s ()
{-# inline skipDigitsThroughComma #-}
skipDigitsThroughComma e =
  Latin.skipDigits *> Latin.char e ','

skipThroughComma :: e -> Parser e s ()
{-# inline skipThroughComma #-}
skipThroughComma e = Latin.skipTrailedBy e ','

w64Comma :: e -> Parser e s Word64
{-# inline w64Comma #-}
w64Comma e = do
  w <- Latin.decWord64 e
  Latin.char e ','
  pure w

w16Comma :: e -> Parser e s Word16
{-# inline w16Comma #-}
w16Comma e = Latin.decWord16 e <* Latin.char e ','


untilComma :: e -> Parser e s Bounds
{-# inline untilComma #-}
untilComma e = do
  start <- Unsafe.cursor
  Latin.skipTrailedBy e ','
  endSucc <- Unsafe.cursor
  let end = endSucc - 1
  pure (Bounds start (end - start))

data Bounds = Bounds
  {-# UNPACK #-} !Int -- offset
  {-# UNPACK #-} !Int -- length


-- | The field that was being parsed when a parse failure occurred.
-- This is typically for useful for libary developers, but to present
-- it to the end user, call @show@ or @throwIO@.
newtype Field = Field UnmanagedBytes

instance Show Field where
  showsPrec _ (Field (UnmanagedBytes (Addr addr) _)) s =
    '"' : GHC.Pack.unpackAppendCString# addr ('"' : s)

instance Exception Field where
  displayException (Field (UnmanagedBytes (Addr addr) _)) =
    GHC.Pack.unpackCString# addr

syslogPriorityField :: Field
syslogPriorityField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "syslogPriority"#

syslogHostField :: Field
syslogHostField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "syslogHost"#

syslogDatetimeField :: Field
syslogDatetimeField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "syslogDatetime"#

prismaDataField :: Field
prismaDataField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "prismaData"#

receiveTimeDateField :: Field
receiveTimeDateField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "receiveTime:date"#

receiveTimeTimeField :: Field
receiveTimeTimeField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "receiveTime:time"#

serialNumberField :: Field
serialNumberField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "serialNumber"#

typeField :: Field
typeField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "type"#

subtypeField :: Field
subtypeField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "subtype"#

timeGeneratedDateField :: Field
timeGeneratedDateField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "timeGenerated:date"#

timeGeneratedTimeField :: Field
timeGeneratedTimeField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "timeGenerated:time"#

sourceAddressField :: Field
sourceAddressField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "sourceAddress"#

destinationAddressField :: Field
destinationAddressField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "destinationAddress"#

natSourceIpField :: Field
natSourceIpField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "natSourceIp"#

natDestinationIpField :: Field
natDestinationIpField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "natDestinationIp"#

ruleNameField :: Field
ruleNameField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "ruleName"#

sourceUserField :: Field
sourceUserField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "sourceUser"#

destinationUserField :: Field
destinationUserField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "destinationUser"#

applicationField :: Field
applicationField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "application"#

virtualSystemField :: Field
virtualSystemField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "virtualSystem"#

sourceZoneField :: Field
sourceZoneField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "sourceZone"#

destinationZoneField :: Field
destinationZoneField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "destinationZone"#

inboundInterfaceField :: Field
inboundInterfaceField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "inboundInterface"#

outboundInterfaceField :: Field
outboundInterfaceField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "outboundInterface"#

logActionField :: Field
logActionField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "logAction"#

sessionIdField :: Field
sessionIdField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "sessionId"#

repeatCountField :: Field
repeatCountField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "repeatCount"#

sourcePortField :: Field
sourcePortField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "sourcePort"#

destinationPortField :: Field
destinationPortField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "destinationPort"#

natSourcePortField :: Field
natSourcePortField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "natSourcePort"#

natDestinationPortField :: Field
natDestinationPortField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "natDestinationPort"#

flagsField :: Field
flagsField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "flags"#

ipProtocolField :: Field
ipProtocolField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "ipProtocol"#

urlCategoryListField :: Field
urlCategoryListField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "urlCategoryList"#

actionField :: Field
actionField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "action"#

bytesField :: Field
bytesField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "bytes"#

bytesSentField :: Field
bytesSentField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "bytesSent"#

bytesReceivedField :: Field
bytesReceivedField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "bytesReceived"#

packetsField :: Field
packetsField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "packets"#

startTimeDateField :: Field
startTimeDateField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "startTime:date"#

startTimeTimeField :: Field
startTimeTimeField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "startTime:time"#

elapsedTimeField :: Field
elapsedTimeField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "elapsedTime"#

categoryField :: Field
categoryField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "category"#

sequenceNumberField :: Field
sequenceNumberField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "sequenceNumber"#

actionFlagsField :: Field
actionFlagsField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "actionFlags"#

sourceCountryField :: Field
sourceCountryField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "sourceCountry"#

destinationCountryField :: Field
destinationCountryField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "destinationCountry"#

packetsSentField :: Field
packetsSentField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "packetsSent"#

packetsReceivedField :: Field
packetsReceivedField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "packetsReceived"#

sessionEndReasonField :: Field
sessionEndReasonField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "sessionEndReason"#

deviceGroupHierarchyLevel1Field :: Field
deviceGroupHierarchyLevel1Field = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "deviceGroupHierarchyLevel1"#

deviceGroupHierarchyLevel2Field :: Field
deviceGroupHierarchyLevel2Field = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "deviceGroupHierarchyLevel2"#

deviceGroupHierarchyLevel3Field :: Field
deviceGroupHierarchyLevel3Field = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "deviceGroupHierarchyLevel3"#

deviceGroupHierarchyLevel4Field :: Field
deviceGroupHierarchyLevel4Field = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "deviceGroupHierarchyLevel4"#

virtualSystemNameField :: Field
virtualSystemNameField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "virtualSystemName"#

payloadProtocolField :: Field
payloadProtocolField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:payloadProtocol"#

senderField :: Field
senderField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:sender"#

recipientField :: Field
recipientField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:recipient"#

refererField :: Field
refererField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:referer"#

pcapIdField :: Field
pcapIdField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:pcapId"#

directionField :: Field
directionField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:direction"#

contentTypeField :: Field
contentTypeField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:contentType"#

severityField :: Field
severityField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:severity"#

cloudField :: Field
cloudField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:cloud"#

threatCategoryField :: Field
threatCategoryField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:threatCategory"#

urlIndexField :: Field
urlIndexField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:urlIndex"#

fileDigestField :: Field
fileDigestField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:fileDigest"#

fileTypeField :: Field
fileTypeField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:fileType"#

forwardedForField :: Field
forwardedForField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:forwardedFor"#

userAgentField :: Field
userAgentField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:userAgent"#

subjectField :: Field
subjectField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:subject"#

contentVersionField :: Field
contentVersionField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:contentVersion"#

httpMethodField :: Field
httpMethodField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:httpMethod"#

httpHeadersField :: Field
httpHeadersField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:httpHeaders"#

reportIdField :: Field
reportIdField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:reportId"#

miscellaneousField :: Field
miscellaneousField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:miscellaneous"#

threatIdField :: Field
threatIdField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:threatId"#

deviceNameField :: Field
deviceNameField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "deviceName"#

actionSourceField :: Field
actionSourceField = Field (UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "actionSource"#

futureUseAField :: Field
futureUseAField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "futureUse:A"#

futureUseBField :: Field
futureUseBField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "futureUse:B"#

futureUseCField :: Field
futureUseCField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "futureUse:C"#

futureUseDField :: Field
futureUseDField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "futureUse:D"#

futureUseEField :: Field
futureUseEField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "futureUse:E"#

futureUseFField :: Field
futureUseFField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "futureUse:F"#

futureUseGField :: Field
futureUseGField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "futureUse:G"#

leftoversField :: Field
leftoversField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "framing:leftovers"#

sourceVmUuidField :: Field
sourceVmUuidField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:source_uuid"#

destinationVmUuidField :: Field
destinationVmUuidField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:dst_uuid"#

tunnelIdField :: Field
tunnelIdField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:tunnelid"#

monitorTagField :: Field
monitorTagField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:monitortag"#

parentSessionIdField :: Field
parentSessionIdField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:parent_session_id"#

parentStartTimeField :: Field
parentStartTimeField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:parent_start_time"#

tunnelTypeField :: Field
tunnelTypeField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:tunnel"#

sctpAssociationIdField :: Field
sctpAssociationIdField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:assoc_id"#

sctpChunksField :: Field
sctpChunksField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:chunks"#

sctpChunksSentField :: Field
sctpChunksSentField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:chunks_sent"#

sctpChunksReceivedField :: Field
sctpChunksReceivedField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:chunks_received"#

ruleUuidField :: Field
ruleUuidField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:rule_uuid"#

http2ConnectionField :: Field
http2ConnectionField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:http_2_connection"#

linkChangeCountField :: Field
linkChangeCountField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "field:link_change_count_field"#

moduleField :: Field
moduleField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:module"#

descriptionField :: Field
descriptionField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:description"#

eventIdField :: Field
eventIdField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:eventId"#

objectField :: Field
objectField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:object"#

userField :: Field
userField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:user"#

dataSourceNameField :: Field
dataSourceNameField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:datasourcename"#

timeoutField :: Field
timeoutField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:timeout"#

ipField :: Field
ipField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:ip"#

dataSourceField :: Field
dataSourceField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:datasource"#

dataSourceTypeField :: Field
dataSourceTypeField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:datasourcetype"#

sourceIpField :: Field
sourceIpField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:source_ip"#

evidenceField :: Field
evidenceField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:evidence"#

objectIdField :: Field
objectIdField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:objectid"#

objectNameField :: Field
objectNameField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:objectname"#

virtualSystemIdField :: Field
virtualSystemIdField = Field ( UnmanagedBytes (Addr x#) (I# ( cstringLen# x#)))
  where !x# = "field:virtualsystemid"#

-- TODO: switch to the known-key cstrlen that comes with GHC 
cstringLen# :: Addr# -> Int#
{-# noinline cstringLen# #-}
cstringLen# ptr = go 0 where
  go !ix@(I# ix#) = if PM.indexOffPtr (Ptr ptr) ix == (0 :: Word8)
    then ix#
    else go (ix + 1)

parserOptionallyQuoted_ :: e -> Parser e s ()
parserOptionallyQuoted_ e = Latin.any e >>= \case
  '"' -> do
    _ <- consumeQuoted e 0
    pure ()
  ',' -> pure ()
  _ -> Latin.skipTrailedBy e ','

-- Precondition: the cursor is placed at the beginning of the
-- possibly-quoted content. That is, the comma preceeding has
-- already been consumed. This is very similar to parserOptionallyQuoted,
-- but it differs slightly because might not be a trailing comma. If
-- there is, it gets left alone.
finalOptionallyQuoted :: e -> Parser e s Bytes
finalOptionallyQuoted e = Latin.opt >>= \case
  Nothing -> do
    !array <- Unsafe.expose
    pure $! Bytes{array,offset=0,length=0}
  Just c -> case c of
    '"' -> do
      -- First, we do a run through just to see if anything
      -- actually needs to be escaped.
      start <- Unsafe.cursor
      !n <- consumeFinalQuoted e 0
      !array <- Unsafe.expose
      !endSucc <- Unsafe.cursor
      let end = endSucc - 1
      if n == 0
        then pure Bytes{array,offset=start,length=(end - start)}
        else do
          let !r = escapeQuotes Bytes{array,offset=start,length=(end - start)}
          pure $! Bytes{array=r,offset=0,length=PM.sizeofByteArray r}
    ',' -> do
      Unsafe.unconsume 1
      !arr <- Unsafe.expose
      pure $! Bytes arr 0 0
    _ -> do
      !startSucc <- Unsafe.cursor
      Latin.skipUntil ','
      !end <- Unsafe.cursor
      !arr <- Unsafe.expose
      let start = startSucc - 1
      pure $! Bytes arr start (end - start)

-- Precondition: the cursor is placed at the beginning of the
-- possibly-quoted content. That is, the comma preceeding has
-- already been consumed.
parserOptionallyQuoted :: e -> Parser e s Bytes
parserOptionallyQuoted e = Latin.any e >>= \case
  '"' -> do
    -- First, we do a run through just to see if anything
    -- actually needs to be escaped.
    start <- Unsafe.cursor
    !n <- consumeQuoted e 0
    !array <- Unsafe.expose
    !endSuccSucc <- Unsafe.cursor
    let end = endSuccSucc - 2
    if n == 0
      then pure Bytes{array,offset=start,length=(end - start)}
      else do
        let !r = escapeQuotes Bytes{array,offset=start,length=(end - start)}
        pure $! Bytes{array=r,offset=0,length=PM.sizeofByteArray r}
  ',' -> do
    !array <- Unsafe.expose
    pure $! Bytes{array,offset=0,length=0}
  _ -> do
    !startSucc <- Unsafe.cursor
    Latin.skipTrailedBy e ','
    !endSucc <- Unsafe.cursor
    !arr <- Unsafe.expose
    let start = startSucc - 1
    let end = endSucc - 1
    pure $! (Bytes arr start (end - start))

-- Precondition: the input is a valid CSV-style quoted-escaped
-- string. That is, any double quote character is guaranteed to
-- be followed by another one.
escapeQuotes :: Bytes -> ByteArray
escapeQuotes (Bytes arr off0 len0) = runByteArrayST $ do
  marr <- PM.newByteArray len0
  let go !soff !doff !len = if len > 0
        then do
          let w :: Word8 = PM.indexByteArray arr soff
          PM.writeByteArray marr doff w
          if w /= c2w '"'
            then go (soff + 1) (doff + 1) (len - 1)
            else go (soff + 2) (doff + 1) (len - 2)
        else pure doff
  finalSz <- go off0 0 len0
  marr' <- PM.resizeMutableByteArray marr finalSz
  PM.unsafeFreezeByteArray marr'

-- When this parser completed, the position in the input will be
-- just after the comma that followed the quoted field.
-- This is defined recursively.
consumeQuoted ::
     e
  -> Int -- the number of escaped quotes we have encountered
  -> Parser e s Int
consumeQuoted e !n = do
  Latin.skipTrailedBy e '"'
  Latin.any e >>= \case
    ',' -> pure n
    '"' -> consumeQuoted e (n + 1)
    _ -> P.fail e

-- Like consumeQuoted except that we are expected end-of-input
-- instead of a comma at the end.
consumeFinalQuoted ::
     e
  -> Int -- the number of escaped quotes we have encountered
  -> Parser e s Int
consumeFinalQuoted e !n = do
  Latin.skipTrailedBy e '"'
  Latin.opt >>= \case
    Nothing -> pure n
    Just c -> case c of
      '"' -> consumeFinalQuoted e (n + 1)
      ',' -> do
        Unsafe.unconsume 1
        pure n
      _ -> P.fail e

c2w :: Char -> Word8
{-# inline c2w #-}
c2w = fromIntegral . ord
