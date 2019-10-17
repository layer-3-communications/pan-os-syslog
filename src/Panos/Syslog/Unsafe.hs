{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language DuplicateRecordFields #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language LambdaCase #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
{-# language ScopedTypeVariables #-}

module Panos.Syslog.Unsafe
  ( -- * Types
    Log(..)
  , Traffic(..)
  , Threat(..)
  , Field(..)
  , Bounds(..)
    -- * Decoding
  , decodeLog
  ) where

import Chronos (DayOfMonth(..),Date(..))
import Chronos (Year(..),Month(..),Datetime(..),TimeOfDay(..))
import Control.Exception (Exception)
import Control.Monad.ST.Run (runByteArrayST)
import Data.Bytes.Parser (Parser)
import Data.Bytes.Types (Bytes(..),UnmanagedBytes(UnmanagedBytes))
import Data.Char (ord)
import Data.Primitive (ByteArray)
import Data.Primitive.Addr (Addr(Addr))
import Data.Word (Word64,Word32,Word16,Word8)
import GHC.Exts (Ptr(Ptr),Int(I#),Int#,Addr#)
import Net.Types (IP)

import qualified Control.Exception
import qualified Data.Bytes.Parser as P
import qualified Data.Bytes.Parser.Ascii as Ascii
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe
import qualified Data.Primitive as PM
import qualified Data.Primitive.Ptr as PM
import qualified GHC.Pack
import qualified Net.IP as IP
import qualified Net.IPv4 as IPv4

data Log
  = LogTraffic !Traffic
  | LogThreat !Threat
  | LogOther

data Bounds = Bounds
  {-# UNPACK #-} !Int -- offset
  {-# UNPACK #-} !Int -- length

data Traffic = Traffic
  { message :: {-# UNPACK #-} !ByteArray
    -- The original log
  , syslogHost :: {-# UNPACK #-} !Bounds
    -- The host as presented in the syslog preamble that
    -- prefixes the message.
  , receiveTime :: {-# UNPACK #-} !Datetime
    -- In log, presented as: 2019/06/18 15:10:20
  , serialNumber :: {-# UNPACK #-} !Word64
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
  }

data Threat = Threat
  { message :: {-# UNPACK #-} !ByteArray
    -- The original log
  , syslogHost :: {-# UNPACK #-} !Bounds
    -- The host as presented in the syslog preamble that
    -- prefixes the message.
  , receiveTime :: {-# UNPACK #-} !Datetime
    -- In log, presented as: 2019/06/18 15:10:20
  , serialNumber :: {-# UNPACK #-} !Word64
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
  , referer :: {-# UNPACK #-} !Bounds
    -- Only used by url filtering subtype
  , sender :: {-# UNPACK #-} !Bounds
    -- Only used by wildfire subtype
  , subject :: {-# UNPACK #-} !Bounds
    -- Only used by wildfire subtype
  , recipient :: {-# UNPACK #-} !Bounds
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
  }

-- | The field that was being parsed when a parse failure
-- occurred.
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

tooBigField :: Field
tooBigField = Field (UnmanagedBytes (Addr x#) (I# (cstringLen# x#)))
  where !x# = "framing:oversized"#

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

untilSpace :: e -> Parser e s Bounds
{-# inline untilSpace #-}
untilSpace e = do
  start <- Unsafe.cursor
  Latin.skipTrailedBy e ' '
  endSucc <- Unsafe.cursor
  let end = endSucc - 1
  pure (Bounds start (end - start))

untilComma :: e -> Parser e s Bounds
{-# inline untilComma #-}
untilComma e = do
  start <- Unsafe.cursor
  Latin.skipTrailedBy e ','
  endSucc <- Unsafe.cursor
  let end = endSucc - 1
  pure (Bounds start (end - start))

skipThroughComma :: e -> Parser e s ()
{-# inline skipThroughComma #-}
skipThroughComma e = Latin.skipTrailedBy e ','

-- This does not require that any digits are
-- actually present.
skipDigitsThroughComma :: e -> Parser e s ()
{-# inline skipDigitsThroughComma #-}
skipDigitsThroughComma e =
  Latin.skipDigits *> Latin.char e ','

w64Comma :: e -> Parser e s Word64
{-# inline w64Comma #-}
w64Comma e = do
  w <- Latin.decWord64 e
  Latin.char e ','
  pure w

w16Comma :: e -> Parser e s Word16
{-# inline w16Comma #-}
w16Comma e = Latin.decWord16 e <* Latin.char e ','

-- Returns the receive time and the serial number. There is a
-- little subtlety here. The PANOS guide says that logs should
-- start with something like:
--   1,2019/07/14 10:26:22,005923187997
-- The leading field is reserved for future use. However, there
-- is typically an additional prefix consisting of a syslog priority,
-- another datetime (in a different format), and a hostname:
--   <14> Jul 14 11:26:23 MY-HOST.example.com 1,...
-- The datetime is within typically within a second of the other one.
-- Additionally, it's missing the year. So, we discard it. The
-- syslog priority is worthless, so we throw it out as well. The
-- host name, however, does provide useful information that does
-- not exist elsewhere in the log. We should be as flexible
-- as possible with this somewhat fragile part of the log.
parserPrefix :: Parser Field s (Bounds,Datetime,Word64)
{-# inline parserPrefix #-}
parserPrefix = do
  Latin.char syslogPriorityField '<'
  Latin.skipTrailedBy syslogPriorityField '>'
  Latin.skipChar ' '
  Ascii.skipAlpha1 syslogDatetimeField -- Month
  Latin.skipChar1 syslogDatetimeField ' '
  Latin.skipDigits1 syslogDatetimeField -- Day
  Latin.skipChar1 syslogDatetimeField ' '
  Latin.skipDigits1 syslogDatetimeField -- Hour
  Latin.char syslogDatetimeField ':'
  Latin.skipDigits1 syslogDatetimeField -- Minute
  Latin.char syslogDatetimeField ':'
  Latin.skipDigits1 syslogDatetimeField -- Second
  Latin.skipChar1 syslogDatetimeField ' '
  hostBounds <- untilSpace syslogHostField
  Latin.skipChar ' '
  skipThroughComma futureUseDField
  !recv <- parserDatetime receiveTimeDateField receiveTimeTimeField
  !ser <- fromIntegral <$> Latin.decWord serialNumberField
  Latin.char serialNumberField ','
  pure (hostBounds,recv,ser)

-- | Decode a PAN-OS syslog message. This fails without attempting
-- to parse the message if the 'ByteArray' is has 16384 or more
-- bytes.
decodeLog :: ByteArray -> Either Field Log
decodeLog b
  -- These logs have to fit in a UDP packet, so it is effectively
  -- impossible to receive one that is over 1500 bytes. The hard
  -- cap on size is included to provide a future opportunity to
  -- save space on indices.
  | PM.sizeofByteArray b < 16384 = case P.parseByteArray parserLog b of
      P.Failure e -> Left e
      P.Success (P.Slice _ len r) -> case len of
        0 -> Right r
        _ -> Left leftoversField
  | otherwise = Left tooBigField

parserLog :: Parser Field s Log
parserLog = do
  (!hostBounds,!receiveTime,!serialNumber) <- parserPrefix
  Latin.char typeField 'T'
  Latin.any typeField >>= \case
    'R' -> do
      Latin.char typeField 'A'
      Latin.char typeField 'F'
      Latin.char typeField 'F'
      Latin.char typeField 'I'
      Latin.char typeField 'C'
      Latin.char typeField ','
      !x <- parserTraffic hostBounds receiveTime serialNumber
      pure (LogTraffic x)
    'H' -> do
      Latin.char typeField 'R'
      Latin.char typeField 'E'
      Latin.char typeField 'A'
      Latin.char typeField 'T'
      Latin.char typeField ','
      !x <- parserThreat hostBounds receiveTime serialNumber
      pure (LogThreat x)
    _ -> P.fail typeField

parserTraffic :: Bounds -> Datetime -> Word64 -> Parser Field s Traffic
parserTraffic syslogHost receiveTime serialNumber = do
  subtype <- untilComma subtypeField
  skipThroughComma futureUseAField
  -- The datetime parser consumes the trailing comma
  timeGenerated <- parserDatetime timeGeneratedDateField timeGeneratedTimeField
  sourceAddress <- IP.fromIPv4 <$> IPv4.parserUtf8Bytes sourceAddressField
  Latin.char sourceAddressField ','
  destinationAddress <- IP.fromIPv4 <$> IPv4.parserUtf8Bytes destinationAddressField
  Latin.char destinationAddressField ','
  natSourceIp <- IP.fromIPv4 <$> IPv4.parserUtf8Bytes natSourceIpField
  Latin.char natSourceIpField ','
  natDestinationIp <- IP.fromIPv4 <$> IPv4.parserUtf8Bytes natDestinationIpField
  Latin.char natDestinationIpField ','
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
    , syslogHost
    }

parserThreat :: Bounds -> Datetime -> Word64 -> Parser Field s Threat
parserThreat syslogHost receiveTime serialNumber = do
  subtype <- untilComma subtypeField
  skipThroughComma futureUseAField
  -- the datetime parser also grabs the trailing comma
  timeGenerated <- parserDatetime timeGeneratedDateField timeGeneratedTimeField
  sourceAddress <- IP.fromIPv4 <$> IPv4.parserUtf8Bytes sourceAddressField
  Latin.char sourceAddressField ','
  destinationAddress <- IP.fromIPv4 <$> IPv4.parserUtf8Bytes destinationAddressField
  Latin.char destinationAddressField ','
  natSourceIp <- IP.fromIPv4 <$> IPv4.parserUtf8Bytes natSourceIpField
  Latin.char natSourceIpField ','
  natDestinationIp <- IP.fromIPv4 <$> IPv4.parserUtf8Bytes natDestinationIpField
  Latin.char natDestinationIpField ','
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
  Bytes{array=miscellaneousByteArray,offset=miscOff,length=miscLen} <-
    parserOptionallyQuoted miscellaneousField
  let miscellaneousBounds = Bounds miscOff miscLen
  (threatName,threatId) <- parserThreatId
  category <- untilComma categoryField
  severity <- untilComma severityField
  direction <- untilComma directionField
  sequenceNumber <- w64Comma sequenceNumberField
  -- TODO: handle action flags
  Latin.char actionFlagsField '0'
  Latin.char actionFlagsField 'x'
  _ <- untilComma actionFlagsField
  let actionFlags = 0
  sourceCountry <- untilComma sourceCountryField
  destinationCountry <- untilComma destinationCountryField
  skipThroughComma futureUseEField
  contentType <- untilComma contentTypeField
  pcapId <- w64Comma pcapIdField
  fileDigest <- untilComma fileDigestField
  cloud <- untilComma cloudField
  urlIndex <- w64Comma urlIndexField
  Bytes{array=userAgentByteArray,offset=uaOff,length=uaLen} <-
    parserOptionallyQuoted userAgentField
  let userAgentBounds = Bounds uaOff uaLen
  fileType <- untilComma fileTypeField
  forwardedFor <- untilComma forwardedForField
  referer <- untilComma refererField
  sender <- untilComma senderField
  subject <- untilComma subjectField
  recipient <- untilComma recipientField
  reportId <- untilComma reportIdField
  deviceGroupHierarchyLevel1 <- w64Comma deviceGroupHierarchyLevel1Field
  deviceGroupHierarchyLevel2 <- w64Comma deviceGroupHierarchyLevel2Field
  deviceGroupHierarchyLevel3 <- w64Comma deviceGroupHierarchyLevel3Field
  deviceGroupHierarchyLevel4 <- w64Comma deviceGroupHierarchyLevel4Field
  virtualSystemName <- untilComma virtualSystemNameField
  deviceName <- untilComma deviceNameField
  skipThroughComma futureUseFField
  skipThroughComma sourceVmUuidField
  skipThroughComma destinationVmUuidField
  httpMethod <- untilComma httpMethodField
  tunnelId <- w64Comma tunnelIdField
  skipThroughComma monitorTagField
  parentSessionId <- w64Comma parentSessionIdField
  skipThroughComma parentStartTimeField
  skipThroughComma tunnelTypeField
  threatCategory <- untilComma threatCategoryField
  contentVersion <- untilComma contentVersionField
  skipThroughComma futureUseGField
  sctpAssociationId <- w64Comma sctpAssociationIdField
  payloadProtocolId <- w64Comma payloadProtocolField
  -- TODO: Handle HTTP Headers correctly
  P.endOfInput httpHeadersField
  message <- Unsafe.expose
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
    }

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
    endSucc <- Unsafe.cursor
    theId <- Latin.decWord64 threatIdField
    Latin.char threatIdField ')'
    Latin.char threatIdField ','
    let start = startSucc - 1
        end = endSucc - 1
    pure (Bounds start (end - start), theId)

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

parserDatetime :: e -> e -> Parser e s Datetime
{-# noinline parserDatetime #-}
parserDatetime edate etime = do
  year <- Latin.decWord edate
  Latin.char edate '/'
  month <- Latin.decWord edate
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

cstringLen# :: Addr# -> Int#
{-# noinline cstringLen# #-}
cstringLen# ptr = go 0 where
  go !ix@(I# ix#) = if PM.indexOffPtr (Ptr ptr) ix == (0 :: Word8)
    then ix#
    else go (ix + 1)

c2w :: Char -> Word8
c2w = fromIntegral . ord
