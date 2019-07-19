{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language DuplicateRecordFields #-}
{-# language NumericUnderscores #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}

module Panos.Syslog.Unsafe
  ( -- * Types
    Log(..)
  , Traffic(..)
  , Field(..)
  , Bounds(..)
    -- * Decoding
  , decodeLog
  ) where

import Data.Bytes.Types (UnmanagedBytes(UnmanagedBytes))
import Data.Primitive (ByteArray)
import Data.Primitive.Addr (Addr(Addr))
import Chronos (Year(..),Month(..),Datetime(..),TimeOfDay(..))
import Chronos (DayOfMonth(..),Date(..))
import Data.Bytes.Parser (Parser)
import Data.Word (Word64,Word32,Word16,Word,Word8)
import Net.Types (IPv4,IP)
import GHC.Exts (Ptr(Ptr),Int(I#),Int#,Addr#)
import Control.Exception (Exception)
import qualified Control.Exception
import qualified Data.Primitive as PM
import qualified Data.Primitive.Ptr as PM
import qualified Net.IP as IP
import qualified Net.IPv4 as IPv4
import qualified Data.Bytes.Parser as P
import qualified GHC.Pack

data Log
  = LogTraffic !Traffic
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
  , deviceGroupHierarchyLevel1 :: {-# UNPACK #-} !Bounds
  , deviceGroupHierarchyLevel2 :: {-# UNPACK #-} !Bounds
  , deviceGroupHierarchyLevel3 :: {-# UNPACK #-} !Bounds
  , deviceGroupHierarchyLevel4 :: {-# UNPACK #-} !Bounds
  , virtualSystemName :: {-# UNPACK #-} !Bounds
  , deviceName :: {-# UNPACK #-} !Bounds
  , actionSource :: {-# UNPACK #-} !Bounds
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
  start <- P.cursor
  P.skipUntilAsciiConsume e ' '
  end <- P.cursor
  pure (Bounds start ((end - start) - 1))

untilComma :: e -> Parser e s Bounds
{-# inline untilComma #-}
untilComma e = do
  start <- P.cursor
  P.skipUntilAsciiConsume e ','
  end <- P.cursor
  pure (Bounds start ((end - start) - 1))

skipThroughComma :: e -> Parser e s ()
{-# inline skipThroughComma #-}
skipThroughComma e = P.skipUntilAsciiConsume e ','

-- This does not require that any digits are
-- actually present.
skipDigitsThroughComma :: e -> Parser e s ()
{-# inline skipDigitsThroughComma #-}
skipDigitsThroughComma e =
  P.skipDigitsAscii *> P.ascii e ','

w64Comma :: e -> Parser e s Word64
{-# inline w64Comma #-}
w64Comma e = do
  w <- P.decWord e
  P.ascii e ','
  pure (fromIntegral w)

w16Comma :: e -> Parser e s Word16
{-# inline w16Comma #-}
w16Comma e = P.decWord16 e <* P.ascii e ','

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
  P.ascii syslogPriorityField '<'
  P.skipUntilAsciiConsume syslogPriorityField '>'
  P.skipAscii ' '
  P.skipAlphaAscii1 syslogDatetimeField -- Month
  P.skipAscii1 syslogDatetimeField ' '
  P.skipDigitsAscii1 syslogDatetimeField -- Day
  P.skipAscii1 syslogDatetimeField ' '
  P.skipDigitsAscii1 syslogDatetimeField -- Hour
  P.ascii syslogDatetimeField ':'
  P.skipDigitsAscii1 syslogDatetimeField -- Minute
  P.ascii syslogDatetimeField ':'
  P.skipDigitsAscii1 syslogDatetimeField -- Second
  P.skipAscii1 syslogDatetimeField ' '
  hostBounds <- untilSpace syslogHostField
  P.skipAscii ' '
  skipThroughComma futureUseDField
  !recv <- parserDatetime receiveTimeDateField receiveTimeTimeField
  !ser <- fromIntegral <$> P.decWord serialNumberField
  P.ascii serialNumberField ','
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
      P.Success r _ len -> case len of
        0 -> Right r
        _ -> Left leftoversField
  | otherwise = Left tooBigField

parserLog :: Parser Field s Log
parserLog = do
  (!hostBounds,!receiveTime,!serialNumber) <- parserPrefix
  P.ascii typeField 'T'
  P.ascii typeField 'R'
  P.ascii typeField 'A'
  P.ascii typeField 'F'
  P.ascii typeField 'F'
  P.ascii typeField 'I'
  P.ascii typeField 'C'
  P.ascii typeField ','
  !x <- parserTraffic hostBounds receiveTime serialNumber
  pure (LogTraffic x)

parserTraffic :: Bounds -> Datetime -> Word64 -> Parser Field s Traffic
parserTraffic syslogHost receiveTime serialNumber = do
  subtype <- untilComma subtypeField
  skipThroughComma futureUseAField
  timeGenerated <- parserDatetime timeGeneratedDateField timeGeneratedTimeField
  -- TODO: get the four ip addresseses
  sourceAddress <- IP.fromIPv4 <$> parserIPv4 sourceAddressField
  destinationAddress <- IP.fromIPv4 <$> parserIPv4 destinationAddressField
  natSourceIp <- IP.fromIPv4 <$> parserIPv4 natSourceIpField
  natDestinationIp <- IP.fromIPv4 <$> parserIPv4 natDestinationIpField
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
  P.ascii actionFlagsField '0'
  P.ascii actionFlagsField 'x'
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
  P.ascii actionFlagsField '0'
  P.ascii actionFlagsField 'x'
  _ <- untilComma actionFlagsField
  let actionFlags = 0
  sourceCountry <- untilComma sourceCountryField
  destinationCountry <- untilComma destinationCountryField
  skipThroughComma futureUseEField
  packetsSent <- w64Comma packetsSentField
  packetsReceived <- w64Comma packetsReceivedField
  sessionEndReason <- untilComma sessionEndReasonField
  deviceGroupHierarchyLevel1 <- untilComma deviceGroupHierarchyLevel1Field
  deviceGroupHierarchyLevel2 <- untilComma deviceGroupHierarchyLevel2Field
  deviceGroupHierarchyLevel3 <- untilComma deviceGroupHierarchyLevel3Field
  deviceGroupHierarchyLevel4 <- untilComma deviceGroupHierarchyLevel4Field
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
  P.skipDigitsAscii1 sctpChunksReceivedField
  message <- P.expose
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

parserIPv4 :: e -> Parser e s IPv4
parserIPv4 e = do
  !a <- P.decWord8 e
  P.ascii e '.'
  !b <- P.decWord8 e
  P.ascii e '.'
  !c <- P.decWord8 e
  P.ascii e '.'
  !d <- P.decWord8 e
  P.ascii e ','
  pure (IPv4.fromOctets a b c d)

parserDatetime :: e -> e -> Parser e s Datetime
{-# noinline parserDatetime #-}
parserDatetime edate etime = do
  year <- P.decWord edate
  P.ascii edate '/'
  month <- P.decWord edate
  P.ascii edate '/'
  day <- P.decWord edate
  P.ascii etime ' '
  hour <- P.decWord etime
  P.ascii etime ':'
  minute <- P.decWord etime
  P.ascii etime ':'
  second <- P.decWord etime
  P.ascii etime ','
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
