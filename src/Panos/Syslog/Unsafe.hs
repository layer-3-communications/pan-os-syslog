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
  , System(..)
  , User(..)
  , Field(..)
  , Bounds(..)
    -- * Decoding
  , decode
  ) where

import Panos.Syslog.Internal.Common

import Chronos (Datetime)
import Data.Bytes.Parser (Parser)
import Data.Bytes.Types (Bytes(..))
import Panos.Syslog.Internal.Traffic (Traffic(..),parserTraffic)
import Panos.Syslog.Internal.Threat (Threat(..),parserThreat)
import Panos.Syslog.Internal.System (System(..),parserSystem)
import Panos.Syslog.Internal.User (User(..),parserUser)

import qualified Data.Bytes.Parser as P
import qualified Data.Bytes.Parser.Ascii as Ascii
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe

-- | Sum that represents all known PAN-OS syslog types. Use 'decode'
-- to parse a byte sequence into a structured log.
data Log
  = LogTraffic !Traffic
  | LogThreat !Threat
  | LogSystem !System
  | LogUser !User
  | LogOther

untilSpace :: e -> Parser e s Bounds
{-# inline untilSpace #-}
untilSpace e = do
  start <- Unsafe.cursor
  Latin.skipTrailedBy e ' '
  endSucc <- Unsafe.cursor
  let end = endSucc - 1
  pure (Bounds start (end - start))

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
parserPrefix :: Parser Field s (Bounds,Datetime,Bounds)
{-# inline parserPrefix #-}
parserPrefix = do
  Latin.skipChar ' '
  -- We allow the syslog priority (the number in angle brackets)
  -- to be absent.
  Latin.trySatisfy (== '<') >>= \case
    True -> do
      Latin.skipTrailedBy syslogPriorityField '>'
      Latin.skipChar ' '
    False -> pure ()
  Latin.trySatisfy (== '1') >>= \case
    True -> do
      _ <- Latin.char futureUseDField ','
      !recv <- parserDatetime receiveTimeDateField receiveTimeTimeField
      !ser <- untilComma serialNumberField
      pure (Bounds 0 0,recv,ser)
    False -> do
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
      !ser <- untilComma serialNumberField
      pure (hostBounds,recv,ser)

-- | Decode a PAN-OS syslog message of an unknown type.
decode :: Bytes -> Either Field Log
decode b = case P.parseBytes parserLog b of
  P.Failure e -> Left e
  P.Success (P.Slice _ len r) -> case len of
    0 -> Right r
    _ -> Left leftoversField

parserLog :: Parser Field s Log
parserLog = do
  (!hostBounds,!receiveTime,!serialNumber) <- parserPrefix
  Latin.any typeField >>= \case
    'U' -> do
      Latin.char6 typeField 'S' 'E' 'R' 'I' 'D' ','
      !x <- parserUser hostBounds receiveTime serialNumber
      pure (LogUser x)
    'S' -> do
      Latin.char6 typeField 'Y' 'S' 'T' 'E' 'M' ','
      !x <- parserSystem hostBounds receiveTime serialNumber
      pure (LogSystem x)
    'T' -> Latin.any typeField >>= \case
      'R' -> do
        Latin.char6 typeField 'A' 'F' 'F' 'I' 'C' ','
        !x <- parserTraffic hostBounds receiveTime serialNumber
        pure (LogTraffic x)
      'H' -> do
        Latin.char5 typeField 'R' 'E' 'A' 'T' ','
        !x <- parserThreat hostBounds receiveTime serialNumber
        pure (LogThreat x)
      _ -> P.fail typeField
    _ -> P.fail typeField


