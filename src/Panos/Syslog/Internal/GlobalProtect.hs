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

module Panos.Syslog.Internal.GlobalProtect
  ( GlobalProtect(..)
  , parserGlobalProtect
  ) where

import Panos.Syslog.Internal.Common

import Chronos (Datetime)
import Data.Bytes.Parser (Parser)
import Data.Bytes.Types (Bytes(..))
import Data.Primitive (ByteArray)
import Data.Word (Word64)
import Net.Types (IPv4)
import GHC.Ptr (Ptr(Ptr))

import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Parser as Parser
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe
import qualified Net.IPv4 as IPv4

-- | A PAN-OS globalprotect log. Read-only accessors are found in
-- @Panos.Syslog.GlobalProtect@.
data GlobalProtect = GlobalProtect
  { message :: {-# UNPACK #-} !ByteArray
    -- The original log
  , syslogHost :: {-# UNPACK #-} !Bounds
    -- The host as presented in the syslog preamble that
    -- prefixes the message.
  , receiveTime :: {-# UNPACK #-} !Datetime
    -- In log, presented as: 2019/06/18 15:10:20
  , serialNumber :: {-# UNPACK #-} !Bounds
    -- In log, presented as: 002610378847
  , timeGenerated :: {-# UNPACK #-} !Datetime
    -- Presented as: 2019/11/04 08:39:05
  , virtualSystem :: {-# UNPACK #-} !Bounds
  , stage :: {-# UNPACK #-} !Bounds
  , authenticationMethod :: {-# UNPACK #-} !Bounds
  , tunnelType :: {-# UNPACK #-} !Bounds
  , sourceUser :: {-# UNPACK #-} !Bounds
  , machineName :: {-# UNPACK #-} !Bounds
  , publicIp :: {-# UNPACK #-} !IPv4
  , status :: {-# UNPACK #-} !Bounds
  , eventId :: {-# UNPACK #-} !Bounds
  , description :: {-# UNPACK #-} !Bytes
  }

parserGlobalProtect :: Bounds -> Datetime -> Bounds -> Parser Field s GlobalProtect
parserGlobalProtect !syslogHost receiveTime !serialNumber = do
  !message <- Unsafe.expose
  skipThroughComma futureUseAField
  skipThroughComma futureUseBField
  -- The datetime parser consumes the trailing comma
  timeGenerated <- parserDatetime timeGeneratedDateField timeGeneratedTimeField
  virtualSystem <- untilComma virtualSystemField
  eventId <- untilComma eventIdField
  stage <- untilComma stageField
  authenticationMethod <- untilComma authenticationMethodField
  tunnelType <- untilComma tunnelTypeField
  sourceUser <- untilComma sourceUserField
  skipThroughComma futureUseDField
  machineName <- untilComma machineNameField
  publicIp <- IPv4.parserUtf8Bytes publicIpField
  Latin.char publicIpField ','
  skipIp futureUseEField -- ip
  skipIp futureUseFField -- ip
  skipIp futureUseGField -- ip
  skipThroughComma futureUseHField -- host id (usually a mac address)
  skipThroughComma futureUseIField -- client serial number
  skipThroughComma futureUseJField -- client version
  skipThroughComma futureUseKField -- client os
  parserOptionallyQuoted_ futureUseLField
  skipDigitsThroughComma futureUseMField -- repetition count
  skipThroughComma futureUseNField -- reason
  skipThroughComma futureUseOField -- error
  description <- parserOptionallyQuoted futureUsePField
  status <- untilComma statusField
  -- Assert that the status is either "success" or "failure" to help
  -- make sure that we have not lost track of our position.
  do let Bounds start len = status
     let statusBytes = Bytes{offset=start,length=len,array=message}
     if | Bytes.equalsCString (Ptr "success"# ) statusBytes -> pure ()
        | Bytes.equalsCString (Ptr "failure"# ) statusBytes -> pure ()
        | otherwise -> Parser.fail statusField
  pure GlobalProtect
    { message
    , syslogHost
    , receiveTime
    , serialNumber
    , timeGenerated
    , virtualSystem
    , eventId
    , stage
    , authenticationMethod
    , tunnelType
    , sourceUser
    , machineName
    , publicIp
    , status
    , description
    }

