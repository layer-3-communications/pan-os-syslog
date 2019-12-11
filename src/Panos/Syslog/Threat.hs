{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language DuplicateRecordFields #-}
{-# language NumericUnderscores #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}

module Panos.Syslog.Threat
  ( application
  , contentVersion
  , destinationAddress
  , destinationPort
  , destinationUser
  , deviceName
  , httpHeaders
  , httpMethod
  , miscellaneous
  , recipient
  , referer
  , sender
  , sequenceNumber
  , serialNumber
  , severity
  , sourceAddress
  , sourcePort
  , sourceUser
  , subject
  , subtype
  , threatCategory
  , threatId
  , threatName
  , timeGenerated
  , virtualSystemName
  ) where

import Data.Bytes.Types (Bytes(..))
import Panos.Syslog.Unsafe (Threat(Threat),Bounds(Bounds))
import Data.Word (Word64,Word16)
import Chronos (Datetime)
import Net.Types (IP)
import qualified Panos.Syslog.Unsafe as U

subtype :: Threat -> Bytes
subtype (Threat{subtype=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

sourceUser :: Threat -> Bytes
sourceUser (Threat{sourceUser=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

destinationUser :: Threat -> Bytes
destinationUser (Threat{destinationUser=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

deviceName :: Threat -> Bytes
deviceName (Threat{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

threatName :: Threat -> Bytes
threatName (Threat{threatName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

threatId :: Threat -> Word64
threatId = U.threatId

timeGenerated :: Threat -> Datetime
timeGenerated = U.timeGenerated

contentVersion :: Threat -> Bytes
contentVersion (Threat{contentVersion=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

virtualSystemName :: Threat -> Bytes
virtualSystemName (Threat{virtualSystemName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

threatCategory :: Threat -> Bytes
threatCategory (Threat{threatCategory=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

httpHeaders :: Threat -> Bytes
httpHeaders = U.httpHeaders

miscellaneous :: Threat -> Bytes
miscellaneous (Threat{miscellaneousBounds=Bounds off len,miscellaneousByteArray=m}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=m}

sequenceNumber :: Threat -> Word64
sequenceNumber = U.sequenceNumber

serialNumber :: Threat -> Word64
serialNumber = U.serialNumber

severity :: Threat -> Bytes
severity (Threat{severity=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

referer :: Threat -> Bytes
referer = U.referer

httpMethod :: Threat -> Bytes
httpMethod (Threat{httpMethod=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

application :: Threat -> Bytes
application (Threat{application=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

destinationAddress :: Threat -> IP
destinationAddress = U.destinationAddress

sourceAddress :: Threat -> IP
sourceAddress = U.sourceAddress

sourcePort :: Threat -> Word16
sourcePort = U.sourcePort

destinationPort :: Threat -> Word16
destinationPort = U.destinationPort

sender :: Threat -> Bytes
sender = U.sender

subject :: Threat -> Bytes
subject = U.subject

recipient :: Threat -> Bytes
recipient = U.recipient
