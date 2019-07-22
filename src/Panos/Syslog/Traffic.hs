{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language DuplicateRecordFields #-}
{-# language NumericUnderscores #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}

module Panos.Syslog.Traffic
  ( bytes
  , bytesReceived
  , bytesSent
  , deviceName
  , packets
  , packetsReceived
  , packetsSent
  , sourceUser
  , destinationUser
  ) where

import Data.Bytes.Types (Bytes(..))
import Panos.Syslog.Unsafe (Traffic(Traffic),Bounds(Bounds))
import Data.Word (Word64)
import qualified Panos.Syslog.Unsafe as U

deviceName :: Traffic -> Bytes
deviceName (Traffic{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

sourceUser :: Traffic -> Maybe Bytes
sourceUser (Traffic{sourceUser=Bounds off len,message=msg}) =
  if len > 0
    then Just Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}
    else Nothing

destinationUser :: Traffic -> Maybe Bytes
destinationUser (Traffic{destinationUser=Bounds off len,message=msg}) =
  if len > 0
    then Just Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}
    else Nothing

packetsReceived :: Traffic -> Word64
packetsReceived = U.packetsReceived

packetsSent :: Traffic -> Word64
packetsSent = U.packetsSent

packets :: Traffic -> Word64
packets = U.packets

bytesReceived :: Traffic -> Word64
bytesReceived = U.bytesReceived

bytesSent :: Traffic -> Word64
bytesSent = U.bytesSent

bytes :: Traffic -> Word64
bytes = U.bytes

