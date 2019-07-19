{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language DuplicateRecordFields #-}
{-# language NumericUnderscores #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}

module Panos.Syslog.Traffic
  ( deviceName
  , packetsReceived
  , bytesReceived
  ) where

import Data.Bytes.Types (Bytes(..))
import Panos.Syslog.Unsafe (Traffic(Traffic),Bounds(Bounds))
import Data.Word (Word64)
import qualified Panos.Syslog.Unsafe as U

deviceName :: Traffic -> Bytes
deviceName (Traffic{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

packetsReceived :: Traffic -> Word64
packetsReceived = U.packetsReceived

bytesReceived :: Traffic -> Word64
bytesReceived = U.bytesReceived

