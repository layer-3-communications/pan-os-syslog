{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language DuplicateRecordFields #-}
{-# language NumericUnderscores #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}

module Panos.Syslog.Threat
  ( deviceName
  , threatCategory
  , miscellaneous
  , virtualSystemName
  , contentVersion
  , threatId
  , threatName
  ) where

import Data.Bytes.Types (Bytes(..))
import Panos.Syslog.Unsafe (Threat(Threat),Bounds(Bounds))
import Data.Word (Word64)
import qualified Panos.Syslog.Unsafe as U

deviceName :: Threat -> Bytes
deviceName (Threat{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

threatName :: Threat -> Bytes
threatName (Threat{threatName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

threatId :: Threat -> Word64
threatId = U.threatId

contentVersion :: Threat -> Bytes
contentVersion (Threat{contentVersion=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

virtualSystemName :: Threat -> Bytes
virtualSystemName (Threat{virtualSystemName=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

threatCategory :: Threat -> Bytes
threatCategory (Threat{threatCategory=Bounds off len,message=msg}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=msg}

miscellaneous :: Threat -> Bytes
miscellaneous (Threat{miscellaneousBounds=Bounds off len,miscellaneousByteArray=m}) =
  Bytes{offset=fromIntegral off,length=fromIntegral len,array=m}

