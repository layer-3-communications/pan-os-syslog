{-# language BangPatterns #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language DuplicateRecordFields #-}
{-# language NumericUnderscores #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}

module Panos.Syslog.System
  ( description
  , deviceName
  , eventId
  , module_
  , object
  , severity
  , subtype
  , timeGenerated
  ) where

import Data.Bytes.Types (Bytes(..))
import Panos.Syslog.Unsafe (System(System),Bounds(Bounds))
import Chronos (Datetime)
import qualified Panos.Syslog.Unsafe as U

subtype :: System -> Bytes
subtype (System{subtype=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

deviceName :: System -> Bytes
deviceName (System{deviceName=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

object :: System -> Bytes
object (System{object=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

module_ :: System -> Bytes
module_ (System{module_=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

severity :: System -> Bytes
severity (System{severity=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

eventId :: System -> Bytes
eventId (System{eventId=Bounds off len,message=msg}) =
  Bytes{offset=off,length=len,array=msg}

description :: System -> Bytes
description (System{descriptionBounds=Bounds off len,descriptionByteArray=m}) =
  Bytes{offset=off,length=len,array=m}

timeGenerated :: System -> Datetime
timeGenerated = U.timeGenerated
