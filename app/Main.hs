{-# language BangPatterns #-}
{-# language DeriveGeneric #-}
{-# language DuplicateRecordFields #-}
{-# language LambdaCase #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
{-# language OverloadedRecordDot #-}
{-# language OverloadedStrings #-}
{-# language PatternSynonyms #-}
{-# language ScopedTypeVariables #-}

import Control.Exception (catchJust)
import Control.Monad.ST.Run (runByteArrayST)
import Control.Monad.Trans.State.Strict (State)
import Data.Bits ((.&.))
import Data.Bool (bool)
import Data.ByteString (ByteString)
import Data.Bytes (Bytes)
import Data.Bytes.Builder (Builder)
import Data.Bytes.Chunks (Chunks(ChunksNil,ChunksCons))
import Data.Char (toUpper)
import Data.Foldable (for_)
import Data.Int (Int64)
import Data.Map.Strict (Map)
import Data.Primitive (ByteArray,SmallMutableArray)
import Data.Primitive (SmallArray)
import Data.Primitive.PrimVar (PrimVar)
import Data.Primitive.PrimVar (readPrimVar,writePrimVar,newPrimVar)
import Data.Text (Text)
import Data.Text.Short (ShortText)
import Data.WideWord (Word128(Word128))
import Foreign.C.Types (CChar)
import GHC.Exts (RealWorld)
import GHC.Generics (Generic)
import Json (pattern (:->))
import Net.Types (IP(IP),IPv6(IPv6))
import Panos.Syslog (Log(LogTraffic),decode)
import Panos.Syslog (Traffic)
import System.Directory (createDirectoryIfMissing)
import System.IO (Handle)
import System.IO.Error (isEOFError)

import qualified Data.Primitive.ByteArray.BigEndian as BigEndian
import qualified Codec.Compression.Zlib.Raw as Deflate
import qualified Data.Primitive as PM
import qualified Data.Primitive.Contiguous as Contiguous
import qualified Data.Map.Strict as Map
import qualified Panos.Syslog.Traffic as Traffic
import qualified Data.Primitive.Ptr as PM
import qualified Data.Bytes.Text.Ascii as Ascii
import qualified Data.ByteString as ByteString
import qualified Data.Bytes as Bytes
import qualified Chronos
import qualified Data.Bytes.Chunks as Chunks
import qualified Data.Bytes.Builder as Builder
import qualified Data.Bytes.Builder.Avro as Avro
import qualified Data.Text as T
import qualified Data.Text.Short as TS
import qualified Control.Monad.Trans.State.Strict as State
import qualified System.IO as IO
import qualified Json
import qualified Data.ByteString.Lazy as LBS
import qualified GHC.Exts as Exts
import qualified Net.IP as IP
import qualified Options.Generic as Opts

data Nullability = Nullable | NonNullable

data Patchedness = Patched | Unpatched

data Atom
  = Signed32
  | Signed64
  | Ip
  | String
  | Timestamp

data Ty
  = Record -- We do not allow records to be nullable
      [Field]
  | Atomic Nullability Atom

data Field = Field
  { name :: !ShortText
    -- ^ Field name must not be the empty string
  , ty :: !Ty
  }

-- x fieldToJson :: Field -> Json.Value
-- x fieldToJson s = case s.ty of
-- x   Record snext -> Json.object3
-- x     ("name" :-> s.name)
-- x     ("type" :-> Json.shortText "record")
-- x     ("fields" :-> schemaToJson snext)

makeRecordType :: ShortText -> SmallArray Json.Value -> Json.Value
makeRecordType tyName fields = Json.object3
  ("type" :-> Json.shortText "record")
  ("name" :-> Json.shortText tyName)
  ("fields" :-> Json.Array fields)

encodeAtom :: Atom -> Json.Value
encodeAtom = \case
  Timestamp -> Json.object2
    ("type" :-> Json.shortText "long")
    ("logicalType" :-> Json.shortText "timestamp-millis")
  Signed64 -> Json.shortText "long"
  Signed32 -> Json.shortText "int"
  String -> Json.shortText "string"
  Ip -> Json.shortText "exts.IP"

encodeAtomWithNullability :: Atom -> Nullability -> Json.Value
encodeAtomWithNullability a n = case n of
  NonNullable -> enc
  Nullable -> Json.Array (Contiguous.doubleton (Json.shortText "null") enc)
  where
  enc = encodeAtom a

-- In this, the prefix is only used to name record components.
fieldToJson :: ShortText -> Field -> Json.Value
fieldToJson prefix x = case x.ty of
  Record children -> 
    let titleName = TS.fromText (uppercaseHead (TS.toText x.name))
        fullName = prefix <> titleName
        convertedFields = Exts.fromList (fmap (fieldToJson fullName) children)
     in Json.object2
          ("type" :-> makeRecordType fullName convertedFields)
          ("name" :-> Json.shortText x.name)
  Atomic nullability atom ->
    let memberName = "name" :-> Json.shortText x.name
        memberType = "type" :-> encodeAtomWithNullability atom nullability
     in Json.object2 memberName memberType

-- This converts the nesting source.nat.ip to SourceNatIp
fieldToFlatJson :: Text -> Field -> [Json.Value]
fieldToFlatJson prefix x = case x.ty of
  Record children -> fieldToFlatJson (prefix <> uppercaseHead (TS.toText x.name)) =<< children
  Atomic nullability atom ->
    let memberName = "name" :-> Json.text (prefix <> uppercaseHead (TS.toText x.name))
        memberType = "type" :-> encodeAtomWithNullability atom nullability
     in pure (Json.object2 memberName memberType)

uppercaseHead :: Text -> Text
uppercaseHead t = case T.uncons t of
  Just (c,cs) -> T.cons (toUpper c) cs
  Nothing -> T.empty

replaceIpWithS64 :: [Field] -> [Field]
replaceIpWithS64 = map replaceIpWithS64Single

replaceIpWithS64Single :: Field -> Field
replaceIpWithS64Single x = case x.ty of 
  Record children -> Field x.name (Record (replaceIpWithS64 children))
  Atomic nullability atom -> case atom of
    Ip -> Field x.name (Atomic nullability Signed64)
    _ -> Field x.name (Atomic nullability atom)

theSchema :: [Field]
theSchema =
  [ Field "timestamp" $ Atomic NonNullable Timestamp
  , Field "chronopartition" $ Atomic NonNullable Signed32
  , Field "network" $ Record
    [ Field "application" $ Atomic Nullable String
    , Field "iana_number" $ Atomic NonNullable Signed32
    ]
  , Field "source" $ Record
    [ Field "ip" $ Atomic NonNullable Ip
    , Field "port" $ Atomic NonNullable Signed32
    , Field "packets" $ Atomic NonNullable Signed64
    , Field "bytes" $ Atomic NonNullable Signed64
    , Field "user" $ Record
      [ Field "original" $ Atomic Nullable String
      ]
    ]
  , Field "destination" $ Record
    [ Field "ip" $ Atomic NonNullable Ip
    , Field "port" $ Atomic NonNullable Signed32
    , Field "packets" $ Atomic NonNullable Signed64
    , Field "bytes" $ Atomic NonNullable Signed64
    , Field "user" $ Record
      [ Field "original" $ Atomic Nullable String
      ]
    ]
  ]

-- Avro is weird about how users have to use the "fixed" type. You have
-- to provide a "name" for it so that a Java code generation tool can
-- use that as the class name. You cannot reuse the same name more than
-- once. And you cannot define all the names in advance. You have to define
-- them inline as you are defining the fields for a document. So, this
-- function is a hack to work around this strange limitation. Here, we
-- find the first occurrence of "exts.IP" and replace it with a definition
-- that names that type. All future occurrences then refer to the original.
patchFirstExtsIP :: Json.Value -> Json.Value
patchFirstExtsIP v0 = State.evalState (go v0) Unpatched
  where
  go :: Json.Value -> State Patchedness Json.Value
  go v = State.get >>= \case
    Patched -> pure v
    Unpatched -> case v of
      Json.Array xs -> Json.Array <$> traverse go xs
      Json.Object mbrs -> Json.Object
        <$> traverse (\Json.Member{key,value} -> Json.Member key <$> go value) mbrs
      Json.String "exts.IP" -> do
        State.put Patched
        pure $ Json.object4
          ("name" :-> Json.shortText "IP") 
          ("namespace" :-> Json.shortText "exts") 
          ("type" :-> Json.shortText "fixed") 
          ("size" :-> Json.int 16) 
      x -> pure x

data Settings = Settings
  { nested :: !Bool
  , ipAsSigned64 :: !Bool
  , timeBucket :: !(Maybe Text)
  , compress :: !Bool
  }
  deriving (Generic, Show)

instance Opts.ParseRecord Settings

data Compression = CompressionNone | CompressionDeflate

main :: IO ()
main = do
  Settings{nested,ipAsSigned64,timeBucket=timeBucketStr,compress} <- Opts.getRecord "pan-os-syslog-to-avro"
  timeBucket :: Int64 <- case timeBucketStr of
    Just "1d" -> pure 86400
    Just "24h" -> pure 86400
    Just "1h" -> pure 3600
    Just "60m" -> pure 3600
    Just "5m" -> pure 300
    Just "none" -> pure 0
    Nothing -> pure 0
    _ -> fail "Unsupported timeBucket. Try: 5m, 60m, 1d"
  let compression = case compress of
        True -> CompressionDeflate
        False -> CompressionNone
  let ipEncoding = case ipAsSigned64 of
        True -> IpEncodingS64
        False -> IpEncodingU128
  let theSchema' = case ipAsSigned64 of
        True -> replaceIpWithS64 theSchema
        False -> theSchema
  let encodedSchema = Builder.run 512 $ Json.encode $ patchFirstExtsIP $ case nested of
        False -> Json.object3
          ("type" :-> Json.shortText "record")
          ("name" :-> Json.shortText "docroot")
          ("fields" :-> Json.Array (Exts.fromList (fieldToFlatJson T.empty =<< theSchema')))
        True -> Json.object3
          ("type" :-> Json.shortText "record")
          ("name" :-> Json.shortText "docroot")
          ("fields" :-> Json.Array (Exts.fromList (map (fieldToJson "") theSchema')))
  let syncMarker@(Word128 syncA syncB) = 0xabcd_0123_9876_fedc_4567_4321_3456_cdef
  putStrLn "Schema"
  putStrLn "======"
  Chunks.hPut IO.stdout encodedSchema
  putStrLn ""
  putStrLn "Sync Marker"
  putStrLn "==========="
  Chunks.hPut IO.stdout
    ( Builder.run 16
      (Builder.word64PaddedUpperHex syncA <> Builder.word64PaddedUpperHex syncB)
    )
  putStrLn ""
  sinks <- handleUntilEof timeBucket compression encodedSchema syncMarker ipEncoding
  for_ sinks $ \Sink{handle=h,buffer,position} -> do
    ix <- readPrimVar position
    case ix of
      0 -> pure ()
      _ -> do
        dst' <- PM.freezeSmallArray buffer 0 ix
        Chunks.hPut h (encodeTrafficLogBatch compression ipEncoding syncMarker dst')
    IO.hClose h
  pure ()

pushAvroHeader :: 
     Compression
  -> Word128 -- sync marker
  -> Chunks -- encoded schema
  -> Handle -- sink
  -> IO ()
pushAvroHeader !compression !syncMarker !encSchema !sink = Chunks.hPut sink $ Builder.run 1024 $
  Builder.ascii4 'O' 'b' 'j' '\x01'
  <>
  Avro.map2
    "avro.schema"
    (Avro.chunks encSchema)
    "avro.codec"
    (Avro.text (case compression of {CompressionNone -> "null"; CompressionDeflate -> "deflate"}))
  <>
  Avro.word128 syncMarker

data Sink = Sink
  { buffer :: !(SmallMutableArray RealWorld Traffic)
  , position :: !(PrimVar RealWorld Int)
  , handle :: !Handle
  }

initializeSinkIfNotExists :: Compression -> Word128 -> Chunks -> Map Int64 Sink -> Int64 -> IO (Sink, Map Int64 Sink)
initializeSinkIfNotExists !compression !syncMarker !encSchema !sinks !k = case Map.lookup k sinks of
  Nothing -> do
    buffer <- PM.newSmallArray batchSize errorThunk
    position <- newPrimVar 0
    createDirectoryIfMissing False "output"
    let partitionDir = ("output/chronopartition=" ++ show k)
    createDirectoryIfMissing False partitionDir
    h <- IO.openFile (partitionDir ++ "/data.avro") IO.WriteMode
    pushAvroHeader compression syncMarker encSchema h
    let newSink = Sink{buffer,position,handle=h}
    let sinks' = Map.insert k newSink sinks
    pure (newSink, sinks')
  Just s -> pure (s,sinks)

computeBucket ::
     Int64
  -> Int64 -- seconds since epoch
  -> Int64
computeBucket !sz !seconds = case sz of
  0 -> 0
  _ -> div (sz * div seconds sz) 300

handleUntilEof ::
     Int64 -- time bucket
  -> Compression -- compression codec
  -> Chunks -- encoded schema
  -> Word128 -- sync marker
  -> IpEncoding
  -> IO (Map Int64 Sink)
handleUntilEof !bucketSize !compression !encSchema !syncMarker !ipEncoding = do
  let go :: Map Int64 Sink -> Int -> IO (Map Int64 Sink)
      go !sinks !fileIx = catchJust (bool Nothing (Just ()) . isEOFError) (Just <$> ByteString.getLine) (\() -> pure Nothing) >>= \case
        Nothing -> pure sinks
        Just b0 -> do
          b1 <- b2b b0
          case decode (Bytes.fromByteArray b1) of
            Right (LogTraffic tr) -> do
              let secondsSinceEpoch = div (Chronos.getTime (Chronos.datetimeToTime (Traffic.timeGenerated tr))) 1_000_000_000
              let bucket = computeBucket bucketSize secondsSinceEpoch
              (Sink{buffer=dst,position,handle=h},sinks') <- initializeSinkIfNotExists compression syncMarker encSchema sinks bucket
              !dstIx0 <- readPrimVar position
              !dstIx <- if dstIx0 == batchSize
                then do
                  dst' <- PM.freezeSmallArray dst 0 batchSize
                  Chunks.hPut h (encodeTrafficLogBatch compression ipEncoding syncMarker dst')
                  pure 0
                else pure dstIx0
              case ipEncoding of
                IpEncodingU128
                  | isKnownIpProtocol (Traffic.ipProtocol tr) -> do
                      PM.writeSmallArray dst dstIx tr
                      writePrimVar position (dstIx + 1)
                      go sinks (fileIx + 1)
                  | otherwise -> go sinks (fileIx + 1)
                IpEncodingS64
                  | IP.isIPv4 (Traffic.sourceAddress tr)
                  , IP.isIPv4 (Traffic.destinationAddress tr)
                  , isKnownIpProtocol (Traffic.ipProtocol tr) -> do
                      PM.writeSmallArray dst dstIx tr
                      writePrimVar position (dstIx + 1)
                      go sinks' (fileIx + 1)
                  | otherwise -> go sinks' (fileIx + 1)
            Right _ -> go sinks (fileIx + 1)
            Left err -> fail ("On line " ++ show fileIx ++ ", " ++ show err)
  go Map.empty (0 :: Int)

batchSize :: Int
batchSize = 8192

isKnownIpProtocol :: Bytes -> Bool
isKnownIpProtocol !proto = proto == Ascii.fromString "tcp" || proto == Ascii.fromString "udp"

data IpEncoding = IpEncodingU128 | IpEncodingS64

syncMarkerToBytes :: Word128 -> Bytes
syncMarkerToBytes !w = Bytes.fromByteArray $ runByteArrayST $ do
  dst <- PM.newByteArray 16
  BigEndian.writeByteArray dst 0 w
  PM.unsafeFreezeByteArray dst

encodeTrafficLogBatch :: Compression -> IpEncoding -> Word128 -> SmallArray Traffic -> Chunks
encodeTrafficLogBatch !compression !ipEnc !syncMarker !xs =
  -- Note: we have to subtract the length of the sync marker from
  -- the payload length. 
  let payload = Builder.run 512 (foldMap (encodeTrafficLog ipEnc) xs)
   in case compression of
        CompressionNone ->
          Builder.runOnto 128
            (Avro.int (PM.sizeofSmallArray xs) <> Avro.int (Chunks.length payload))
            (payload <> ChunksCons (syncMarkerToBytes syncMarker) ChunksNil)
        CompressionDeflate ->
          let compressedPayload = Deflate.compress (LBS.fromStrict (Chunks.concatByteString payload))
           in Builder.runOnto 128
                (Avro.int (PM.sizeofSmallArray xs) <> Avro.int64 (LBS.length compressedPayload))
                (ChunksCons (Bytes.fromLazyByteString compressedPayload) (ChunksCons (syncMarkerToBytes syncMarker) ChunksNil))

encodeIp :: IpEncoding -> IP -> Builder
encodeIp !enc !ip = case enc of
  IpEncodingS64 -> Avro.int64 (extractIPv4 ip)
  IpEncodingU128 -> Avro.word128 (ipToW128 ip)

encodeTrafficLog :: IpEncoding -> Traffic -> Builder
encodeTrafficLog ipEnc t =
  let millisecondsSinceEpoch = div (Chronos.getTime (Chronos.datetimeToTime (Traffic.timeGenerated t))) 1_000_000 in
  Avro.int64 millisecondsSinceEpoch
  <>
  Avro.int64 (div millisecondsSinceEpoch 300_000)
  <>
  encodeNullableString Traffic.application t
  <>
  Avro.int32 (if Traffic.ipProtocol t == Ascii.fromString "tcp" then 6 else 17)
  <>
  encodeIp ipEnc (Traffic.sourceAddress t)
  <>
  Avro.word16 (Traffic.sourcePort t)
  <>
  Avro.int64 (fromIntegral (Traffic.packetsReceived t))
  <>
  Avro.int64 (fromIntegral (Traffic.bytesReceived t))
  <>
  encodeNullableString Traffic.sourceUser t
  <>
  encodeIp ipEnc (Traffic.destinationAddress t)
  <>
  Avro.word16 (Traffic.destinationPort t)
  <>
  Avro.int64 (fromIntegral (Traffic.packetsSent t))
  <>
  Avro.int64 (fromIntegral (Traffic.bytesSent t))
  <>
  encodeNullableString Traffic.destinationUser t

extractIPv4 :: IP -> Int64
extractIPv4 (IP (IPv6 (Word128 _ b))) = fromIntegral (b .&. 0x0000_0000_FFFF_FFFF)

encodeNullableString :: (Traffic -> Bytes) -> Traffic -> Builder
encodeNullableString project t =
  let x = project t
   in case Bytes.null x of
        True -> Builder.word8 0x00
        False -> Builder.word8 0x02 <> Avro.bytes x

ipToW128 :: IP -> Word128
ipToW128 (IP (IPv6 w)) = w

errorThunk :: Traffic
{-# noinline errorThunk #-}
errorThunk = errorWithoutStackTrace "pan-os-syslog-to-avro: implementation mistake"

b2b :: ByteString -> IO ByteArray
b2b !b = ByteString.useAsCStringLen b $ \(ptr,len) -> do
  arr <- PM.newByteArray len
  PM.copyPtrToMutablePrimArray (castArray arr) 0 ptr len
  PM.unsafeFreezeByteArray arr

castArray :: PM.MutableByteArray s -> PM.MutablePrimArray s CChar
castArray (PM.MutableByteArray x) = PM.MutablePrimArray x
