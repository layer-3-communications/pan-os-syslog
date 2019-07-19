import Gauge (bgroup,bench,whnf,defaultMain)
import Panos.Syslog (decodeLog)

import qualified Sample as S

main :: IO ()
main = defaultMain
  [ bench "8-1-A" (whnf decodeLog S.traffic_8_1_A)
  ]

