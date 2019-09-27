import Gauge (bench,whnf,defaultMain)
import Panos.Syslog (decodeLog)

import qualified Sample as S

main :: IO ()
main = defaultMain
  [ bench "8-1-Traffic-A" (whnf decodeLog S.traffic_8_1_A)
  , bench "8-1-Threat-A" (whnf decodeLog S.threat_8_1_A)
  , bench "8-1-Threat-B" (whnf decodeLog S.threat_8_1_B)
  , bench "8-1-Threat-C" (whnf decodeLog S.threat_8_1_C)
  ]

