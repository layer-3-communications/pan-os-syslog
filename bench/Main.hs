import Gauge (bench,whnf,defaultMain)
import Panos.Syslog (decode)

import qualified Sample as S

main :: IO ()
main = defaultMain
  [ bench "8-1-Traffic-A" (whnf decode S.traffic_8_1_A)
  , bench "8-1-Threat-A" (whnf decode S.threat_8_1_A)
  , bench "8-1-Threat-B" (whnf decode S.threat_8_1_B)
  , bench "8-1-Threat-C" (whnf decode S.threat_8_1_C)
  ]

