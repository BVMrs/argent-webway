# taint-laundering-model results (MAXLEN=5)

## Family 1: chains, 4680 paths of 2..=5 nodes x 2 origins x 3937 liar assignments (<= 2 liars, 16 lies each)

| policy | scenarios | judged receipts | RAISE | over-taint | inconsistent | inherent | out of scope | liar rejected | honest rejected |
|---|---|---|---|---|---|---|---|---|---|
| P0/E1 as written, senders add own owner | 9946320 | 12227800 | 99904 | 0 | 1025136 | 2700608 | 7631360 | 0 | 0 |
| P0/E0 as written, senders forward taint | 9946320 | 12227800 | 110088 | 0 | 1282944 | 2695928 | 7631360 | 0 | 0 |
| P1/E1 normalise | 9946320 | 12227800 | 0 | 0 | 0 | 2750560 | 7631360 | 0 | 0 |
| P1/E0 normalise | 9946320 | 12227800 | 0 | 0 | 0 | 2750560 | 7631360 | 0 | 0 |
| P2/E1 reject if sender owner missing | 9946320 | 5139480 | 0 | 0 | 0 | 978480 | 2330880 | 7330080 | 0 |
| P2/E0 reject if sender owner missing | 9946320 | 4285820 | 0 | 0 | 0 | 784700 | 1775168 | 6310080 | 2217540 |

- P0/E1 as written, senders add own owner: shortest RAISE: `A1*[] -> B1 -> B2: B2 computes same-owner, truth foreign`

- P0/E0 as written, senders forward taint: shortest RAISE: `A1*[] -> B1 -> B2: B2 computes same-owner, truth foreign`
- P2/E0 reject if sender owner missing: shortest honest reject: `A1 -> B1 -> A1 rejected: honest B1 omitted its own owner`

## Family 2: derivation at an honest node, inputs 1..=3 nodes, output 2..=3 nodes, 265 liar assignments (<= 2 liars, lies: owners in {},{A},{B},{C}, unverified=false)

| policy | scenarios | judged receipts | RAISE | over-taint | inconsistent | inherent | out of scope | liar rejected | honest rejected |
|---|---|---|---|---|---|---|---|---|---|
| P0/E1 as written, senders add own owner | 125237520 | 109105160 | 2296192 | 0 | 9939824 | 39693144 | 42079360 | 0 | 0 |
| P0/E0 as written, senders forward taint | 125237520 | 109105160 | 4959746 | 0 | 19545270 | 38309208 | 42079360 | 0 | 0 |
| P1/E1 normalise | 125237520 | 109105160 | 0 | 0 | 0 | 41221416 | 42079360 | 0 | 0 |
| P1/E0 normalise | 125237520 | 109105160 | 0 | 0 | 0 | 41221416 | 42079360 | 0 | 0 |
| P2/E1 reject if sender owner missing | 45835920 | 43681088 | 0 | 0 | 0 | 7537674 | 6741952 | 10266120 | 0 |
| P2/E0 reject if sender owner missing | 14174160 | 6258048 | 0 | 0 | 0 | 1223704 | 1096456 | 3456432 | 9502840 |

- P0/E1 as written, senders add own owner: shortest RAISE: `(A1 + B1*[] -> A1) derive@A1 -> A3: A3 computes same-owner, truth foreign`

- P0/E0 as written, senders forward taint: shortest RAISE: `(A1 + B1*[] -> A1) derive@A1 -> A3: A3 computes same-owner, truth foreign`
- P2/E0 reject if sender owner missing: shortest honest reject: `A1 -> B1 -> A1 rejected: honest B1 omitted its own owner`

## Directed vectors (trust computed at the last node)

| vector | P0/E1 | P1/E1 | expected |
|---|---|---|---|
| B1 claims owners=[A] to A1 (§6 step 7) | foreign | foreign | foreign |
| B1 claims owners=[A] to A1, A1 forwards to A2 | same-owner | foreign | foreign |
| B1 sends owners=[] to A1, A1 forwards to A2 | same-owner | foreign | foreign |
| B1 claims owners=[A] to A1, A1 -> A2 -> A3 | same-owner | foreign | foreign |
| A1 edge content -> B1 (honest) -> A2 | unverified-origin | unverified-origin | unverified-origin |
| A1 edge content -> B1 drops unverified -> A2 | foreign | foreign | foreign (inherent) |
| honest B1 -> A1 -> A2 | foreign | foreign | foreign |
| honest A1 -> A2 -> A3 | same-owner | same-owner | same-owner |
