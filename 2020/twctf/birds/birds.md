# Birds

In this challenge we got a list of what seems to be flight numbers, as well as the hint that the flag would be a proper sentence:

```
TWCTF{

BC552
AC849
JL106
PQ448
JL901
LH908
NH2177

}

It will be a proper sentence.
Flag format is /^TWCTF{[A-Z]+}$/
```

First we gathered some initial information about these flights:

| Flight | From                  | To                          | Take off | UTC           | Landing | UTC           | Fligthtime (local-time-delta) | Airline            |
| ------ | --------------------- | --------------------------- | -------- | ------------- | ------- | ------------- | ----------------------------- | ------------------ |
| BC552  | OKA (Okinawa)         | NGO (Nagoya Chubu Centrair) | 11:00    | 19. Sep 02:00 | 13:10   | 19. Sep 04:10 | 02:10                         | Skymark            |
| AC849  | LHR (London Heathrow) | YYZ (Toronto Pearson)       | 14:05    | 19. Sep 13:05 | 16:50   | 19. Sep 20:50 | 02:45                         | Air Canada         |
| JL106  | ITM (Osaka Itami)     | HND (Tokyo Haneda)          | 08:30    | 18. Sep 23:30 | 09:40   | 19. Sep 00:40 | 01:10                         | Japan Airlines     |
| PQ448  | TBS (Tbilisi)         | ODS (Odesa)                 | 03:35    | 18. Sep 23:35 | 04:45   | 19. Sep 01:45 | 01:10                         | SkyUp              |
| JL901  | HND (Tokyo Haneda)    | OKA (Okinawa)               | 06:20    | 18. Sep 21:20 | 09:00   | 19. Sep 00:00 | 02:40                         | Japan Airlines     |
| LH908  | FRA (Frankfurt)       | LHR (London Heathrow)       | 14:00    | 19. Sep 12:00 | 14:40   | 19. Sep 13:40 | 00:40                         | Lufthansa          |
| NH2177 | NRT (Tokyo Narita)    | ITM (Osaka Itami)           | 16:40    | 19. Sep 07:40 | 18:00   | 19. Sep 09:00 | 01:20                         | All Nippon Airways |

Since we didn't really see anything concrete, we just tried out a bunch of combinations of the three letter airport codes. It became clear very quickly that this wouldn't yield proper sentences, so we started to only use the first letters. The words `FLY` and `TO` can both be built using these letters, which seemed like it could be part of the flag. A japanophile on our team recognized, that the word `NIHON` can also be formed from those letters, which is the Japanese name for Japan. This doesn't use all letters, but we were pretty desperate, so we tried to submit the flag `TWCTF{FLYTONIHON}` and that worked.
