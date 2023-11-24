proc cipher(data: openarray[byte]): seq[byte] =
    var res: seq[byte]
    KEY_PLACEHOLDER
    for y in countup(0,data.len-1):
        res.add(byte(data[y] xor key[y mod key.len]))

    return res