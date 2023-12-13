import nimcrypto

proc cipher(data: openarray[byte]): seq[byte] =
    KEY_PLACEHOLDER

    var dctx: ECB[aes256]
    var keya: array[aes256.sizeKey, byte]
    var decText: seq[byte]
    
    decText.setLen(len(data))

    copyMem(addr keya[0], addr key[0], len(key))

    dctx.init(key)

    dctx.decrypt(data, decText)
    dctx.clear()

    return  @(decText)