# XXChaCha20-Poly1305-SIV
XXChaCha20-Poly1305-SIV is a key-committing, misuse-resistant AEAD scheme based on [ChaCha20-Poly1305-PSIV](https://eprint.iacr.org/2025/222) and [Daence](https://eprint.iacr.org/2020/067). It uses HChaCha20, Poly1305, and ChaCha20.

> [!CAUTION]
> This is an experimental construction that has not received any peer review or proper analysis. It **MUST NOT** be used in production.

It has the following advantages over PSIV:
- A larger nonce is supported (128 bits), which is better for random nonces.
- The tag size is larger (256 bits), which is better for commitment.
- Existing APIs can be used for implementation (e.g., [libsodium](https://doc.libsodium.org/key_derivation#nonce-extension)).
- If an existing API is inaccessible, HChaCha20 is easier to implement than the entire ChaCha20 stream cipher because you don't need to process multiple blocks. The implementation performance is also less important (for medium-long messages) because it's only called a few times.
- The ChaCha20 state is left as is so existing and future security analyses of ChaCha20 apply directly.

However, it's less efficient than PSIV due to the HChaCha20 calls, although the performance should be better than Daence and not too far off XChaCha20. Note that the Poly1305 key can also be cached to improve performance.

Whilst both PSIV and XXChaCha20-Poly1305-SIV are only key committing, they can be made context committing by using [HtE](https://eprint.iacr.org/2022/268) with a collision-resistant KDF (e.g., BLAKE3). Both also allow the pre-processing of static associated data for the same key, which is a feature advertised in [EAX mode](https://web.cs.ucdavis.edu/~rogaway/papers/eax.html). Finally, both should share the same benefits over AES-GCM-SIV, like no slowdown for encryption compared to decryption.

## Design
```
macKey = HChaCha20(key, allZeros, UTF8("firstHChaChaBloc"))

// As in ChaCha20-Poly1305 but with the plaintext
poly1305Tag = Poly1305(macKey, associatedData, plaintext)

// Both use Davies-Meyer with XOR
subkey = HChaCha20DM(key, nonce, UTF8("secondHChaChaBlo"))
tag = HChaCha20DM(subkey, poly1305Tag, UTF8("thirdHChaChaBloc"))

// Truncated tag (224 bits) as the nonce
encKey = HChaCha20(key, tag[..16])
ciphertext = ChaCha20(encKey, nonce: tag[16..28], plaintext)

return ciphertext || tag
```

### Design Rationale
PSIV does the following:
- Reuses the key for Poly1305 key derivation, tag computation, and encryption.
- Derives a static Poly1305 key, allowing precomputation. This is acceptable because the Poly1305 tag is protected by the ChaCha20 permutation with the feed-forward (truncated).
- Uses different constants in the ChaCha20 state for Poly1305 key derivation, tag computation, and encryption to ensure the permutation inputs/outputs don't collide.
- Computes a tag from the key, nonce, and Poly1305 tag of the associated data and plaintext using the ChaCha20 permutation with the feed-forward, truncating the output.
- Puts the tag (and nonce) in the ChaCha20 state when performing encryption.

XXChaCha20-Poly1305-SIV essentially does the same but using HChaCha20 and Davies-Meyer with XOR to replicate PSIV's use of truncated ChaCha20 with the feed-forward for tag computation. Two HChaCha20 calls are chained, like in Daence, due to input length restrictions. If each call is collision-resistant, it can be viewed similarly to [CTX](https://eprint.iacr.org/2022/1260) without processing the associated data outside the AEAD scheme.

Additionally, the user's nonce is not used directly for encryption because an [SIV](https://eprint.iacr.org/2006/221) (just using the tag) instead of an [NSIV](https://eprint.iacr.org/2015/1049) (nonce + tag) approach is adopted. This is due to input length restrictions without manipulating the ChaCha20 state. However, it would be possible to do this with a 128-bit tag and a 64- or 96-bit nonce (see below).

To be able to use most of the tag, XChaCha20 can be used for encryption, like in [generalised SIV](https://datatracker.ietf.org/doc/html/draft-madden-generalised-siv) and Daence. However, XChaCha20 wastes 32 bits of nonce space. Therefore, [XXChaCha20](https://github.com/samuel-lucas6/XXChaCha20) is used for encryption. This is XChaCha20 but with a 224-bit nonce. The extra 32 bits of nonce are free from a performance perspective, but this does prevent a 192-bit tag from being used and means the ChaCha20 counter is limited to 32 bits (some XChaCha20 implementations use a 64-bit counter). With that said, nobody should be encrypting plaintexts that large without [stream encryption](https://eprint.iacr.org/2015/189) anyway.

The HChaCha20 constants are changed for each call, except XXChaCha20, for domain separation. The constants are inspired by [Rumba20](https://cr.yp.to/rumba20.html), which uses custom constants with Salsa20/ChaCha20.

Davies-Meyer is not used for the Poly1305 key derivation or XXChaCha20 because collision resistance is not required here. I don't think Davies-Meyer is needed at all, but it's in place to match the PSIV key-committing security analysis (truncated Davies-Meyer with a permutation).
