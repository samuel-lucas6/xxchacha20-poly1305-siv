using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;

namespace XXChaCha20Poly1305SivDotNet;

public static class XXChaCha20Poly1305Siv
{
    public const int KeySize = 32;
    public const int NonceSize = 16;
    public const int TagSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> macKey = stackalloc byte[Poly1305.KeySize], encKey = macKey;
        Span<byte> poly1305Tag = stackalloc byte[Poly1305.TagSize]; poly1305Tag.Clear();
        ReadOnlySpan<byte> constant1 = "firstHChaChaBloc"u8;
        HChaCha20.DeriveKey(macKey, key, poly1305Tag, constant1);
        ComputePoly1305Tag(poly1305Tag, associatedData, plaintext, macKey);

        Span<byte> tag = ciphertext[^TagSize..];
        ReadOnlySpan<byte> constant2 = "secondHChaChaBlo"u8;
        HChaCha20.DeriveKey(tag, key, nonce, constant2);
        Spans.Concat(macKey, constant2, nonce);
        XorBytes(tag, macKey);

        ReadOnlySpan<byte> constant3 = "thirdHChaChaBloc"u8;
        HChaCha20.DeriveKey(tag, tag, poly1305Tag, constant3);
        Spans.Concat(macKey, constant3, poly1305Tag);
        XorBytes(tag, macKey);
        SecureMemory.ZeroMemory(poly1305Tag);

        HChaCha20.DeriveKey(encKey, key, tag[..HChaCha20.NonceSize]);
        ChaCha20.Encrypt(ciphertext[..^TagSize], plaintext, nonce: tag.Slice(HChaCha20.NonceSize, ChaCha20.NonceSize), encKey);
        SecureMemory.ZeroMemory(macKey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> macKey = stackalloc byte[Poly1305.KeySize], encKey = macKey;
        ReadOnlySpan<byte> tag = ciphertext[^TagSize..];
        HChaCha20.DeriveKey(encKey, key, tag[..HChaCha20.NonceSize]);
        ChaCha20.Decrypt(plaintext, ciphertext[..^TagSize], nonce: tag.Slice(HChaCha20.NonceSize, ChaCha20.NonceSize), encKey);

        Span<byte> poly1305Tag = stackalloc byte[Poly1305.TagSize]; poly1305Tag.Clear();
        ReadOnlySpan<byte> constant1 = "firstHChaChaBloc"u8;
        HChaCha20.DeriveKey(macKey, key, poly1305Tag, constant1);
        ComputePoly1305Tag(poly1305Tag, associatedData, plaintext, macKey);

        Span<byte> computedTag = stackalloc byte[TagSize];
        ReadOnlySpan<byte> constant2 = "secondHChaChaBlo"u8;
        HChaCha20.DeriveKey(computedTag, key, nonce, constant2);
        Spans.Concat(macKey, constant2, nonce);
        XorBytes(computedTag, macKey);

        ReadOnlySpan<byte> constant3 = "thirdHChaChaBloc"u8;
        HChaCha20.DeriveKey(computedTag, computedTag, poly1305Tag, constant3);
        Spans.Concat(macKey, constant3, poly1305Tag);
        XorBytes(computedTag, macKey);
        SecureMemory.ZeroMemory(macKey);
        SecureMemory.ZeroMemory(poly1305Tag);

        bool valid = ConstantTime.Equals(tag, computedTag);
        SecureMemory.ZeroMemory(computedTag);
        if (!valid) {
            SecureMemory.ZeroMemory(plaintext);
            throw new CryptographicException();
        }
    }

    private static void ComputePoly1305Tag(Span<byte> tag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> macKey)
    {
        Span<byte> padding = stackalloc byte[16]; padding.Clear();
        using var poly1305 = new IncrementalPoly1305(macKey);
        poly1305.Update(associatedData);
        int remainder = associatedData.Length % 16;
        if (remainder != 0) {
            poly1305.Update(padding[remainder..]);
        }
        poly1305.Update(plaintext);
        remainder = plaintext.Length % 16;
        if (remainder != 0) {
            poly1305.Update(padding[remainder..]);
        }
        BinaryPrimitives.WriteUInt64LittleEndian(padding[..8], (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(padding[8..], (ulong)plaintext.Length);
        poly1305.Update(padding);
        poly1305.Finalize(tag);
    }

    private static void XorBytes(Span<byte> output, ReadOnlySpan<byte> input)
    {
        for (int i = 0; i < output.Length; i++) {
            output[i] ^= input[i];
        }
    }
}
