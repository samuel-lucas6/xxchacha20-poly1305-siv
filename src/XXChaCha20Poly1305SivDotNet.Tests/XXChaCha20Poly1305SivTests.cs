using System.Security.Cryptography;

namespace XXChaCha20Poly1305SivDotNet.Tests;

[TestClass]
public class XXChaCha20Poly1305SivTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "44d63a4b90ad0560edf861511e93c632f10d12e34747674d794c0cc385328819438921792bc78fad10b8125bfcbe8e2c15211d9ae259945f75a00ae28819ecbc20d2fd29d02703d776b87a7f04961deda6f0bac1ef0b0301386418995da8aa88128db0f6f5be1a2191b1c666fd6631fa199177566697ce6096e2f31c71b7efe8f68381b35936ba8d35596937a31742371515",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "530ee5e3dae7693017d28e5d7c6936ce",
            "1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2",
            ""
        ];
        yield return
        [
            "7c1f693ecf2818f8c14847e3482e331e5bfac32bdf8503931d5d2f103314f59e8a56d6871d784090b8be6b18b4288ceaeb75e7f30c83e23a05a526bb4de25556a952a8b44c013fbdb961e02daf8facdf860c821660db15e500160ad3556f568bd17fda137893f2669906b863bdcb4058c9152310f4e120b2f12ecdaaa267156c7a2ecfd7580eba027105c7a8d3c880cd92a4835617a1b4a492c70de198eb7a6c9225b6cee820ac3e7b79d65d8c3ee97d6b30b125e25be284e3344caf341b4c6a7c69a7c19df0156470df866a5e7ab623d563d8d5f7279f3d6966d403a4a6b3f7f11d55bb8a6d52900c40cbb86f4b49396a0fac9e98c20a61fa313f1ff0609bce351146ef35810d2c80f2c0edaf2abf0f8847cf8118cf699dac1a72bfd7fbe27050c6a3a2b1c7d6dde0",
            "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
            "530ee5e3dae7693017d28e5d7c6936ce",
            "1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2",
            ""
        ];
        yield return
        [
            "0b4c5ed1fad78f27127b4ab0c99d3b3a3514f6f908be999b32d78a08d87344563a28aa3825cbc3eabc55363c967247ea49b7fb87e9b8fdada10c6b3e8dbe2b1cf3ab21da9cc2a98d82512efe21be1d3c717ee5fbbde69f65b690c8390cf607e4a42d07899f86b3a8f7749373032080cb321239b13ea40d40d755524dc000ba6d5455a772de3ed9f6bd6537f16e11f5d287cb",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "85975d0ee263b966a551adab8325ebe3",
            "1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2",
            ""
        ];
        yield return
        [
            "dae81b5cf3964552376daad664b2a5342868d810a0906fadc68c5b04d5a70df85f29f6545166e32c142aad7c370635e7e84eba5044b2ed9467dfff37df13399854651c74dbc46eb30c2fbf3c23d4b59ece0c232c7ef9f30193a6a09a157397413cc2100c172de411a1c91b047b274679ec435a224789d44c749cabc0cd992aed21a2c6a467ea9cc22229e20cadce06aacc81",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "530ee5e3dae7693017d28e5d7c6936ce",
            "3ef4832df6f83cd761539792c7c34b90fde64ca02d31151fdf924bf2206e37cb",
            ""
        ];
        yield return
        [
            "3dd28ef5be0a5ba1e6fc586b1850687e4ddaa3df33d73c84e41595cb45974045bba1ae7ff09dce42e89784ade68930596310dd2bc2b3f643de9bbfadfcb90e016b0b381bff5ed560efd38378f0af0bda54e51f035714dc9102435200fc11108cdd358efe053b3ff157fcaac62a8a955b8062c446dab73138acbaafbe84f23be6fa534fb068dd451df5a39f7b28a310c50094",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "530ee5e3dae7693017d28e5d7c6936ce",
            "1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2",
            "50515253c0c1c2c3c4c5c6c7"
        ];
        yield return
        [
            "590c3df9a345e2bb2eda996d2dddd652c513dc25be0d635e5f6859ad29cb36a29ff3548adfbc526963d42ac30e679b2432532b69022c5d56b82540ed90e6eeb3",
            "aeadc48d4a2ea7ee06f9f41a6fbcd651ac5df158860e14af1fb0ebbe0a04bab2",
            "530ee5e3dae7693017d28e5d7c6936ce",
            "1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2",
            "2891ec111a27c55b3a6757ff173ef9cfc02bb682bcee4aaa317715b0b7895a58"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [XXChaCha20Poly1305Siv.TagSize - 1, 0, XXChaCha20Poly1305Siv.NonceSize, XXChaCha20Poly1305Siv.KeySize, XXChaCha20Poly1305Siv.TagSize];
        yield return [XXChaCha20Poly1305Siv.TagSize, 1, XXChaCha20Poly1305Siv.NonceSize, XXChaCha20Poly1305Siv.KeySize, XXChaCha20Poly1305Siv.TagSize];
        yield return [XXChaCha20Poly1305Siv.TagSize, 0, XXChaCha20Poly1305Siv.NonceSize + 1, XXChaCha20Poly1305Siv.KeySize, XXChaCha20Poly1305Siv.TagSize];
        yield return [XXChaCha20Poly1305Siv.TagSize, 0, XXChaCha20Poly1305Siv.NonceSize - 1, XXChaCha20Poly1305Siv.KeySize, XXChaCha20Poly1305Siv.TagSize];
        yield return [XXChaCha20Poly1305Siv.TagSize, 0, XXChaCha20Poly1305Siv.NonceSize, XXChaCha20Poly1305Siv.KeySize + 1, XXChaCha20Poly1305Siv.TagSize];
        yield return [XXChaCha20Poly1305Siv.TagSize, 0, XXChaCha20Poly1305Siv.NonceSize, XXChaCha20Poly1305Siv.KeySize - 1, XXChaCha20Poly1305Siv.TagSize];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, XXChaCha20Poly1305Siv.KeySize);
        Assert.AreEqual(16, XXChaCha20Poly1305Siv.NonceSize);
        Assert.AreEqual(32, XXChaCha20Poly1305Siv.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        XXChaCha20Poly1305Siv.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XXChaCha20Poly1305Siv.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        XXChaCha20Poly1305Siv.Decrypt(p, c, n, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new Dictionary<string, byte[]>
        {
            { "c", Convert.FromHexString(ciphertext) },
            { "n", Convert.FromHexString(nonce) },
            { "k", Convert.FromHexString(key) },
            { "ad", Convert.FromHexString(associatedData) }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => XXChaCha20Poly1305Siv.Decrypt(p, parameters["c"], parameters["n"], parameters["k"], parameters["ad"]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XXChaCha20Poly1305Siv.Decrypt(p, c, n, k, ad));
    }
}
