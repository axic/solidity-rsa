/*

https://github.com/ethereum/EIPs/issues/101

At the address 0x0000....09, add a precompile that expects input in the following format:

<length of B, as a 32-byte-padded integer> <bytes of B> <length of E, as a 32-byte-padded integer> <bytes of E> <bytes of M>

This should return B**E % M

High level method: rsaverify(msg, N, e, S, paddingScheme), where

msg is the message hash,
N is the public key modulus,
e is the public key exponent
and S is the signature.

Se=Pad(Hash(M))(modN)

Sig^(Exponent) = Pad(Hash(Msg)) (mod Modulus)

paddingScheme:
- 0: input is padded
- 1: PKCS1.5 SHA1
- 2: PSS SHA256

*/

pragma solidity ^0.4.1;

import "./Memory.sol";

library BytesTool {
    function memset(bytes input, uint offset, uint length, byte value) internal {
    }

    function test() {
        bytes memory test = hex"000000001010101014031241214124124124";
        uint len = test.length;
        bytes memory output = new bytes(32);
        uint olen = output.length;
        assembly {
            pop(call(gas, 9, 0, add(test, 32), len, add(output, 32), olen))
        }
    }
}

library RSAVerify {
    // PKCS1 padding: [0] [1] ... (rest) [ff]
    // Note: keysize >= 3
    function pkcs1_pad(bytes input, uint keysize) returns (bool, bytes) {
        uint input_length = input.length;

        bytes memory output;
        uint pad_len = keysize - 3;

        if (pad_len < input_length) {
            return (false, new bytes(0));
        }

        output = new bytes(keysize);

        for (var i = 0; i < input_length; i++) {
            output[i] = input[i];
        }

        assembly {
            pop(call(add(15, mul(input_length, 5)), 4, 0, add(input, 32), input_length, add(output, 32), input_length))
        }

        output[input_length++] = 0;
        output[input_length++] = 1;
        for (; input_length < keysize; input_length++) {
            output[input_length] = 0xff;
        }

        return (true, output);
    }

    function pkcs1_sha256_pad(bytes input, uint keysize)  returns (bool, bytes output)
    {
        var (success, value) = pkcs1_pad(input, keysize);
        if (success) {
            output = new bytes(32);
            assembly {
                mstore(add(output, 32), value)
            }
        }
        return (success, output);
    }

    // This is based on ERC101, but optimised for RSA (e=65537)
    function bigmulmod (bytes B, uint E, bytes M)  returns (bool ret, bytes val) {
        uint Blen = B.length;
        uint Mlen = M.length;
        assembly {
            let memstart := mload(0x40)
            let mempos := memstart

            // store Blen as uint256
            mstore(mempos, Blen)
            mempos := add(mempos, 32)

            // memcpy B
            jumpi(call(add(15, mul(Blen, 5)), 4, 0, add(B, 32), Blen, mempos, Blen), error)
            mempos := add(mempos, Blen)

            // store Elen (32) as uint256
            mstore(mempos, 32)
            mempos := add(mempos, 32)

            // store E
            mstore(mempos, E)
            mempos := add(mempos, 32)

            // store Mlen as uint256
            mstore(mempos, Mlen)
            mempos := add(mempos, 32)

            // memcpy M
            jumpi(call(add(15, mul(Mlen, 5)), 4, 0, add(M, 32), Mlen, mempos, Mlen), error)
            mempos := add(mempos, Mlen)

            // total amount written
            let len := sub(mempos, memstart)

            // this feels a bit complex
            let words := mul(div(add(len, 31), 32), 6)
            let complexity := div(mul(Blen, mul(Mlen, 32)), 32)
            let gasleft := add(45, add(words, complexity))

            // NOTE: response will overwrite the request
            val := memstart

            // call MODEXP precompile
            jumpi(call(gasleft, 9, 0, memstart, len, add(val, 32), Mlen), error)

            // set the expected length, but since it shares the input memory
            // it cannot be done before the call
            mstore(val, Mlen)

            jump(success)
        error:
            ret := 0

        success:
            ret := 1
        }
    }

    enum PaddingScheme { Padded, PKCS1, PSS }

    function rsaverify(bytes msg, bytes N, uint e, bytes S, PaddingScheme paddingScheme) returns (bool) {
        if (paddingScheme == PaddingScheme.PKCS1) {
            var (retP, msgP) = pkcs1_sha256_pad(msg, N.length);
            if (!retP) {
                return false;
            }
            msg = msgP;
        } else if (paddingScheme != PaddingScheme.Padded) {
            return false;
        }

        // message length must match the keysize
        if (msgP.length != N.length) {
            return false;
        }

        // FIXME: optimise this maybe?
        var (retS, valS) = bigmulmod(S, e, N);
        return retS == true && sha3(valS) == sha3(msgP);
//        var (retM, valM) = bigmulmod(msg, 1, N);
//        return retS == true && retM == true && sha3(valS) == sha3(valM);
//        return sha3(bigmulmod(S, e, N)) == sha3(bigmulmod(msg, 1, N));
    }
}

contract RSAVerifyTest {
    function test512() returns (bool) {
        bytes memory msg = hex"cd8d103034f3796038d906de40faf3c3ba118a6b";
        bytes memory N = hex"00890e68c2485f2c725116f259a7ac871e1de3618dfc41e1df8eacc0131b2d433de6ed6d1f36bbf5a401d5afa32eeb2d444cf02a920c81f8088ba0b99d47a0bfdf";
        uint e = 65537;
        bytes memory S = hex"77c6b0c53800d37b6b946df6d91a693c25b1ba97cac16879a10b3231a5cea0932a0bc16443b2e82b33ec155a61b29572a5faaf574152bd509a248fdb8ed9d7af";
        return RSAVerify.rsaverify(msg, N, e, S, RSAVerify.PaddingScheme.PKCS1);
    }
    function test2048() returns (bool) {
        bytes memory msg = hex"70dd0c1b74d12222bc1e5257bd8c2d45b816202c";
        bytes memory N = hex"00a2904487e49592a42890964f2a758ce58af027ba0fd68f6c9a5684a2d963b6af4127b91e0b9c084aeb0cd9cc81328433d8ed178e4c696c199e2a3d899f85b02f2d16023b57d06ada7e7ab46b49978063d739c9697b3b119783ba870132ac5bba37ccbd99b99a8188fcae7ccce24525dc03c50f78c7a043cc6c2589c90b3f717851d7de5f62d0eafe81aba1287d8e674750090e521589187613518892603dcb9ff37051616805e6fae9ff6185d8037711f2a8cf37db8ccad45fa4410d0e354a029268b22192fabaa45d0b6c72314682143f7e14603a40a9e314644b69cba10910dc651b5fa559a7df46a7758331b24e4ae1a050d280420a49b6119b6e61827749";
        uint e = 65537;
        bytes memory S = hex"1650a750994065226a299be192530fb5575dafe752427f91adb9dadbca968e7edc56db9d3da7550fc2903d2b6a7e0a6452db83855b8a54ff523bdcd4b987640a9939b3f691fae1eac3c0674b1bdb8d4dcf8c2ad003a5ee68bfff34c12ac70081cd817fabc0820d730c7e8f9e4960a7724c8882e65196f6477c85602da607e496f1f5e59f1a346d46ec72ba44cf5b1a562bf4f9c408c2d0c12fb68be0872048700485385414ff76485a0c29d4ed8ccc9594261dc4d54f71ace0878956e918405bd2f41cfd47404c3b63bf4d734d71d72f9df4382790b506f10fb73450b5ad4302b3e232f7deef1d3541c505e3e87b9e24b329a8b95f0ff7be5d4685bafafb84db";
        return RSAVerify.rsaverify(msg, N, e, S, RSAVerify.PaddingScheme.PKCS1);
    }
}
