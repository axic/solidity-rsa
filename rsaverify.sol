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

*/

contract RSAVerify {
    // This is based on ERC101, but optimised for RSA (e=65537)
    function bigmulmod (bytes B, uint E, bytes M) internal returns (bool _ret, bytes _val) {
        bool ret;
        bytes memory val;
        uint Blen = B.length;
        uint Mlen = M.length;
        assembly {
            let memstart := mload(0x40)
            let mempos := memstart

            // store Blen as uint256
            mstore(mempos, Blen)
            mempos := add(mempos, 32)

            // memcpy B
            call(add(15, mul(Blen, 5)), 4, 0, add(B, 32), Blen, mempos, Blen)
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
            call(add(15, mul(Mlen, 5)), 4, 0, add(M, 32), Mlen, mempos, Mlen)
            mempos := add(mempos, Mlen)

            // total amount written
            let len := sub(mempos, memstart)

            // this feels a bit complex
            let words := mul(div(add(len, 31), 32), 6)
            let complexity := div(mul(Blen, mul(Mlen, 32)), 32)
            let gas := add(45, add(words, complexity))

            // NOTE: response will overwrite the request
            val := memstart

            // call MODEXP precompile
            ret := call(gas, 9, 0, memstart, len, add(val, 32), Mlen)

            // set the expected length, but since it shares the input memory
            // it cannot be done before the call
            mstore(val, Mlen)
        }
        
        _ret = ret;
        _val = val;
    }

    function rsaverify(bytes msg, bytes N, uint e, bytes S) returns (bool) {
        // FIXME: do padding here for `msg`
        // FIXME: optimise this maybe?
        return sha3(bigmulmod(S, e, N)) == sha3(bigmulmod(msg, 1, N));
    }
}
