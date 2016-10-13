library Memory {
    function copy(bytes src, uint srcoffset, bytes dst, uint dstoffset, uint length) internal returns (bool) {
        if (dst.length < dstoffset + length)
            return false;
        bool ret;
        assembly {
            ret := call(add(15, mul(length, 5)), 4, 0, add(src, add(32, srcoffset)), length, add(dst, add(32, dstoffset)), length)
        }
        return ret;
    }
    function a() returns (string) {
        bytes memory x = "hello world";
        bytes memory y = "            from shanghai";
        if (!copy(x, 0, y, 0, x.length))
            return string(new bytes(0));
        return string(y);
    }
}
