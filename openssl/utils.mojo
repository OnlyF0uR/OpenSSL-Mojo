# https://github.com/saviorand/lightbug_http/blob/a05ca369f07aabe262538cdd9e67112f8803ad83/external/libc.mojo#L109
fn to_char_ptr(s: String) -> Pointer[UInt8]:
    """Only ASCII-based strings."""
    var ptr = Pointer[UInt8]().alloc(len(s))
    for i in range(len(s)):
        ptr.store(i, ord(s[i]))
    return ptr

fn c_charptr_to_string(s: Pointer[UInt8], length: Int) -> String:
    var bc = s.bitcast[Int8]()
    if bc == Pointer[Int8](): # 0x00
        return ""
    return String(s.bitcast[Int8](), length + 1)