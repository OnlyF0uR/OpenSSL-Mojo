from openssl.utils import to_char_ptr, c_charptr_to_string

alias c_char = UInt8
alias c_char_p = Pointer[c_char]
alias c_int = Int32

fn sha256(input: String) raises -> String:
  var param_a = to_char_ptr(input)
  var param_b = len(input)

  var result = external_call["sha256", Pointer[UInt8], Pointer[UInt8], Int32](param_a, param_b)
  var s_result = c_charptr_to_string(result, 64)

  if s_result == "":
    raise "Error while hashing"
  else:
    return s_result

fn sha256_file(file_path: String) raises -> String:
  # TODO: Check if file actually exists instead of just letting it fail
  var param_a = to_char_ptr(file_path)

  var result = external_call["sha256_file", Pointer[UInt8], Pointer[UInt8]](param_a)
  var s_result = c_charptr_to_string(result, 64)

  if s_result == "":
    raise "Error while hashing"
  else:
    return s_result

fn sha512(input: String) raises -> String:
  var param_a = to_char_ptr(input)
  var param_b = len(input)

  var result = external_call["sha512", Pointer[UInt8], Pointer[UInt8], Int32](param_a, param_b)
  var s_result = c_charptr_to_string(result, 128)

  if s_result == "":
    raise "Error while hashing"
  else:
    return s_result

fn sha512_file(file_path: String) raises -> String:
  # TODO: Check if file actually exists instead of just letting it fail
  var param_a = to_char_ptr(file_path)

  var result = external_call["sha512_file", Pointer[UInt8], Pointer[UInt8]](param_a)
  var s_result = c_charptr_to_string(result, 128)

  if s_result == "":
    raise "Error while hashing"
  else:
    return s_result