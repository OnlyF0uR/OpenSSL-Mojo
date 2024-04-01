from openssl import *

fn main():
  # sha256
  var data = "hello world"

  try:
    # sha1
    var hash = sha1(data)
    print("sha1   text hash: ", hash)
    hash = sha1_file("test.txt")
    print("sha1   file hash: ", hash)

    # sha224
    hash = sha224(data)
    print("sha224 text hash: ", hash)
    hash = sha224_file("test.txt")
    print("sha224 file hash: ", hash)

    # sha256
    hash = sha256(data)
    print("sha256 text hash: ", hash)
    hash = sha256_file("test.txt")
    print("sha256 file hash: ", hash)

    # sha384
    hash = sha384(data)
    print("sha384 text hash: ", hash)
    hash = sha384_file("test.txt")
    print("sha384 file hash: ", hash)

    # sha512
    hash = sha512(data)
    print("sha512 text hash: ", hash)
    hash = sha512_file("test.txt")
    print("sha512 file hash: ", hash)

  except e:
    print("error: ", e)