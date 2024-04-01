from openssl import *

fn main():
  # sha256
  var data = "hello world"

  try:
    # sha256
    var hash = sha256(data)
    print("sha256 hash: ", hash)
    hash = sha256_file("test.txt")
    print("sha256 file hash: ", hash)

    # sha512
    hash = sha512(data)
    print("sha512 hash: ", hash)
    hash = sha512_file("test.txt")
    print("sha512 file hash: ", hash)

  except e:
    print("error: ", e)