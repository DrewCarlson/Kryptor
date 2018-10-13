package kryptor

expect object Crypto {
  fun keyFromPassword(password: String): UByteArray
  fun encryptFile(file: String, key: UByteArray)
  fun decryptFile(file: String, key: UByteArray)
}
