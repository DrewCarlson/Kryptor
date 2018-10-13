package kryptor

import kotlinx.cinterop.*
import libsodium.*
import platform.posix.*

const val FILE_CHUNK_SIZE = 4096

actual object Crypto {

  actual fun keyFromPassword(password: String): UByteArray = memScoped {
    if (sodium_init() == -1) error("Failed to init libsodium")
    println("Hashing password.")
    val pwLen = password.length.toUInt()
    when {
      pwLen < crypto_pwhash_PASSWD_MIN -> error("Password too short.")
      pwLen > crypto_pwhash_PASSWD_MAX -> error("Password too long.")
    }
    val saltSize = crypto_pwhash_SALTBYTES
    val salt = allocArray<UByteVar>(saltSize.toInt())

    randombytes_buf(
      buf = salt,
      size = saltSize.toULong()
    )

    val outSize = crypto_secretstream_xchacha20poly1305_KEYBYTES.toInt()
    val out = allocArray<UByteVar>(outSize)
    val result = crypto_pwhash(
      out = out,
      outlen = outSize.toULong(),
      passwd = password,
      passwdlen = pwLen.toULong(),
      salt = salt,
      opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE.toULong(),
      memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE.toULong(),
      alg = crypto_pwhash_ALG_DEFAULT
    )

    if (result != 0) {
      sodium_memzero(salt, saltSize.toULong())
      error("Out of memory.")
    }
    println("Password hashed.")

    out.readBytes(outSize).asUByteArray()
  }

  actual fun encryptFile(file: String, key: UByteArray): Unit = memScoped {
    if (sodium_init() == -1) error("Failed to init libsodium")
    println("Encrypting file.")
    val k = key.pin()
    val inputBuf = allocArray<UByteVar>(FILE_CHUNK_SIZE)
    val outputSize = FILE_CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES.toInt()
    val outputBuf = allocArray<UByteVar>(outputSize)
    val headerSize = crypto_secretstream_xchacha20poly1305_HEADERBYTES.toInt()
    val header = allocArray<UByteVar>(headerSize)

    val state = cValue<crypto_secretstream_xchacha20poly1305_state> {}
    val initRes = crypto_secretstream_xchacha20poly1305_init_push(
      state = state,
      header = header,
      k = k.addressOf(0)
    )

    if (initRes != 0) {
      k.unpin()
      error("Failed to create stream.")
    }

    val inputFile = fopen(file, "rb")
    val outputFile = fopen("$file.enc", "wb")
    var eof: Int
    var tag: Int
    var readLen: ULong
    val outputLen = alloc<ULongVar>()

    fwrite(header, 1u, headerSize.toULong(), outputFile)
    do {
      readLen = fread(inputBuf, 1u, FILE_CHUNK_SIZE.toULong(), inputFile)
      eof = feof(inputFile)
      tag = if (eof == 1) crypto_secretstream_xchacha20poly1305_TAG_FINAL else 0
      val pushRes = crypto_secretstream_xchacha20poly1305_push(
        state = state,
        c = outputBuf,
        clen_p = outputLen.ptr,
        m = inputBuf,
        mlen = readLen,
        ad = null,
        adlen = 0u,
        tag = tag.toUByte()
      )
      fwrite(outputBuf, 1u, outputLen.value, outputFile)
      if (pushRes != 0 || tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        sodium_memzero(k.addressOf(0), k.get().size.toULong())
        fclose(inputFile)
        fclose(outputFile)

        k.unpin()

        if (pushRes != 0) {
          remove("$file.enc")
          error("Failed to encrypt file.")
        }
      }
    } while (eof != 1)
    remove(file)
    rename("$file.enc", file)
    println("File encrypted.")
  }

  actual fun decryptFile(file: String, key: UByteArray): Unit = memScoped {
    if (sodium_init() == -1) error("Failed to init libsodium")
    println("Decrypting file.")
    val k = key.pin()
    val inputSize = FILE_CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES.toInt()
    val inputBuf = allocArray<u_charVar>(inputSize)
    val outputBuf = allocArray<u_charVar>(FILE_CHUNK_SIZE)
    val headerSize = crypto_secretstream_xchacha20poly1305_HEADERBYTES
    val header = allocArray<UByteVar>(headerSize.toInt())

    val inputFile = fopen(file, "rb")
    val outputFile = fopen("$file.dec", "wb")
    var eof: Int
    var readLen: ULong
    val outputLen = alloc<ULongVar>()
    val tag = alloc<UByteVar>()

    fread(header, 1u, headerSize.toULong(), inputFile)
    val state = cValue<crypto_secretstream_xchacha20poly1305_state> { }
    val initRes = crypto_secretstream_xchacha20poly1305_init_pull(
      state = state,
      header = header,
      k = k.addressOf(0)
    )

    if (initRes != 0) {
      k.unpin()
      error("Failed to create stream.")
    }

    do {
      readLen = fread(inputBuf, 1u, inputSize.toULong(), inputFile)
      eof = feof(inputFile)
      val pullRes = crypto_secretstream_xchacha20poly1305_pull(
        state = state,
        m = outputBuf,
        mlen_p = outputLen.ptr,
        tag_p = tag.ptr,
        c = inputBuf,
        clen = readLen,
        ad = null,
        adlen = 0u
      )

      fwrite(outputBuf, 1u, outputLen.value, outputFile)
      if (pullRes != 0 || (eof != 1 && tag.value.toInt() == crypto_secretstream_xchacha20poly1305_TAG_FINAL)) {
        sodium_memzero(k.addressOf(0), k.get().size.toULong())
        fclose(inputFile)
        fclose(outputFile)
        remove("$file.dec")

        k.unpin()

        if (tag.value.toInt() == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
          error("Failed to decrypt file. Unexpected end of stream.")
        }

        if (pullRes != 0) {
          error("Failed to decrypt file.")
        }
      }
    } while (eof != 1)
    println("File decrypted.")
    sodium_memzero(k.addressOf(0), k.get().size.toULong())
    fclose(inputFile)
    fclose(outputFile)
    remove(file)
    rename("$file.dec", file)

    k.unpin()
  }
}
