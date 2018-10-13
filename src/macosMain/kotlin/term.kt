package kryptor

import kotlinx.cinterop.toKString

actual fun readLine(): String? {
  return kotlin.io.readLine()
}

actual fun getpass(prompt: String): String? {
  return platform.posix.getpass(prompt)?.toKString()
}
