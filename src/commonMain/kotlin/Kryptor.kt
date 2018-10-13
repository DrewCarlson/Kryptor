package kryptor

import de.dbaelz.konclik.Parameter
import de.dbaelz.konclik.konclikApp

fun main(args: Array<String>) = konclikApp(args) {
  metadata {
    name = "Kryptor"
    description = "Encrypt/Decrypt individual files or an entire folder in-place."
    version = "0.0.1"
  }
  command {
    metadata {
      name = "init"
    }
  }
  command {
    metadata {
      name = "list"
      description = "Lists the metadata for all the encrypted files in the current directory."
    }
    action { command, parameters ->

    }
  }
  command {
    metadata {
      name = "lock"
      description = "Encrypt the target file."
    }
    parameters {
      arguments = listOf(Parameter.Argument("file"))
      options = listOf(
        Parameter.Option.Switch("--recursive"),
        Parameter.Option.Switch("-r")
      )
    }
    action { command, parameters ->
      val file = parameters.positionalArguments["file"] ?: error("Missing file argument.")
      val key = Crypto.keyFromPassword(getpass("Password:")!!)
      Crypto.encryptFile(file, key)
    }
  }
  command {
    metadata {
      name = "unlock"
      description = "Decrypt the target file."
    }
    parameters {
      arguments = listOf(Parameter.Argument("file"))
      options = listOf(
        Parameter.Option.Switch("--recursive"),
        Parameter.Option.Switch("-r")
      )
    }
    action { command, parameters ->
      val file = parameters.positionalArguments["file"] ?: error("Missing file argument.")
      val key = Crypto.keyFromPassword(getpass("Password:")!!)
      Crypto.decryptFile(file, key)
    }
  }
  command {
    metadata {
      name = "burn"
      description = "Delete the target encrypted files."
    }
    parameters {
      arguments = listOf(Parameter.Argument("files"))
    }
  }
}
