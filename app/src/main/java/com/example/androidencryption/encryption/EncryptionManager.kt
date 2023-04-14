package com.example.androidencryption.encryption

import android.content.Context
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.Signature
import java.util.Calendar
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.security.auth.x500.X500Principal

class EncryptionManager {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ENCRYPTION_KEY = "EncryptionKey"
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
        private const val ITERATION_COUNT_KEY_PAIR = 2048
    }

    /************Key Encryption***********/

    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        this.load(null)
    }

    private val encryptionCipher = Cipher.getInstance(TRANSFORMATION).apply {
        this.init(Cipher.ENCRYPT_MODE, getKey())
    }

    private fun getDecryptCipherForIv(iv: ByteArray): Cipher {
        return Cipher.getInstance(TRANSFORMATION).apply {
            this.init(Cipher.DECRYPT_MODE, getKey(), IvParameterSpec(iv))
        }
    }

    private fun getKey(): SecretKey {
        val existingKey = keyStore.getEntry(ENCRYPTION_KEY, null) as? KeyStore.SecretKeyEntry
        return existingKey?.secretKey ?: createKey()
    }

    private fun createKey(): SecretKey {
        return KeyGenerator.getInstance(ALGORITHM).apply {
            this.init(
                KeyGenParameterSpec.Builder(ENCRYPTION_KEY, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(BLOCK_MODE)
                    .setEncryptionPaddings(PADDING)
                    .setUserAuthenticationRequired(false)
                    .setRandomizedEncryptionRequired(true)
                    .build()
            )
        }.generateKey()
    }

    fun encryptFromFile(bytes: ByteArray, outputStream: OutputStream): ByteArray{
        val encryptedBytes = encryptionCipher.doFinal(bytes)
        outputStream.use{
            it.write(encryptionCipher.iv.size)
            it.write(encryptionCipher.iv)
            it.write(encryptedBytes.size)
            it.write(encryptedBytes)
        }
        return encryptedBytes
    }

    fun decryptFromFile(inputStream: InputStream): ByteArray {
        return inputStream.use{
            val ivSize = it.read()
            val iv = ByteArray(ivSize)
            it.read(iv)

            val encryptedBytesSize = it.read()
            val encryptedBytes = ByteArray(encryptedBytesSize)
            it.read(encryptedBytes)

            getDecryptCipherForIv(iv).doFinal(encryptedBytes)
        }
    }

    fun encryptString(bytes: ByteArray): ByteArray {
        val encryptedData = encryptionCipher.doFinal(bytes)
        return mergeTwoByteArrays(encryptionCipher.iv, encryptedData)
    }

    fun decryptString(bytes: ByteArray): ByteArray {
        return getDecryptCipherForIv(bytes).doFinal(bytes)
    }

    /************Key Pair Encryption***********/

    fun getKeyPairForEncryption(keyName: String, context: Context?): KeyPair? {
        try {
            //Checking if my keypair already exists
            if (returnKeypairIfExists(keyName) != null) {
                return returnKeypairIfExists(keyName)
            }
            val start = Calendar.getInstance()
            val end = Calendar.getInstance()
            end.add(Calendar.YEAR, 99)

            //Generating a keypair with RSA and size 2048 which will be saved in the android KeyStore
            //With my keyName I can retrieve this exact keypair from the Android KeyStore
            val kpg: KeyPairGenerator = KeyPairGenerator.getInstance("RSA", ANDROID_KEYSTORE)

            kpg.initialize(
                KeyPairGeneratorSpec.Builder(context!!)
                    .setAlias(keyName)
                    .setSubject(X500Principal("CN=$keyName"))
                    .setSerialNumber(BigInteger.TEN)
                    .setKeySize(ITERATION_COUNT_KEY_PAIR)
                    .setStartDate(start.time)
                    .setEndDate(end.time)
                    .build()
            )
            return kpg.generateKeyPair()
        } catch (e: java.lang.Exception) {
            e.printStackTrace()
            deleteKey(keyName)
        }
        return null
    }

    fun signWithKey(keyName: String, data: ByteArray): ByteArray? {
        try {
            val entry = keyStore.getEntry(keyName, null)
            if (entry !is KeyStore.PrivateKeyEntry) {
                return null
            }

            //Signing the data with RSA algorithm with the PrivateKey from my Keypair with name=keyName
            val s = Signature.getInstance("SHA256withRSA")
            s.initSign(entry.privateKey)
            s.update(bytesToBase64String(data)?.toByteArray())
            return s.sign()

        } catch (e: KeyStoreException) {
            e.printStackTrace()
            deleteKey(keyName)
        }
        return ByteArray(0)
    }

    fun verifyWithKey(keyName: String, encryptedData: ByteArray, data: ByteArray): Boolean {
        try {
            val entry = keyStore.getEntry(keyName, null)
            if (entry !is KeyStore.PrivateKeyEntry) {
                return false
            }

            //Verifying that the encryptedData with RSA algorithm is the same as data with the PublicKey from my Keypair with name=keyName
            val s = Signature.getInstance("SHA256withRSA")
            s.initVerify(entry.certificate.publicKey)
            s.update(bytesToBase64String(data)?.toByteArray())
            return s.verify(encryptedData)

        } catch (e: KeyStoreException) {
            e.printStackTrace()
            deleteKey(keyName)
            return false
        }
    }

    fun encryptWithKey(keyName: String, data: ByteArray): ByteArray? {
        try {
            val entry = keyStore.getEntry(keyName, null)
            if (entry !is KeyStore.PrivateKeyEntry) {
                return null
            }

            //Encrypting the data with RSA algorithm and the PublicKey from my Keypair with name=keyName
            val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            cipher.init(Cipher.ENCRYPT_MODE, entry.certificate.publicKey)
            return cipher.doFinal(data)

        } catch (e: KeyStoreException) {
            e.printStackTrace()
            deleteKey(keyName)
            return null
        }
    }

    fun decryptWithKey(keyName: String, data: ByteArray): ByteArray? {
        try {
            val entry = keyStore.getEntry(keyName, null)
            if (entry !is KeyStore.PrivateKeyEntry) {
                return null
            }

            //Decrypting the data with RSA algorithm and the PrivateKey from my Keypair with name=keyName
            val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            cipher.init(Cipher.DECRYPT_MODE, entry.privateKey)
            return cipher.doFinal(data)

        } catch (e: Exception) {
            e.printStackTrace()
            deleteKey(keyName)
            return null
        }
    }

    /************Helper methods***********/

    fun bytesToString(bytes: ByteArray): String? {
        return bytesToBase64String(bytes)
    }

    fun stringToBytes(string: String): ByteArray? {
        return base64StringToBytes(string)
    }

    private fun bytesToBase64String(bytes: ByteArray): String? {
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    private fun base64StringToBytes(base64String: String): ByteArray? {
        return Base64.decode(base64String, Base64.NO_WRAP)
    }

    private fun mergeTwoByteArrays(firstByteArray: ByteArray, secondByteArray: ByteArray): ByteArray {
        val combined = ByteArray(firstByteArray.size + secondByteArray.size)
        for (i in combined.indices) {
            combined[i] = if (i < firstByteArray.size) {
                firstByteArray[i]
            } else {
                secondByteArray[i - firstByteArray.size]
            }
        }
        return combined
    }

    private fun returnKeypairIfExists(keyName: String): KeyPair? {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            val key = keyStore.getKey(keyName, null)

            if (key is PrivateKey) {
                // Get certificate of public key
                val cert = keyStore.getCertificate(keyName)

                // Get public key
                val publicKey = cert.publicKey

                // Return a key pair
                return KeyPair(publicKey, key)
            }

        } catch (e: Exception) {
            return null
        }
        return null
    }

    private fun deleteKey(keyName: String): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.deleteEntry(keyName)
            true
        } catch (e: java.lang.Exception) {
            false
        }
    }
}