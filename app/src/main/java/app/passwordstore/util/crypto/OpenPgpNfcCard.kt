/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.crypto

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import app.passwordstore.R
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

class OpenPgpNfcCard(
  private val isoDep: IsoDep,
  private val onClose: () -> Unit = {},
) : AutoCloseable {

  fun selectOpenPgpApplet() {
    transceive(SELECT_OPENPGP)
  }

  fun verifyUserPin(pin: CharArray) {
    verifyPin(pin, reference = 0x82)
  }

  fun verifySignaturePin(pin: CharArray) {
    verifyPin(pin, reference = 0x81)
  }

  private fun verifyPin(pin: CharArray, reference: Int) {
    val pinBytes = pin.concatToString().toByteArray(Charsets.UTF_8)
    try {
      transceive(
        byteArrayOf(0x00, 0x20, 0x00, reference.toByte(), pinBytes.size.toByte()) + pinBytes
      )
    } finally {
      pinBytes.fill(0)
    }
  }

  fun decipher(ciphertext: ByteArray): ByteArray {
    val payload = byteArrayOf(0x00) + ciphertext
    return transceiveData(0x2A, 0x80, 0x86, payload, expectedLength = ciphertext.size)
  }

  fun computeDigitalSignature(digestInfo: ByteArray, expectedLength: Int): ByteArray {
    return transceiveData(0x2A, 0x9E, 0x9A, digestInfo, expectedLength)
  }

  fun readCardInfo(): OpenPgpCardInfo {
    val applicationData = transceive(GET_APPLICATION_RELATED_DATA)
    val fingerprints = findTlv(applicationData, 0xC5)?.let(::parseFingerprints).orEmpty()
    val url = runCatching { transceive(GET_URL).toString(Charsets.UTF_8).trim() }.getOrNull()
    return OpenPgpCardInfo(fingerprints = fingerprints, url = url?.takeIf { it.isNotBlank() })
  }

  override fun close() {
    runCatching { isoDep.close() }
    onClose()
  }

  private fun transceive(command: ByteArray): ByteArray {
    val response = isoDep.transceive(command)
    if (response.size < 2) throw IOException("Malformed NFC response")
    val sw1 = response[response.size - 2].toInt() and 0xff
    val sw2 = response[response.size - 1].toInt() and 0xff
    val data = response.copyOf(response.size - 2)
    if (sw1 == 0x90 && sw2 == 0x00) return data
    if (sw1 == 0x61)
      return data + transceive(byteArrayOf(0x00, 0xC0.toByte(), 0x00, 0x00, sw2.toByte()))
    if (sw1 == 0x6C) return transceive(command.copyOf(command.size - 1) + sw2.toByte())
    throw OpenPgpCardStatusException(sw1, sw2)
  }

  private fun transceiveData(
    ins: Int,
    p1: Int,
    p2: Int,
    payload: ByteArray,
    expectedLength: Int,
  ): ByteArray {
    return if (payload.size <= MAX_APDU_NC) {
      transceiveShort(ins, p1, p2, payload, expectedLength)
    } else {
      transceiveChained(ins, p1, p2, payload, expectedLength)
    }
  }

  private fun transceiveShort(
    ins: Int,
    p1: Int,
    p2: Int,
    payload: ByteArray,
    expectedLength: Int,
  ): ByteArray {
    val command =
      byteArrayOf(0x00, ins.toByte(), p1.toByte(), p2.toByte(), payload.size.toByte()) +
        payload +
        encodeShortLe(expectedLength)
    return transceive(command)
  }

  private fun transceiveChained(
    ins: Int,
    p1: Int,
    p2: Int,
    payload: ByteArray,
    expectedLength: Int,
  ): ByteArray {
    val chunkSize = (isoDep.maxTransceiveLength - 6).coerceIn(1, MAX_APDU_NC)
    var offset = 0
    var response = byteArrayOf()
    while (offset < payload.size) {
      val end = minOf(offset + chunkSize, payload.size)
      val chunk = payload.copyOfRange(offset, end)
      val isLast = end == payload.size
      val cla = if (isLast) 0x00 else 0x10
      val command =
        byteArrayOf(cla.toByte(), ins.toByte(), p1.toByte(), p2.toByte(), chunk.size.toByte()) +
          chunk +
          if (isLast) encodeShortLe(expectedLength) else byteArrayOf()
      response = transceive(command)
      offset = end
    }
    return response
  }

  @Suppress("unused")
  private fun transceiveExtended(ins: Int, p1: Int, p2: Int, payload: ByteArray): ByteArray {
    val lc = payload.size
    val command =
      byteArrayOf(
        0x00,
        ins.toByte(),
        p1.toByte(),
        p2.toByte(),
        0x00,
        ((lc ushr 8) and 0xff).toByte(),
        (lc and 0xff).toByte(),
      ) + payload + byteArrayOf(0x00, 0x00)
    return transceive(command)
  }

  companion object {
    private const val MAX_APDU_NC = 254

    private fun encodeShortLe(expectedLength: Int): ByteArray =
      byteArrayOf(if (expectedLength >= 256) 0x00 else expectedLength.toByte())

    private val OPENPGP_AID = byteArrayOf(0xD2.toByte(), 0x76, 0x00, 0x01, 0x24, 0x01)
    private val SELECT_OPENPGP =
      byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, OPENPGP_AID.size.toByte()) +
        OPENPGP_AID +
        byteArrayOf(0x00)
    private val GET_APPLICATION_RELATED_DATA = byteArrayOf(0x00, 0xCA.toByte(), 0x00, 0x6E, 0x00)
    private val GET_URL = byteArrayOf(0x00, 0xCA.toByte(), 0x5F, 0x50, 0x00)

    private fun parseFingerprints(value: ByteArray): List<ByteArray> =
      value
        .asSequence()
        .chunked(20)
        .map { it.toByteArray() }
        .filter { fingerprint -> fingerprint.any { it != 0.toByte() } }
        .toList()

    private fun findTlv(data: ByteArray, expectedTag: Int): ByteArray? {
      var offset = 0
      while (offset < data.size) {
        val (tag, tagEnd) = readTag(data, offset)
        val (length, valueOffset) = readLength(data, tagEnd)
        val valueEnd = valueOffset + length
        if (valueEnd > data.size) return null
        val value = data.copyOfRange(valueOffset, valueEnd)
        if (tag == expectedTag) return value
        if (tag == 0x6E || tag == 0x73)
          findTlv(value, expectedTag)?.let {
            return it
          }
        offset = valueEnd
      }
      return null
    }

    private fun readTag(data: ByteArray, offset: Int): Pair<Int, Int> {
      var cursor = offset
      var tag = data[cursor++].toInt() and 0xff
      if (tag and 0x1f == 0x1f) {
        do {
          val next = data[cursor++].toInt() and 0xff
          tag = (tag shl 8) or next
        } while (next and 0x80 == 0x80 && cursor < data.size)
      }
      return tag to cursor
    }

    private fun readLength(data: ByteArray, offset: Int): Pair<Int, Int> {
      var cursor = offset
      val first = data[cursor++].toInt() and 0xff
      if (first and 0x80 == 0) return first to cursor
      val count = first and 0x7f
      var length = 0
      repeat(count) { length = (length shl 8) or (data[cursor++].toInt() and 0xff) }
      return length to cursor
    }

    fun disableReaderMode(activity: Activity) {
      NfcAdapter.getDefaultAdapter(activity)?.disableReaderMode(activity)
    }

    suspend fun waitForCard(
      activity: Activity,
      disableReaderModeOnError: Boolean = true,
      disableReaderModeOnClose: Boolean = true,
    ): OpenPgpNfcCard = suspendCancellableCoroutine { continuation ->
      val adapter = NfcAdapter.getDefaultAdapter(activity)
      if (adapter == null || !adapter.isEnabled) {
        continuation.resumeWithException(
          IOException(activity.getString(R.string.openpgp_nfc_unavailable))
        )
        return@suspendCancellableCoroutine
      }
      val completed = AtomicBoolean(false)

      val callback = NfcAdapter.ReaderCallback { tag: Tag ->
        if (!completed.compareAndSet(false, true)) return@ReaderCallback
        try {
          val isoDep =
            IsoDep.get(tag)
              ?: throw IOException(activity.getString(R.string.openpgp_nfc_not_iso_dep))
          isoDep.connect()
          isoDep.timeout = 30_000
          val card =
            OpenPgpNfcCard(isoDep) {
              if (disableReaderModeOnClose) {
                activity.runOnUiThread { adapter.disableReaderMode(activity) }
              }
            }
          card.selectOpenPgpApplet()
          continuation.resume(card)
        } catch (e: Throwable) {
          if (disableReaderModeOnError) {
            activity.runOnUiThread { adapter.disableReaderMode(activity) }
          }
          continuation.resumeWithException(e)
        }
      }

      adapter.enableReaderMode(
        activity,
        callback,
        NfcAdapter.FLAG_READER_NFC_A or
          NfcAdapter.FLAG_READER_NFC_B or
          NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or
          NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
        Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 500) },
      )
      continuation.invokeOnCancellation {
        if (completed.compareAndSet(false, true)) adapter.disableReaderMode(activity)
      }
    }
  }
}

class OpenPgpCardStatusException(val sw1: Int, val sw2: Int) :
  IOException(
    "OpenPGP card returned ${sw1.toString(16).padStart(2, '0')} " +
      sw2.toString(16).padStart(2, '0')
  ) {

  val isAuthenticationFailure: Boolean
    get() = sw1 == 0x69 && sw2 == 0x82 || sw1 == 0x63 && sw2 in 0xC0..0xCF
}

data class OpenPgpCardInfo(val fingerprints: List<ByteArray>, val url: String?)
