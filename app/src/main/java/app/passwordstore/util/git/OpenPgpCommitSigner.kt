/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.git

import android.text.InputType
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity
import app.passwordstore.R
import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.util.crypto.OpenPgpNfcCard
import app.passwordstore.util.crypto.OpenPgpSmartcardStore
import app.passwordstore.util.extensions.wipe
import com.github.michaelbull.result.get
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.DigestInfo
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.PGPContentSigner
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.eclipse.jgit.api.errors.CanceledException
import org.eclipse.jgit.lib.CommitBuilder
import org.eclipse.jgit.lib.GpgSignature
import org.eclipse.jgit.lib.GpgSigner
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.transport.CredentialsProvider

class OpenPgpCommitSigner(
  private val activity: FragmentActivity,
  private val keyManager: PGPKeyManager,
  private val smartcardStore: OpenPgpSmartcardStore,
) : GpgSigner() {

  override fun sign(
    commit: CommitBuilder,
    gpgSigningKey: String?,
    committer: PersonIdent,
    credentialsProvider: CredentialsProvider?,
  ) {
    val signingKey = resolveSigningKey(gpgSigningKey)
    val primaryKeyId =
      KeyUtils.tryGetKeyId(signingKey)
        ?: throw PGPException("Cannot determine OpenPGP signing key ID")
    val signature =
      if (smartcardStore.hasAssociation(primaryKeyId)) {
        signWithSmartcard(signingKey, primaryKeyId, commit.build())
      } else {
        signWithSecretKey(signingKey, commit.build())
      }
    commit.setGpgSignature(GpgSignature(signature))
  }

  override fun canLocateSigningKey(
    gpgSigningKey: String?,
    committer: PersonIdent,
    credentialsProvider: CredentialsProvider?,
  ): Boolean = runCatching { resolveSigningKey(gpgSigningKey) }.isSuccess

  private fun resolveSigningKey(gpgSigningKey: String?): PGPKey {
    val identifiers =
      gpgSigningKey?.let(PGPIdentifier::fromString)?.let(::listOf) ?: rootGpgIdentifiers()
    identifiers.forEach { identifier ->
      keyManager.getKeyById(identifier).get()?.let {
        return it
      }
    }
    throw PGPException("No OpenPGP key from .gpg-id is available for Git commit signing")
  }

  private fun rootGpgIdentifiers(): List<PGPIdentifier> {
    val gpgIdFile = PasswordRepository.getRepositoryDirectory().resolve(".gpg-id")
    if (!gpgIdFile.isFile) throw PGPException("No root .gpg-id found for Git commit signing")
    return gpgIdFile
      .readLines()
      .map { it.substringBefore('#').substringBefore('!').trim() }
      .filter { it.isNotEmpty() && it != "gpg-id" }
      .mapNotNull(PGPIdentifier::fromString)
  }

  private fun signWithSecretKey(key: PGPKey, payload: ByteArray): ByteArray {
    val secretKey = findSecretSigningKey(key)
    if (secretKey.isPrivateKeyEmpty) {
      throw PGPException("Git commit signing key is a smartcard stub without a card association")
    }
    val passphrase =
      askSecret(
        titleRes = R.string.git_signing_passphrase_title,
        hintRes = R.string.ssh_keygen_passphrase,
      )
    try {
      val decryptor =
        BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(passphrase)
      val privateKey = secretKey.extractPrivateKey(decryptor)
      return buildDetachedSignature(
        secretKey.publicKey,
        BcPGPContentSignerBuilder(secretKey.publicKey.algorithm, HashAlgorithmTags.SHA256),
        privateKey,
        payload,
      )
    } finally {
      passphrase.wipe()
    }
  }

  private fun signWithSmartcard(
    key: PGPKey,
    primaryKeyId: PGPIdentifier.KeyId,
    payload: ByteArray,
  ): ByteArray {
    val cardFingerprints = smartcardStore.getFingerprints(primaryKeyId)
    val publicKey = findCardSigningKey(key, cardFingerprints)
    val pin =
      askSecret(
        titleRes = R.string.git_signing_card_pin_title,
        hintRes = R.string.openpgp_card_pin_hint,
      )
    try {
      val card =
        waitForSigningCard() ?: throw CanceledException(activity.getString(R.string.dialog_cancel))
      card.use {
        val privateKey = PGPPrivateKey(publicKey.keyID, publicKey.publicKeyPacket, null)
        return buildDetachedSignature(
          publicKey,
          CardContentSignerBuilder(publicKey, pin, it),
          privateKey,
          payload,
        )
      }
    } finally {
      pin.wipe()
    }
  }

  private fun waitForSigningCard(): OpenPgpNfcCard? {
    val dialogRef = AtomicReference<android.app.Dialog?>()
    return runBlocking {
      val cardResult = CompletableDeferred<OpenPgpNfcCard?>()
      val waitJob = AtomicReference<Job?>()
      withContext(Dispatchers.Main) {
        dialogRef.set(
          MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.openpgp_nfc_decrypt_title)
            .setMessage(R.string.git_signing_tap_card)
            .setNegativeButton(R.string.dialog_cancel) { _, _ ->
              waitJob.get()?.cancel()
              OpenPgpNfcCard.disableReaderMode(activity)
              cardResult.complete(null)
            }
            .setCancelable(false)
            .show()
        )
        waitJob.set(
          CoroutineScope(Dispatchers.Main).launch {
            runCatching {
                OpenPgpNfcCard.waitForCard(
                  activity,
                  disableReaderModeOnError = true,
                  disableReaderModeOnClose = true,
                )
              }
              .fold(
                onSuccess = { cardResult.complete(it) },
                onFailure = { cardResult.completeExceptionally(it) },
              )
          }
        )
      }
      try {
        cardResult.await()
      } finally {
        waitJob.get()?.cancel()
        withContext(Dispatchers.Main) { dialogRef.get()?.dismiss() }
      }
    }
  }

  private fun findSecretSigningKey(key: PGPKey): PGPSecretKey {
    val rings =
      PGPSecretKeyRingCollection(
        PGPUtil.getDecoderStream(key.contents.inputStream()),
        JcaKeyFingerprintCalculator(),
      )
    return rings.keyRings
      .asSequence()
      .flatMap { it.secretKeys.asSequence() }
      .firstOrNull { it.isSigningKey }
      ?: throw PGPException("No signing-capable OpenPGP secret key found")
  }

  private fun publicKeys(key: PGPKey): Sequence<PGPPublicKey> =
    runCatching {
        PGPSecretKeyRingCollection(
            PGPUtil.getDecoderStream(key.contents.inputStream()),
            JcaKeyFingerprintCalculator(),
          )
          .keyRings
          .asSequence()
          .flatMap { it.secretKeys.asSequence() }
          .map { it.publicKey }
      }
      .getOrElse {
        PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(key.contents.inputStream()),
            JcaKeyFingerprintCalculator(),
          )
          .keyRings
          .asSequence()
          .flatMap { it.publicKeys.asSequence() }
      }

  private fun findCardSigningKey(key: PGPKey, cardFingerprints: List<ByteArray>): PGPPublicKey {
    return publicKeys(key).firstOrNull { publicKey ->
      publicKey.algorithm in RSA_SIGNING_ALGORITHMS &&
        cardFingerprints.any { it.contentEquals(publicKey.fingerprint) }
    } ?: throw PGPException("No RSA signing key matching this OpenPGP card was found")
  }

  private fun buildDetachedSignature(
    publicKey: PGPPublicKey,
    signerBuilder: PGPContentSignerBuilder,
    privateKey: PGPPrivateKey,
    payload: ByteArray,
  ): ByteArray {
    val generator = PGPSignatureGenerator(signerBuilder, publicKey)
    generator.init(PGPSignature.BINARY_DOCUMENT, privateKey)
    generator.update(payload)
    val out = ByteArrayOutputStream()
    ArmoredOutputStream(out).use { armored -> generator.generate().encode(armored) }
    return out.toByteArray()
  }

  private fun askSecret(titleRes: Int, hintRes: Int): CharArray {
    val result = AtomicReference<CharArray?>()
    val latch = CountDownLatch(1)
    activity.runOnUiThread {
      val input = TextInputEditText(activity)
      input.inputType =
        InputType.TYPE_CLASS_TEXT or
          InputType.TYPE_TEXT_VARIATION_PASSWORD or
          InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
      val layout =
        TextInputLayout(activity).apply {
          hint = activity.getString(hintRes)
          addView(input)
        }
      val dialog =
        MaterialAlertDialogBuilder(activity)
          .setTitle(titleRes)
          .setView(layout)
          .setPositiveButton(android.R.string.ok) { _, _ ->
            val text = input.text
            result.set(text?.let { CharArray(it.length) { index -> it[index] } } ?: charArrayOf())
            text?.clear()
            latch.countDown()
          }
          .setNegativeButton(R.string.dialog_cancel) { _, _ -> latch.countDown() }
          .setOnCancelListener { latch.countDown() }
          .show()
      dialog.window?.setFlags(
        WindowManager.LayoutParams.FLAG_SECURE,
        WindowManager.LayoutParams.FLAG_SECURE,
      )
    }
    latch.await()
    return result.get() ?: throw CanceledException(activity.getString(R.string.dialog_cancel))
  }

  private class CardContentSignerBuilder(
    private val publicKey: PGPPublicKey,
    private val pin: CharArray,
    private val card: OpenPgpNfcCard,
  ) : PGPContentSignerBuilder {

    override fun build(signatureType: Int, privateKey: PGPPrivateKey): PGPContentSigner {
      if (publicKey.algorithm !in RSA_SIGNING_ALGORITHMS) {
        throw PGPException("NFC OpenPGP commit signing currently supports RSA card keys only")
      }
      val digestCalculator = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256)
      return object : PGPContentSigner {
        override fun getOutputStream(): OutputStream = digestCalculator.outputStream

        override fun getSignature(): ByteArray {
          val digestInfo =
            DigestInfo(
                AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE),
                digestCalculator.digest,
              )
              .encoded
          card.verifySignaturePin(pin)
          return card.computeDigitalSignature(
            digestInfo,
            expectedLength = (publicKey.bitStrength + 7) / 8,
          )
        }

        override fun getDigest(): ByteArray = digestCalculator.digest

        override fun getType(): Int = signatureType

        override fun getHashAlgorithm(): Int = HashAlgorithmTags.SHA256

        override fun getKeyAlgorithm(): Int = publicKey.algorithm

        override fun getKeyID(): Long = publicKey.keyID
      }
    }
  }

  companion object {
    private val RSA_SIGNING_ALGORITHMS =
      setOf(PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_SIGN)
  }
}
