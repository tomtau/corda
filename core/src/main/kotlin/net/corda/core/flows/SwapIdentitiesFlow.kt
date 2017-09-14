package net.corda.core.flows

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.crypto.DigitalSignature
import net.corda.core.crypto.secureRandomBytes
import net.corda.core.identity.AnonymousParty
import net.corda.core.identity.Party
import net.corda.core.identity.PartyAndCertificate
import net.corda.core.node.services.IdentityService
import net.corda.core.serialization.CordaSerializable
import net.corda.core.serialization.SerializedBytes
import net.corda.core.serialization.deserialize
import net.corda.core.serialization.serialize
import net.corda.core.utilities.ProgressTracker
import net.corda.core.utilities.UntrustworthyData
import net.corda.core.utilities.unwrap
import java.io.ByteArrayOutputStream
import java.security.SignatureException

/**
 * Very basic flow which generates new confidential identities for parties in a transaction and exchanges the transaction
 * key and certificate paths between the parties. This is intended for use as a subflow of another flow which builds a
 * transaction.
 */
@StartableByRPC
@InitiatingFlow
class SwapIdentitiesFlow(val otherSide: Party,
                         val revocationEnabled: Boolean,
                         override val progressTracker: ProgressTracker) : FlowLogic<LinkedHashMap<Party, AnonymousParty>>() {
    constructor(otherSide: Party) : this(otherSide, false, tracker())

    companion object {
        object AWAITING_KEY : ProgressTracker.Step("Awaiting key")
        val NONCE_SIZE_BYTES = 16

        fun tracker() = ProgressTracker(AWAITING_KEY)
        fun buildDataToSign(identity: SerializedBytes<PartyAndCertificate>, nonce: ByteArray): ByteArray {
            val buffer = ByteArrayOutputStream(1024)
            buffer.write(identity.bytes)
            buffer.write(nonce)
            return buffer.toByteArray()
        }

        @Throws(SwapIdentitiesException::class)
        fun validateAndRegisterIdentity(identityService: IdentityService,
                                        otherSide: Party,
                                        anonymousOtherSideBytes: SerializedBytes<PartyAndCertificate>,
                                        nonce: ByteArray,
                                        sigBytes: ByteArray): PartyAndCertificate {
            val anonymousOtherSide: PartyAndCertificate = anonymousOtherSideBytes.deserialize()
            if (anonymousOtherSide.name != otherSide.name) {
                throw SwapIdentitiesException("Certificate subject must match counterparty's well known identity.")
            }
            val signature = DigitalSignature.WithKey(anonymousOtherSide.owningKey, sigBytes)
            val sigWithKey = DigitalSignature.WithKey(anonymousOtherSide.owningKey, signature.bytes)
            try {
                sigWithKey.verify(buildDataToSign(anonymousOtherSideBytes, nonce))
            } catch(ex: SignatureException) {
                throw SwapIdentitiesException("Signature does not match the given identity and nonce.", ex)
            }
            // Validate then store their identity so that we can prove the key in the transaction is owned by the
            // counterparty.
            identityService.verifyAndRegisterIdentity(anonymousOtherSide)
            return anonymousOtherSide
        }
    }

    @Suspendable
    override fun call(): LinkedHashMap<Party, AnonymousParty> {
        progressTracker.currentStep = AWAITING_KEY
        val legalIdentityAnonymous = serviceHub.keyManagementService.freshKeyAndCert(serviceHub.myInfo.legalIdentityAndCert, revocationEnabled)
        val serializedIdentity = SerializedBytes<PartyAndCertificate>(legalIdentityAnonymous.serialize().bytes)

        // Special case that if we're both parties, a single identity is generated
        val identities = LinkedHashMap<Party, AnonymousParty>()
        identities.put(serviceHub.myInfo.legalIdentity, legalIdentityAnonymous.party.anonymise())
        if (otherSide != serviceHub.myInfo.legalIdentity) {
            val ourNonce = secureRandomBytes(NONCE_SIZE_BYTES)
            val theirNonce = sendAndReceive<ByteArray>(otherSide, ourNonce).unwrap(NonceVerifier)
            val data = buildDataToSign(serializedIdentity, theirNonce)
            val ourSig: DigitalSignature = serviceHub.keyManagementService.sign(data, legalIdentityAnonymous.owningKey)
            val anonymousOtherSide = sendAndReceive<IdentityWithSignature>(otherSide, IdentityWithSignature(serializedIdentity, ourSig.bytes)).unwrap { (confidentialIdentityBytes, theirSigBytes) ->
                validateAndRegisterIdentity(serviceHub.identityService, otherSide, confidentialIdentityBytes, ourNonce, theirSigBytes)
            }
            identities.put(serviceHub.myInfo.legalIdentity, legalIdentityAnonymous.party.anonymise())
            identities.put(otherSide, anonymousOtherSide.party.anonymise())
        }
        return identities
    }

    @CordaSerializable
    data class IdentityWithSignature(val identity: SerializedBytes<PartyAndCertificate>, val signature: ByteArray)

    object NonceVerifier : UntrustworthyData.Validator<ByteArray, ByteArray> {
        override fun validate(data: ByteArray): ByteArray {
            if (data.size != NONCE_SIZE_BYTES)
                throw SwapIdentitiesException("Nonce must be $NONCE_SIZE_BYTES bytes.")
            val zeroByte = 0.toByte()
            if (data.all { it == zeroByte })
                throw SwapIdentitiesException("Nonce must not be all zeroes.")
            return data
        }
    }
}

open class SwapIdentitiesException @JvmOverloads constructor(message: String, cause: Throwable? = null)
    : FlowException(message, cause)