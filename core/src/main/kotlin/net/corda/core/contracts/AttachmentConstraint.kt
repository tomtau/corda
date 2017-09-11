package net.corda.core.contracts

import net.corda.core.crypto.SecureHash
import net.corda.core.serialization.CordaSerializable

/** Constrain which contract-code-containing attachments can be used with a [ContractState]. */
interface AttachmentConstraint {
    /** Returns whether the given contract attachments can be used with the [ContractState] associated with this constraint object. */
    fun isSatisfiedBy(attachments: List<Attachment>): Boolean
}

/** An [AttachmentConstraint] where [isSatisfiedBy] always returns true. */
@CordaSerializable
object AlwaysAcceptAttachmentConstraint : AttachmentConstraint {
    override fun isSatisfiedBy(attachments: List<Attachment>) = true
}

/**
 * The contract attachment must match the given hash
 *
 * @property hash   Required hash for the contract attachment
 */
data class AttachmentHashConstraint(val hash: SecureHash) : AttachmentConstraint {
    override fun isSatisfiedBy(attachments: List<Attachment>): Boolean {
        TODO()
    }
}