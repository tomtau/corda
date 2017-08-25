package net.corda.core.transactions

import net.corda.core.contracts.*
import net.corda.core.contracts.ComponentGroupEnum.*
import net.corda.core.crypto.*
import net.corda.core.identity.Party
import net.corda.core.internal.Emoji
import net.corda.core.internal.VisibleForTesting
import net.corda.core.node.ServicesForResolution
import net.corda.core.serialization.*
import net.corda.core.utilities.OpaqueBytes
import java.security.PublicKey
import java.security.SignatureException
import java.util.function.Predicate

/**
 * A transaction ready for serialisation, without any signatures attached. A WireTransaction is usually wrapped
 * by a [SignedTransaction] that carries the signatures over this payload.
 * The identity of the transaction is the Merkle tree root of its components (see [MerkleTree]).
 *
 * A few notes about backwards compatibility:
 * A wire transaction can be backwards compatible, in the sense that if an old client receives a [componentGroups] with
 * more elements than expected, it will normally deserialise the required objects and omit any checks in the optional
 * new fields. Moreover, because Merkle tree is constructed from the received list of [ComponentGroup], which internally
 * deals with bytes, any client can compute the Merkle tree and on the same time relay a [WireTransaction] object even
 * if she is unable to read some of the "optional" component types. We stress out that practically, a new type of
 * [WireTransaction] should only be considered compatible if and only if the following rules apply:
 * <p><ul>
 * <li>Component-type ordering is fixed (eg. inputs, then outputs, then commands etc, see [ComponentGroupEnum] for the actual ordering).
 * <li>Removing a component-type that existed in older wire transaction types is not allowed, because it will affect the Merkle tree structure.
 * <li>Changing the order of existing component types is also not allowed, for the same reason.
 * <li>New component types must be added at the end of the list of [ComponentGroup] and update the [ComponentGroupEnum] with the new type. After a component is added, its ordinal must never change.
 * <li>A new component type should always be an "optional value", in the sense that lack of its visibility does not change the transaction and contract logic and details. An example of "optional" components could be a transaction summary or some statistics.
 * </ul></p>
 */
@CordaSerializable
data class WireTransaction(val componentGroups: List<ComponentGroup>, override val privacySalt: PrivacySalt = PrivacySalt()) : CoreTransaction(), TraversableTransaction {

    @Deprecated("Required only in some unit-tests and for backwards compatibility purposes.", ReplaceWith("WireTransaction(val componentGroups: List<ComponentGroup>, override val privacySalt: PrivacySalt)"), DeprecationLevel.WARNING)
    constructor(inputs: List<StateRef>,
                attachments: List<SecureHash>,
                outputs: List<TransactionState<ContractState>>,
                commands: List<Command<*>>,
                notary: Party?,
                timeWindow: TimeWindow?,
                privacySalt: PrivacySalt = PrivacySalt()
    ) : this(createComponentGroups(inputs, outputs, commands, attachments, notary, timeWindow), privacySalt)


    init {
        check(ComponentGroupEnum.values().size <= componentGroups.size  ) { "Malformed WireTransaction, expected at least ${ComponentGroupEnum.values().size} tx component types, but received ${componentGroups.size}" }
    }

    /** Hashes of the ZIP/JAR files that are needed to interpret the contents of this wire transaction. */
    override val attachments: List<SecureHash> = deserialiseComponentGroup(ATTACHMENTS_GROUP, { SerializedBytes<SecureHash>(it).deserialize() })

    /** Pointers to the input states on the ledger, identified by (tx identity hash, output index). */
    override val inputs: List<StateRef> = deserialiseComponentGroup(INPUTS_GROUP, { SerializedBytes<StateRef>(it).deserialize() })

    override val outputs: List<TransactionState<ContractState>> = deserialiseComponentGroup(OUTPUTS_GROUP, { SerializedBytes<TransactionState<ContractState>>(it).deserialize(context = SerializationFactory.defaultFactory.defaultContext.withAttachmentsClassLoader(attachments)) })

    /** Ordered list of ([CommandData], [PublicKey]) pairs that instruct the contracts what to do. */
    override val commands: List<Command<*>> = deserialiseComponentGroup(COMMANDS_GROUP, { SerializedBytes<Command<*>>(it).deserialize(context = SerializationFactory.defaultFactory.defaultContext.withAttachmentsClassLoader(attachments)) })

    override val notary: Party? = let {
        val notaries: List<Party> = deserialiseComponentGroup(NOTARY_GROUP, { SerializedBytes<Party>(it).deserialize() })
        check(notaries.size <= 1) { "Invalid Transaction. More than 1 notary party detected." }
        if (notaries.isNotEmpty()) notaries[0] else null
    }
    override val timeWindow: TimeWindow? = let {
        val timeWindows: List<TimeWindow> = deserialiseComponentGroup(TIMEWINDOW_GROUP, { SerializedBytes<TimeWindow>(it).deserialize() })
        check(timeWindows.size <= 1) { "Invalid Transaction. More than 1 time-window detected." }
        if (timeWindows.isNotEmpty()) timeWindows[0] else null
    }

    // Helper function to return a meaningful exception if deserialisation of a component fails.
    private fun <T> deserialiseComponentGroup(groupEnum: ComponentGroupEnum, deserialiseBody: (ByteArray) -> T): List<T> {
        return componentGroups[groupEnum.ordinal].components.mapIndexed { internalIndex, component ->
            try {
                deserialiseBody(component.bytes)
            } catch (e: MissingAttachmentsException) {
                throw e
            } catch (e: Exception) {
                throw Exception("Malformed WireTransaction, $groupEnum at index $internalIndex cannot be deserialised", e)
            }
        }
    }

    init {
        checkBaseInvariants()
        check(inputs.isNotEmpty() || outputs.isNotEmpty()) { "A transaction must contain at least one input or output state" }
        check(commands.isNotEmpty()) { "A transaction must contain at least one command" }
        if (timeWindow != null) check(notary != null) { "Transactions with time-windows must be notarised" }
    }

    /** The transaction id is represented by the root hash of Merkle tree over the transaction components. */
    override val id: SecureHash get() = merkleTree.hash

    /** Public keys that need to be fulfilled by signatures in order for the transaction to be valid. */
    val requiredSigningKeys: Set<PublicKey> get() {
        val commandKeys = commands.flatMap { it.signers }.toSet()
        // TODO: prevent notary field from being set if there are no inputs and no timestamp.
        return if (notary != null && (inputs.isNotEmpty() || timeWindow != null)) {
            commandKeys + notary.owningKey
        } else {
            commandKeys
        }
    }

    /**
     * Looks up identities and attachments from storage to generate a [LedgerTransaction]. A transaction is expected to
     * have been fully resolved using the resolution flow by this point.
     *
     * @throws AttachmentResolutionException if a required attachment was not found in storage.
     * @throws TransactionResolutionException if an input points to a transaction not found in storage.
     */
    @Throws(AttachmentResolutionException::class, TransactionResolutionException::class)
    fun toLedgerTransaction(services: ServicesForResolution): LedgerTransaction {
        return toLedgerTransaction(
                resolveIdentity = { services.identityService.partyFromKey(it) },
                resolveAttachment = { services.attachments.openAttachment(it) },
                resolveStateRef = { services.loadState(it) }
        )
    }

    /**
     * Looks up identities, attachments and dependent input states using the provided lookup functions in order to
     * construct a [LedgerTransaction]. Note that identity lookup failure does *not* cause an exception to be thrown.
     *
     * @throws AttachmentResolutionException if a required attachment was not found using [resolveAttachment].
     * @throws TransactionResolutionException if an input was not found not using [resolveStateRef].
     */
    @Throws(AttachmentResolutionException::class, TransactionResolutionException::class)
    fun toLedgerTransaction(
            resolveIdentity: (PublicKey) -> Party?,
            resolveAttachment: (SecureHash) -> Attachment?,
            resolveStateRef: (StateRef) -> TransactionState<*>?
    ): LedgerTransaction {
        // Look up public keys to authenticated identities. This is just a stub placeholder and will all change in future.
        val authenticatedArgs = commands.map {
            val parties = it.signers.mapNotNull { pk -> resolveIdentity(pk) }
            CommandWithParties(it.signers, parties, it.value)
        }
        // Open attachments specified in this transaction. If we haven't downloaded them, we fail.
        val attachments = attachments.map { resolveAttachment(it) ?: throw AttachmentResolutionException(it) }
        val resolvedInputs = inputs.map { ref ->
            resolveStateRef(ref)?.let { StateAndRef(it, ref) } ?: throw TransactionResolutionException(ref.txhash)
        }
        return LedgerTransaction(resolvedInputs, outputs, authenticatedArgs, attachments, id, notary, timeWindow, privacySalt)
    }

    /**
     * Build filtered transaction using provided filtering functions.
     */
    fun buildFilteredTransaction(filtering: Predicate<Any>): FilteredTransaction {
        return FilteredTransaction.buildFilteredTransaction(this, filtering)
    }

    /**
     * Builds whole Merkle tree for a transaction.
     */
    val merkleTree: MerkleTree by lazy { MerkleTree.getMerkleTree(listOf(privacySalt.sha256()) + groupsMerkleRoots) }

    /**
     * Calculate the hashes of the sub-components of the transaction, that are used to build its Merkle tree.
     * The root of the tree is the transaction identifier. The tree structure is helpful for privacy, please
     * see the user-guide section "Transaction tear-offs" to learn more about this topic.
     */
    @VisibleForTesting
    val groupsMerkleRoots: List<SecureHash> get() = componentGroups.mapIndexed { index, (components) ->
        if (components.isNotEmpty()) {
            MerkleTree.getMerkleTree(availableComponentHashes[index]).hash
        } else {
            SecureHash.zeroHash
        }
    }

    /**
     * Checks that the given signature matches one of the commands and that it is a correct signature over the tx.
     *
     * @throws SignatureException if the signature didn't match the transaction contents.
     * @throws IllegalArgumentException if the signature key doesn't appear in any command.
     */
    fun checkSignature(sig: TransactionSignature) {
        require(commands.any { it.signers.any { sig.by in it.keys } }) { "Signature key doesn't match any command" }
        sig.verify(id)
    }

    override fun toString(): String {
        val buf = StringBuilder()
        buf.appendln("Transaction:")
        for (input in inputs) buf.appendln("${Emoji.rightArrow}INPUT:      $input")
        for ((data) in outputs) buf.appendln("${Emoji.leftArrow}OUTPUT:     $data")
        for (command in commands) buf.appendln("${Emoji.diamond}COMMAND:    $command")
        for (attachment in attachments) buf.appendln("${Emoji.paperclip}ATTACHMENT: $attachment")
        return buf.toString()
    }

    internal companion object {
        /**
         * Creating list of [ComponentGroup] used in one of the constructors of [WireTransaction] required
         * for backwards compatibility purposes.
         */
        fun createComponentGroups(inputs: List<StateRef>,
                                  outputs: List<TransactionState<ContractState>>,
                                  commands: List<Command<*>>,
                                  attachments: List<SecureHash>,
                                  notary: Party?,
                                  timeWindow: TimeWindow?): List<ComponentGroup> {
            val inputsGroup = ComponentGroup(inputs.map { it.serialize() })
            val outputsGroup = ComponentGroup(outputs.map { it.serialize(context = SerializationFactory.defaultFactory.defaultContext.withAttachmentsClassLoader(attachments)) })
            val commandsGroup = ComponentGroup(commands.map { it.serialize(context = SerializationFactory.defaultFactory.defaultContext.withAttachmentsClassLoader(attachments)) })
            val attachmentsGroup = ComponentGroup(attachments.map { it.serialize() })
            val notaryGroup = ComponentGroup(if (notary != null) listOf(notary.serialize()) else emptyList())
            val timeWindowGroup = ComponentGroup(if (timeWindow != null) listOf(timeWindow.serialize()) else emptyList())
            return listOf(inputsGroup, outputsGroup, commandsGroup, attachmentsGroup, notaryGroup, timeWindowGroup)
        }
    }

    /** Calculate nonces for every transaction component, including new fields (due to backwards compatibility support) we cannot process. */
    val availableComponentNonces: List<List<SecureHash>>
        get() = componentGroups.mapIndexed { componentGroupIndex, (components) -> components.mapIndexed {
            internalIndex, internalIt -> serializedHash(internalIt, privacySalt, componentGroupIndex, internalIndex) }
        }

    /**
     * Calculate hasehs for every transaction component. These will be used to build the full Merkle tree.
     * The root of the tree is the transaction identifier. The tree structure is helpful for privacy, please
     * see the user-guide section "Transaction tear-offs" to learn more about this topic.
     */
    val availableComponentHashes: List<List<SecureHash>>
        get() = componentGroups.mapIndexed { componentGroupIndex, (components) -> components.mapIndexed {
            internalIndex, internalIt -> serializedHash(internalIt, availableComponentNonces[componentGroupIndex][internalIndex]) }
        }
}

// TODO: change to ComponentGroup(val enumGroup: ComponentGroupEnum, val components: List<OpaqueBytes>) when enum evolvability is supported.
/**
 * A ComponentGroup is used to store the full list of transaction components of the same type in serialised form.
 * Practically, a group per component type of a transaction is required; thus, there will be a group for input states,
 * a group for all attachments (if there are any) etc.
 */
@CordaSerializable
data class ComponentGroup(val components: List<OpaqueBytes>)
