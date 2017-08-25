package net.corda.core.transactions

import net.corda.core.contracts.*
import net.corda.core.crypto.*
import net.corda.core.identity.Party
import net.corda.core.serialization.*
import net.corda.core.utilities.OpaqueBytes
import java.security.PublicKey
import java.util.function.Predicate

/**
 * Implemented by [WireTransaction] and [FilteredLeaves]. A TraversableTransaction allows you to iterate
 * over the flattened components of the underlying transaction structure, taking into account that some
 * may be missing in the case of this representing a "torn" transaction. Please see the user guide section
 * "Transaction tear-offs" to learn more about this feature.
 *
 * The [availableComponentGroups] property is used for calculation of the transaction's [MerkleTree], which is in
 * turn used to derive the ID hash.
 */
interface TraversableTransaction {
    val inputs: List<StateRef>
    val attachments: List<SecureHash>
    val outputs: List<TransactionState<ContractState>>
    val commands: List<Command<*>>
    val notary: Party?
    val timeWindow: TimeWindow?
    /**
     * For privacy purposes, each part of a transaction should be accompanied by a nonce.
     * To avoid storing a random number (nonce) per component, an initial "salt" is the sole value utilised,
     * so that all component nonces are deterministically computed in the following way:
     * nonce1 = H(salt || 1)
     * nonce2 = H(salt || 2)
     *
     * Thus, all of the nonces are "independent" in the sense that knowing one or some of them, you can learn
     * nothing about the rest.
     */
    val privacySalt: PrivacySalt?

    /**
     * Returns a list of all the component groups that are present in the transaction, excluding the privacySalt,
     * in the following order (which is the same with the order in [ComponentGroupEnum]:
     * - list of each input that is present
     * - list of each output that is present
     * - list of each command that is present
     * - list of each attachment that is present
     * - The notary [Party], if present (list with one element)
     * - The time-window of the transaction, if present (list with one element)
    */
    val availableComponentGroups: List<List<Any>>
        get() {
            val result = mutableListOf(inputs, outputs, commands, attachments)
            notary?.let { result += listOf(it) }
            timeWindow?.let { result += listOf(it) }
            return result
        }
}

/**
 * Class that holds filtered leaves for a partial Merkle transaction. We assume mixed leaf types, notice that every
 * field from [WireTransaction] can be used in [PartialMerkleTree] calculation, except for the privacySalt.
 * A list of nonces is also required to (re)construct component hashes.
 */
@CordaSerializable
data class FilteredLeaves(
        override val inputs: List<StateRef>,
        override val attachments: List<SecureHash>,
        override val outputs: List<TransactionState<ContractState>>,
        override val commands: List<Command<*>>,
        override val notary: Party?,
        override val timeWindow: TimeWindow?
) : TraversableTransaction {

    /**
     * PrivacySalt should be always null for FilteredLeaves, because making it accidentally visible would expose all
     * nonces (including filtered out components) causing privacy issues, see [serializedHash] and
     * [TraversableTransaction.privacySalt].
     */
    override val privacySalt: PrivacySalt? get() = null

    /**
     * Function that checks the whole filtered structure.
     * Force type checking on a structure that we obtained, so we don't sign more than expected.
     * Example: Oracle is implemented to check only for commands, if it gets an attachment and doesn't expect it - it can sign
     * over a transaction with the attachment that wasn't verified. Of course it depends on how you implement it, but else -> false
     * should solve a problem with possible later extensions to WireTransaction.
     * @param checkingFun function that performs type checking on the structure fields and provides verification logic accordingly.
     * @returns false if no elements were matched on a structure or checkingFun returned false.
     */
    fun checkWithFun(checkingFun: (Any) -> Boolean): Boolean {
        val checkList = availableComponentGroups.flatten().map { checkingFun(it) }
        return (!checkList.isEmpty()) && checkList.all { it }
    }
}

/**
 * Class representing merkleized filtered transaction.
 * @param id Merkle tree root hash.
 * @param filteredComponentGroups list of transaction components groups remained after filters are applied to [WireTransaction].
 * @param partialMerkleTree the partial Merkle tree of the transaction groups.
 */
@CordaSerializable
class FilteredTransaction private constructor(
        val id: SecureHash,
        val filteredComponentGroups: List<FilteredComponentGroup>,
        private val partialMerkleTree: PartialMerkleTree
) {

    init {
        check(ComponentGroupEnum.values().size <= filteredComponentGroups.size  ) { "Malformed FilteredTransaction, expected at least ${ComponentGroupEnum.values().size} tx component types, but received ${filteredComponentGroups.size}" }
    }

    val filteredLeaves: FilteredLeaves = buildFilteredLeaves()

    // TODO: Consider avoiding duplicated code of this and the WireTransaction related construction.
    private fun buildFilteredLeaves(): FilteredLeaves {
        /** Hashes of the ZIP/JAR files that are needed to interpret the contents of this wire transaction. */
        val attachments: List<SecureHash> = deserialiseFilteredComponentGroup(ComponentGroupEnum.ATTACHMENTS_GROUP, { SerializedBytes<SecureHash>(it).deserialize() })

        /** Pointers to the input states on the ledger, identified by (tx identity hash, output index). */
        val inputs: List<StateRef> = deserialiseFilteredComponentGroup(ComponentGroupEnum.INPUTS_GROUP, { SerializedBytes<StateRef>(it).deserialize() })

        val outputs: List<TransactionState<ContractState>> = deserialiseFilteredComponentGroup(ComponentGroupEnum.OUTPUTS_GROUP, { SerializedBytes<TransactionState<ContractState>>(it).deserialize(context = SerializationFactory.defaultFactory.defaultContext.withAttachmentsClassLoader(attachments)) })

        /** Ordered list of ([CommandData], [PublicKey]) pairs that instruct the contracts what to do. */
        val commands: List<Command<*>> = deserialiseFilteredComponentGroup(ComponentGroupEnum.COMMANDS_GROUP, { SerializedBytes<Command<*>>(it).deserialize(context = SerializationFactory.defaultFactory.defaultContext.withAttachmentsClassLoader(attachments)) })

        val notary: Party? = let {
            val notaries: List<Party> = deserialiseFilteredComponentGroup(ComponentGroupEnum.NOTARY_GROUP, { SerializedBytes<Party>(it).deserialize() })
            check(notaries.size <= 1) { "Invalid Transaction. More than 1 notary party detected." }
            if (notaries.isNotEmpty()) notaries[0] else null
        }

        val timeWindow: TimeWindow? = let {
            val timeWindows: List<TimeWindow> = deserialiseFilteredComponentGroup(ComponentGroupEnum.TIMEWINDOW_GROUP, { SerializedBytes<TimeWindow>(it).deserialize() })
            check(timeWindows.size <= 1) { "Invalid Transaction. More than 1 time-window detected." }
            if (timeWindows.isNotEmpty()) timeWindows[0] else null
        }

        return FilteredLeaves(inputs, attachments, outputs, commands, notary, timeWindow)
    }

    // Helper function to return a meaningful exception if deserialisation of a component fails.
    private fun <T> deserialiseFilteredComponentGroup(groupEnum: ComponentGroupEnum, deserialiseBody: (ByteArray) -> T): List<T> {
        return filteredComponentGroups[groupEnum.ordinal].components.mapIndexed { internalIndex, component ->
            try {
                deserialiseBody(component.bytes)
            } catch (e: MissingAttachmentsException) {
                throw e // TODO: do we need a more descriptive error handling?
            } catch (e: Exception) {
                throw Exception("Malformed FilteredTransaction, $groupEnum at index $internalIndex cannot be deserialised", e)
            }
        }
    }

    companion object {
        /**
         * Construction of filtered transaction with partial Merkle tree.
         * @param wtx WireTransaction to be filtered.
         * @param filtering filtering over the whole WireTransaction
         */
        @JvmStatic
        fun buildFilteredTransaction(wtx: WireTransaction, filtering: Predicate<Any>): FilteredTransaction {
            val filteredComponentGroups = filterWithFun(wtx, filtering)
            val merkleTree = wtx.merkleTree
            val groupHashes = wtx.groupsMerkleRoots.filterIndexed { componentGroupIndex, _ -> filteredComponentGroups[componentGroupIndex].components.isNotEmpty() }
            val pmt = PartialMerkleTree.build(merkleTree, groupHashes)
            return FilteredTransaction(merkleTree.hash, filteredComponentGroups, pmt)
        }

        /**
         * Construction of partial transaction from [WireTransaction] based on filtering.
         * Note that list of nonces to be sent is updated on the fly, based on the index of the filtered tx component.
         * @param filtering filtering over the whole WireTransaction
         * @returns FilteredLeaves used in PartialMerkleTree calculation and verification.
         */
        private fun filterWithFun(wtx: WireTransaction, filtering: Predicate<Any>): List<FilteredComponentGroup> {

            val filteredSerialisedComponents: MutableMap<Int, MutableList<OpaqueBytes>> = hashMapOf()
            val filteredComponentNonces: MutableMap<Int, MutableList<SecureHash>> = hashMapOf()
            val filteredComponentHashes: MutableMap<Int, MutableList<SecureHash>> = hashMapOf() // Required for partial Merkle tree generation.

            fun <T : Any> filter(t: T, componentGroupIndex: Int, internalIndex: Int) {
                if (filtering.test(t)) {
                    val group = filteredSerialisedComponents[componentGroupIndex]
                    if (group == null) {
                        filteredSerialisedComponents.put(componentGroupIndex, mutableListOf(wtx.componentGroups[componentGroupIndex].components[internalIndex]))
                        filteredComponentNonces.put(componentGroupIndex, mutableListOf(wtx.availableComponentNonces[componentGroupIndex][internalIndex]))
                        filteredComponentHashes.put(componentGroupIndex, mutableListOf(wtx.availableComponentHashes[componentGroupIndex][internalIndex]))
                    } else {
                        group.add(wtx.componentGroups[componentGroupIndex].components[internalIndex])
                        filteredComponentNonces[componentGroupIndex]!!.add(wtx.availableComponentNonces[componentGroupIndex][internalIndex])
                        filteredComponentHashes[componentGroupIndex]!!.add(wtx.availableComponentHashes[componentGroupIndex][internalIndex])
                    }
                }
            }

            fun updateFilteredComponents() {
                wtx.inputs.forEachIndexed { internalIndex, it -> filter(it, ComponentGroupEnum.INPUTS_GROUP.ordinal, internalIndex) }
                wtx.outputs.forEachIndexed { internalIndex, it -> filter(it, ComponentGroupEnum.OUTPUTS_GROUP.ordinal, internalIndex) }
                wtx.commands.forEachIndexed { internalIndex, it -> filter(it, ComponentGroupEnum.COMMANDS_GROUP.ordinal, internalIndex)  }
                wtx.attachments.forEachIndexed { internalIndex, it -> filter(it, ComponentGroupEnum.ATTACHMENTS_GROUP.ordinal, internalIndex) }
                if (wtx.notary != null) filter(wtx.notary, ComponentGroupEnum.NOTARY_GROUP.ordinal, 0)
                if (wtx.timeWindow != null) filter(wtx.timeWindow, ComponentGroupEnum.TIMEWINDOW_GROUP.ordinal, 0)

                // It's sometimes possible that when we receive a WireTransaction for which there is a new or more unknown component groups,
                // we decide to filter and attach this field to a FilteredTransaction.
                // An example would be to redact certain contract state types, but otherwise leave a transaction alone,
                // including the unknown new components.
                for (componentGroupIndex in ComponentGroupEnum.values().size until wtx.componentGroups.size) {
                    wtx.componentGroups[componentGroupIndex].components.forEachIndexed { internalIndex, component -> filter(component, componentGroupIndex, internalIndex) }
                }
            }

            fun createPartialMerkleTree(componentGroupIndex: Int) = PartialMerkleTree.build(MerkleTree.getMerkleTree(wtx.availableComponentHashes[componentGroupIndex]), filteredComponentHashes[componentGroupIndex]!!)

            fun createFilteredComponentGroups(): List<FilteredComponentGroup> {
                updateFilteredComponents()
                val filteredComponentGroups: MutableList<FilteredComponentGroup> = mutableListOf()
                for (componentGroupIndex in 0 until wtx.componentGroups.size) {
                    val group = filteredSerialisedComponents[componentGroupIndex]
                    if (group != null) {
                        filteredComponentGroups.add(FilteredComponentGroup(group, filteredComponentNonces[componentGroupIndex]!!, createPartialMerkleTree(componentGroupIndex) ))
                    } else {
                        filteredComponentGroups.add(FilteredComponentGroup()) // Add an empty group.
                    }
                }
                return filteredComponentGroups
            }

            // TODO: We should have a warning (require) if all leaves (excluding salt) are visible after filtering.
            //      Consider the above after refactoring FilteredTransaction to implement TraversableTransaction,
            //      so that a WireTransaction can be used when required to send a full tx (e.g. RatesFixFlow in Oracles).
            return createFilteredComponentGroups()
        }
    }

    /**
     * Runs verification of partial Merkle branch against [id].
     */
    @Throws(MerkleTreeException::class)
    fun verify(): Boolean {
        val hashes: List<SecureHash> = filteredComponentGroups.map { it.nonces }.flatten()
        if (hashes.isEmpty()) {
            throw MerkleTreeException("Transaction without included leaves.")
        }
        val groupHashes = filteredComponentGroups.filter { it.partialMerkleTree != null }.map { it.partialMerkleTree!!.verify(it.partialMerkleTree.root, mutableListOf()) }
        return partialMerkleTree.verify(id, groupHashes)
    }
}

/**
 * A FilteredComponentGroup is used to store the filtered list of transaction components of the same type in serialised form.
 * This is similar to [ComponentGroup], but it also includes the corresponding nonce per component.
 */
@CordaSerializable
data class FilteredComponentGroup(val components: List<OpaqueBytes>, val nonces: List<SecureHash>, val partialMerkleTree: PartialMerkleTree?) {

    /** A helper constructor to create empty filtered component groups. */
    constructor() : this(emptyList(), emptyList(), null)

    init {
        check(components.size == nonces.size) { "Size of components and nonces do not match" }
    }
}
