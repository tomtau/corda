package net.corda.core.contracts

import net.corda.core.contracts.ComponentGroupEnum.*
import net.corda.core.crypto.MerkleTree
import net.corda.core.crypto.SecureHash
import net.corda.core.crypto.secureRandomBytes
import net.corda.core.crypto.sha256
import net.corda.core.serialization.serialize
import net.corda.core.transactions.ComponentGroup
import net.corda.core.transactions.WireTransaction
import net.corda.core.utilities.OpaqueBytes
import net.corda.testing.*
import net.corda.testing.contracts.DUMMY_PROGRAM_ID
import net.corda.testing.contracts.DummyState
import org.junit.Test
import java.time.Instant
import java.util.function.Predicate
import kotlin.test.*

class CompatibleTransactionTests : TestDependencyInjectionBase() {

    private val dummyOutState = TransactionState(DummyState(0), DUMMY_PROGRAM_ID, DUMMY_NOTARY)
    private val stateRef1 = StateRef(SecureHash.randomSHA256(), 0)
    private val stateRef2 = StateRef(SecureHash.randomSHA256(), 1)
    private val stateRef3 = StateRef(SecureHash.randomSHA256(), 0)

    private val inputs = listOf(stateRef1, stateRef2, stateRef3) // 3 elements.
    private val outputs = listOf(dummyOutState, dummyOutState.copy(notary = BOB)) // 2 elements.
    private val commands = listOf(dummyCommand(DUMMY_KEY_1.public, DUMMY_KEY_2.public)) // 1 element.
    private val attachments = emptyList<SecureHash>() // Empty list.
    private val notary = DUMMY_NOTARY
    private val timeWindow = TimeWindow.fromOnly(Instant.now())
    private val privacySalt: PrivacySalt = PrivacySalt()

    private val inputGroup by lazy { ComponentGroup(inputs.map { it.serialize() }) }
    private val outputGroup by lazy { ComponentGroup(outputs.map { it.serialize() }) }
    private val commandGroup by lazy { ComponentGroup(commands.map { it.serialize() }) }
    private val attachmentGroup by lazy { ComponentGroup(attachments.map { it.serialize() }) } // The list is empty.
    private val notaryGroup by lazy { ComponentGroup(listOf(notary.serialize())) }
    private val timeWindowGroup by lazy { ComponentGroup(listOf(timeWindow.serialize())) }
    private val componentGroupsA by lazy { listOf(inputGroup, outputGroup, commandGroup, attachmentGroup, notaryGroup, timeWindowGroup) }
    private val wireTransactionA by lazy { WireTransaction(componentGroups = componentGroupsA, privacySalt = privacySalt) }

    @Test
    fun `Merkle root computations`() {
        val wireTransactionB = WireTransaction(componentGroups = componentGroupsA, privacySalt = privacySalt)

        // Merkle tree computation is deterministic.
        assertEquals(wireTransactionA.merkleTree, wireTransactionB.merkleTree)

        // Full Merkle root is computed from the list of Merkle roots of each component group.
        assertEquals(wireTransactionA.merkleTree, MerkleTree.getMerkleTree(listOf(privacySalt.sha256()) + wireTransactionA.groupsMerkleRoots))

        val componentGroupsEmptyOutputs = listOf(inputGroup, ComponentGroup(emptyList()), commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)
        val wireTransactionEmptyOutputs = WireTransaction(componentGroups = componentGroupsEmptyOutputs, privacySalt = privacySalt)

        // Because outputs list is empty, it should be zeroHash.
        assertEquals(SecureHash.zeroHash, wireTransactionEmptyOutputs.groupsMerkleRoots[OUTPUTS_GROUP.ordinal])

        // TXs differ in outputStates.
        assertNotEquals(wireTransactionA.merkleTree, wireTransactionEmptyOutputs.merkleTree)

        val inputsShuffled = listOf(stateRef2, stateRef1, stateRef3)
        val inputShuffledGroup = ComponentGroup(inputsShuffled.map { it -> it.serialize() })
        val componentGroupsB = listOf(inputShuffledGroup, outputGroup, commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)
        val wireTransaction1ShuffledInputs = WireTransaction(componentGroups = componentGroupsB, privacySalt = privacySalt)

        // Ordering inside a component group matters.
        assertNotEquals(wireTransactionA, wireTransaction1ShuffledInputs)
        assertNotEquals(wireTransactionA.merkleTree, wireTransaction1ShuffledInputs.merkleTree)
        // Inputs group Merkle root is not equal.
        assertNotEquals(wireTransactionA.groupsMerkleRoots[INPUTS_GROUP.ordinal], wireTransaction1ShuffledInputs.groupsMerkleRoots[INPUTS_GROUP.ordinal])
        // But outputs group Merkle leaf (and the rest) remained the same.
        assertEquals(wireTransactionA.groupsMerkleRoots[OUTPUTS_GROUP.ordinal], wireTransaction1ShuffledInputs.groupsMerkleRoots[OUTPUTS_GROUP.ordinal])
        assertEquals(wireTransactionA.groupsMerkleRoots[ATTACHMENTS_GROUP.ordinal], wireTransaction1ShuffledInputs.groupsMerkleRoots[ATTACHMENTS_GROUP.ordinal])

        // Group leaves ordering matters and will cause an exception during construction. We should keep a standardised
        // sequence for backwards/forwards compatibility. For instance inputs should always be the first leaf, then outputs, the commands etc.
        val shuffledComponentGroupsA = listOf(outputGroup, inputGroup, commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)
        assertFails { WireTransaction(componentGroups = shuffledComponentGroupsA, privacySalt = privacySalt) }
    }

    @Test
    fun `WireTransaction constructors and compatibility`() {
        val wireTransactionOldContsructor = WireTransaction(inputs, attachments, outputs, commands, notary, timeWindow, privacySalt)
        assertEquals(wireTransactionA, wireTransactionOldContsructor)

        // Malformed tx - attachments (index = 3) is not List<SecureHash>, actually attachmentsGroup is not added at all and everything after it is left-shifted.
        val componentGroupsB = listOf(inputGroup, outputGroup, commandGroup, notaryGroup, timeWindowGroup)
        assertFails { WireTransaction(componentGroupsB, privacySalt) }

        // Malformed tx - inputs (index = 0) is not a serialised object at all.
        val componentGroupsC = listOf(ComponentGroup(listOf(OpaqueBytes(ByteArray(8)))), outputGroup, commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)
        assertFails { WireTransaction(componentGroupsC, privacySalt) }

        val componentGroupsCompatibleA = listOf(
                inputGroup,
                outputGroup,
                commandGroup,
                attachmentGroup,
                notaryGroup,
                timeWindowGroup,
                ComponentGroup(listOf(OpaqueBytes(secureRandomBytes(4)), OpaqueBytes(secureRandomBytes(8)))) // A new component that we cannot process.
        )

        // The old client (receiving more component types than expected) is still compatible.
        val wireTransactionCompatibleA = WireTransaction(componentGroupsCompatibleA, privacySalt)
        assertEquals(wireTransactionCompatibleA.inputs, wireTransactionA.inputs)
        assertNotEquals(wireTransactionCompatibleA.id, wireTransactionA.id)
        assertNotEquals(wireTransactionCompatibleA, wireTransactionA)
        assertEquals(7, wireTransactionCompatibleA.componentGroups.size)

        val componentGroupsCompatibleB = listOf(
                inputGroup,
                outputGroup,
                commandGroup,
                attachmentGroup,
                notaryGroup,
                timeWindowGroup,
                ComponentGroup(emptyList()) // A new empty component.
        )
        // The old client (receiving more component types than expected, even if empty) is still compatible.
        val wireTransactionCompatibleB = WireTransaction(componentGroupsCompatibleB, privacySalt)
        assertEquals(wireTransactionCompatibleB.inputs, wireTransactionA.inputs)
        assertEquals(wireTransactionCompatibleB, wireTransactionA) // Although the last component is empty, transactions ids are equal.
        assertEquals(7, wireTransactionCompatibleB.componentGroups.size)

        // We expect at least 6 component types (excluding privacySalt).
        val componentGroupsNonCompatible = listOf(
                inputGroup,
                outputGroup
        )
        assertFails { WireTransaction(componentGroupsNonCompatible, privacySalt) }
    }

    @Test
    fun `FilteredTransaction constructors and compatibility`() {
        val ftxNothing = wireTransactionA.buildFilteredTransaction(Predicate { false }) // Nothing filtered.
        val ftxAll = wireTransactionA.buildFilteredTransaction(Predicate { true }) // All filtered.

        fun filtering(elem: Any): Boolean {
            return when (elem) {
                is StateRef -> true
                else -> false
            }
        }
        val ftxInputs = wireTransactionA.buildFilteredTransaction(Predicate(::filtering)) // Inputs only filtered.

        assertEquals(ftxNothing.inputs, wireTransactionA.buildFilteredTransaction(Predicate{ false }).inputs)
        assertEquals(ftxAll.outputs, wireTransactionA.buildFilteredTransaction(Predicate{ true }).outputs)
        assertEquals(ftxInputs.inputs, wireTransactionA.buildFilteredTransaction(Predicate(::filtering)).inputs)

        assertEquals(6, ftxInputs.filteredComponentGroups.size)
        assertEquals(3, ftxInputs.filteredComponentGroups[0].components.size)
        assertEquals(3, ftxInputs.filteredComponentGroups[0].nonces.size)
        assertNotNull(ftxInputs.filteredComponentGroups[0].partialMerkleTree)
        assertTrue(ftxInputs.filteredComponentGroups[1].components.isEmpty())
        assertTrue(ftxInputs.filteredComponentGroups[1].nonces.isEmpty())
        assertNull(ftxInputs.filteredComponentGroups[1].partialMerkleTree)

        val componentGroupsCompatibleA = listOf(
                inputGroup,
                outputGroup,
                commandGroup,
                attachmentGroup,
                notaryGroup,
                timeWindowGroup,
                ComponentGroup(listOf(OpaqueBytes(secureRandomBytes(4)), OpaqueBytes(secureRandomBytes(8)))) // A new component that we cannot process.
        )

        // The old client (receiving more component types than expected) is still compatible.
        val wireTransactionCompatibleA = WireTransaction(componentGroupsCompatibleA, privacySalt)
        val ftxCompatible = wireTransactionCompatibleA.buildFilteredTransaction(Predicate(::filtering))

        assertEquals(ftxInputs.inputs, ftxCompatible.inputs)
        assertNotEquals(ftxInputs.id, ftxCompatible.id)
        assertNotEquals(ftxInputs.filteredComponentGroups, ftxCompatible.filteredComponentGroups)
        assertEquals(wireTransactionCompatibleA.id, ftxCompatible.id)

        assertEquals(7, ftxCompatible.filteredComponentGroups.size)
        assertEquals(3, ftxCompatible.filteredComponentGroups[0].components.size)
        assertEquals(3, ftxCompatible.filteredComponentGroups[0].nonces.size)
        assertNotNull(ftxCompatible.filteredComponentGroups[0].partialMerkleTree)
        assertTrue(ftxCompatible.filteredComponentGroups[1].components.isEmpty())
        assertTrue(ftxCompatible.filteredComponentGroups[1].nonces.isEmpty())
        assertNull(ftxCompatible.filteredComponentGroups[1].partialMerkleTree)

        // Now, let's allow everything, including the 7th new component type that we cannot process.
        val ftxCompatibleAll = wireTransactionCompatibleA.buildFilteredTransaction(Predicate { true }) // All filtered, including the unknown 7th component.
        assertEquals(wireTransactionCompatibleA.id, ftxCompatibleAll.id)
        // Check we received the last element that we cannot process (backwards compatibility).
        assertEquals(7, ftxCompatibleAll.filteredComponentGroups.size)
        assertEquals(2, ftxCompatibleAll.filteredComponentGroups[6].components.size)
        assertEquals(2, ftxCompatibleAll.filteredComponentGroups[6].nonces.size)
        assertNotNull(ftxCompatibleAll.filteredComponentGroups[6].partialMerkleTree)
    }
}
