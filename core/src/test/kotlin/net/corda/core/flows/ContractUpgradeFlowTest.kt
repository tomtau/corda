package net.corda.core.flows

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.contracts.*
import net.corda.core.identity.AbstractParty
import net.corda.core.identity.Party
import net.corda.core.identity.PartyAndCertificate
import net.corda.core.internal.Emoji
import net.corda.core.messaging.CordaRPCOps
import net.corda.core.messaging.startFlow
import net.corda.core.node.services.queryBy
import net.corda.core.transactions.LedgerTransaction
import net.corda.core.transactions.SignedTransaction
import net.corda.core.utilities.OpaqueBytes
import net.corda.core.utilities.getOrThrow
import net.corda.finance.USD
import net.corda.finance.`issued by`
import net.corda.finance.contracts.asset.CASH_PROGRAM_ID
import net.corda.finance.contracts.asset.Cash
import net.corda.finance.flows.CashIssueFlow
import net.corda.node.internal.CordaRPCOpsImpl
import net.corda.node.internal.StartedNode
import net.corda.node.services.FlowPermissions.Companion.startFlowPermission
import net.corda.nodeapi.User
import net.corda.testing.RPCDriverExposedDSLInterface
import net.corda.testing.chooseIdentity
import net.corda.testing.contracts.DummyContract
import net.corda.testing.contracts.DummyContractV2
import net.corda.testing.node.MockNetwork
import net.corda.testing.rpcDriver
import net.corda.testing.rpcTestUser
import net.corda.testing.startRpcClient
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ContractUpgradeFlowTest {
    lateinit var mockNet: MockNetwork
    lateinit var a: StartedNode<MockNetwork.MockNode>
    lateinit var b: StartedNode<MockNetwork.MockNode>
    lateinit var notary: PartyAndCertificate

    @Before
    fun setup() {
        mockNet = MockNetwork()
        val nodes = mockNet.createSomeNodes(notaryKeyPair = null) // prevent generation of notary override
        a = nodes.partyNodes[0]
        b = nodes.partyNodes[1]

        // Process registration
        mockNet.runNetwork()
        a.internals.ensureRegistered()

        notary = a.services.networkMapCache.notaryIdentities.first()
        a.database.transaction {
            a.services.identityService.verifyAndRegisterIdentity(notary)
        }
        b.database.transaction {
            b.services.identityService.verifyAndRegisterIdentity(notary)
        }

    }

    @After
    fun tearDown() {
        mockNet.stopNodes()
    }

    @Test
    fun `2 parties contract upgrade`() {
        // Create dummy contract.
        val twoPartyDummyContract = DummyContract.generateInitial(0, notary.party, a.info.chooseIdentity().ref(1), b.info.chooseIdentity().ref(1))
        val signedByA = a.services.signInitialTransaction(twoPartyDummyContract)
        val stx = b.services.addSignature(signedByA)

        a.services.startFlow(FinalityFlow(stx, setOf(a.info.chooseIdentity(), b.info.chooseIdentity())))
        mockNet.runNetwork()

        val atx = a.database.transaction { a.services.validatedTransactions.getTransaction(stx.id) }
        val btx = b.database.transaction { b.services.validatedTransactions.getTransaction(stx.id) }
        requireNotNull(atx)
        requireNotNull(btx)

        // The request is expected to be rejected because party B hasn't authorised the upgrade yet.
        val rejectedFuture = a.services.startFlow(ContractUpgradeFlow.Initiator(atx!!.tx.outRef(0), DummyContractV2::class.java)).resultFuture
        mockNet.runNetwork()
        assertFailsWith(UnexpectedFlowEndException::class) { rejectedFuture.getOrThrow() }

        // Party B authorise the contract state upgrade, and immediately deauthorise the same.
        b.services.startFlow(ContractUpgradeFlow.Authorise(btx!!.tx.outRef<ContractState>(0), DummyContractV2::class.java)).resultFuture.getOrThrow()
        b.services.startFlow(ContractUpgradeFlow.Deauthorise(btx.tx.outRef<ContractState>(0).ref)).resultFuture.getOrThrow()

        // The request is expected to be rejected because party B has subsequently deauthorised and a previously authorised upgrade.
        val deauthorisedFuture = a.services.startFlow(ContractUpgradeFlow.Initiator(atx.tx.outRef(0), DummyContractV2::class.java)).resultFuture
        mockNet.runNetwork()
        assertFailsWith(UnexpectedFlowEndException::class) { deauthorisedFuture.getOrThrow() }

        // Party B authorise the contract state upgrade
        b.services.startFlow(ContractUpgradeFlow.Authorise(btx.tx.outRef<ContractState>(0), DummyContractV2::class.java)).resultFuture.getOrThrow()

        // Party A initiates contract upgrade flow, expected to succeed this time.
        val resultFuture = a.services.startFlow(ContractUpgradeFlow.Initiator(atx.tx.outRef(0), DummyContractV2::class.java)).resultFuture
        mockNet.runNetwork()

        val result = resultFuture.getOrThrow()

        fun check(node: StartedNode<*>) {
            val nodeStx = node.database.transaction {
                node.services.validatedTransactions.getTransaction(result.ref.txhash)
            }
            requireNotNull(nodeStx)

            // Verify inputs.
            val input = node.database.transaction {
                node.services.validatedTransactions.getTransaction(nodeStx!!.tx.inputs.single().txhash)
            }
            requireNotNull(input)
            assertTrue(input!!.tx.outputs.single().data is DummyContract.State)

            // Verify outputs.
            assertTrue(nodeStx!!.tx.outputs.single().data is DummyContractV2.State)
        }
        check(a)
        check(b)
    }

    private fun RPCDriverExposedDSLInterface.startProxy(node: StartedNode<*>, user: User): CordaRPCOps {
        return startRpcClient<CordaRPCOps>(
                rpcAddress = startRpcServer(
                        rpcUser = user,
                        ops = CordaRPCOpsImpl(node.services, node.smm, node.database)
                ).get().broker.hostAndPort!!,
                username = user.username,
                password = user.password
        ).get()
    }

    @Test
    fun `2 parties contract upgrade using RPC`() {
        rpcDriver(initialiseSerialization = false) {
            // Create dummy contract.
            val twoPartyDummyContract = DummyContract.generateInitial(0, notary.party, a.info.chooseIdentity().ref(1), b.info.chooseIdentity().ref(1))
            val signedByA = a.services.signInitialTransaction(twoPartyDummyContract)
            val stx = b.services.addSignature(signedByA)

            val user = rpcTestUser.copy(permissions = setOf(
                    startFlowPermission<FinalityInvoker>(),
                    startFlowPermission<ContractUpgradeFlow.Initiator<*, *>>(),
                    startFlowPermission<ContractUpgradeFlow.Acceptor>(),
                    startFlowPermission<ContractUpgradeFlow.Authorise>(),
                    startFlowPermission<ContractUpgradeFlow.Deauthorise>()
            ))
            val rpcA = startProxy(a, user)
            val rpcB = startProxy(b, user)
            val handle = rpcA.startFlow(::FinalityInvoker, stx, setOf(a.info.chooseIdentity(), b.info.chooseIdentity()))
            mockNet.runNetwork()
            handle.returnValue.getOrThrow()

            val atx = a.database.transaction { a.services.validatedTransactions.getTransaction(stx.id) }
            val btx = b.database.transaction { b.services.validatedTransactions.getTransaction(stx.id) }
            requireNotNull(atx)
            requireNotNull(btx)

            val rejectedFuture = rpcA.startFlow({ stateAndRef, upgrade -> ContractUpgradeFlow.Initiator(stateAndRef, upgrade) },
                    atx!!.tx.outRef<DummyContract.State>(0),
                    DummyContractV2::class.java).returnValue

            mockNet.runNetwork()
            assertFailsWith(UnexpectedFlowEndException::class) { rejectedFuture.getOrThrow() }

            // Party B authorise the contract state upgrade, and immediately deauthorise the same.
            rpcB.startFlow( { stateAndRef, upgrade -> ContractUpgradeFlow.Authorise(stateAndRef, upgrade ) },
                    btx!!.tx.outRef<ContractState>(0),
                    DummyContractV2::class.java).returnValue
            rpcB.startFlow( { stateRef -> ContractUpgradeFlow.Deauthorise(stateRef) },
                    btx.tx.outRef<ContractState>(0).ref).returnValue

            // The request is expected to be rejected because party B has subsequently deauthorised and a previously authorised upgrade.
            val deauthorisedFuture = rpcA.startFlow( {stateAndRef, upgrade -> ContractUpgradeFlow.Initiator(stateAndRef, upgrade) },
                    atx.tx.outRef<DummyContract.State>(0),
                    DummyContractV2::class.java).returnValue

            mockNet.runNetwork()
            assertFailsWith(UnexpectedFlowEndException::class) { deauthorisedFuture.getOrThrow() }

            // Party B authorise the contract state upgrade.
            rpcB.startFlow( { stateAndRef, upgrade -> ContractUpgradeFlow.Authorise(stateAndRef, upgrade ) },
                    btx.tx.outRef<ContractState>(0),
                    DummyContractV2::class.java).returnValue

            // Party A initiates contract upgrade flow, expected to succeed this time.
            val resultFuture = rpcA.startFlow({ stateAndRef, upgrade -> ContractUpgradeFlow.Initiator(stateAndRef, upgrade) },
                    atx.tx.outRef<DummyContract.State>(0),
                    DummyContractV2::class.java).returnValue

            mockNet.runNetwork()
            val result = resultFuture.getOrThrow()
            // Check results.
            listOf(a, b).forEach {
                val signedTX = a.database.transaction { a.services.validatedTransactions.getTransaction(result.ref.txhash) }
                requireNotNull(signedTX)

                // Verify inputs.
                val input = a.database.transaction { a.services.validatedTransactions.getTransaction(signedTX!!.tx.inputs.single().txhash) }
                requireNotNull(input)
                assertTrue(input!!.tx.outputs.single().data is DummyContract.State)

                // Verify outputs.
                assertTrue(signedTX!!.tx.outputs.single().data is DummyContractV2.State)
            }
        }
    }

    @Test
    fun `upgrade Cash to v2`() {
        // Create some cash.
        val chosenIdentity = a.info.chooseIdentity()
        val result = a.services.startFlow(CashIssueFlow(Amount(1000, USD), OpaqueBytes.of(1), notary.party)).resultFuture
        mockNet.runNetwork()
        val stx = result.getOrThrow().stx
        val anonymisedRecipient = result.get().recipient!!
        val stateAndRef = stx.tx.outRef<Cash.State>(0)
        val baseState = a.database.transaction { a.services.vaultQueryService.queryBy<ContractState>().states.single() }
        assertTrue(baseState.state.data is Cash.State, "Contract state is old version.")
        // Starts contract upgrade flow.
        val upgradeResult = a.services.startFlow(ContractUpgradeFlow.Initiator(stateAndRef, CashV2::class.java)).resultFuture
        mockNet.runNetwork()
        upgradeResult.getOrThrow()
        // Get contract state from the vault.
        val firstState = a.database.transaction { a.services.vaultQueryService.queryBy<ContractState>().states.single() }
        assertTrue(firstState.state.data is CashV2.State, "Contract state is upgraded to the new version.")
        assertEquals(Amount(1000000, USD).`issued by`(chosenIdentity.ref(1)), (firstState.state.data as CashV2.State).amount, "Upgraded cash contain the correct amount.")
        assertEquals<Collection<AbstractParty>>(listOf(anonymisedRecipient), (firstState.state.data as CashV2.State).owners, "Upgraded cash belongs to the right owner.")
    }

    class CashV2 : UpgradedContract<Cash.State, CashV2.State> {
        override val legacyContract = CASH_PROGRAM_ID

        data class State(override val amount: Amount<Issued<Currency>>, val owners: List<AbstractParty>) : FungibleAsset<Currency> {
            override val owner: AbstractParty = owners.first()
            override val exitKeys = (owners + amount.token.issuer.party).map { it.owningKey }.toSet()
            override val participants = owners

            override fun withNewOwnerAndAmount(newAmount: Amount<Issued<Currency>>, newOwner: AbstractParty) = copy(amount = amount.copy(newAmount.quantity), owners = listOf(newOwner))
            override fun toString() = "${Emoji.bagOfCash}New Cash($amount at ${amount.token.issuer} owned by $owner)"
            override fun withNewOwner(newOwner: AbstractParty) = CommandAndState(Cash.Commands.Move(), copy(owners = listOf(newOwner)))
        }

        override fun upgrade(state: Cash.State) = CashV2.State(state.amount.times(1000), listOf(state.owner))

        override fun verify(tx: LedgerTransaction) {}
    }

    @StartableByRPC
    class FinalityInvoker(val transaction: SignedTransaction,
                          val extraRecipients: Set<Party>) : FlowLogic<List<SignedTransaction>>() {
        @Suspendable
        override fun call(): List<SignedTransaction> = subFlow(FinalityFlow(transaction, extraRecipients))
    }
}
