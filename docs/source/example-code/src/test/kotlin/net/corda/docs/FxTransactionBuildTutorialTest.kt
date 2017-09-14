package net.corda.docs

import net.corda.core.node.services.ServiceInfo
import net.corda.core.toFuture
import net.corda.core.utilities.OpaqueBytes
import net.corda.core.utilities.getOrThrow
import net.corda.finance.*
import net.corda.finance.contracts.getCashBalances
import net.corda.finance.flows.CashIssueFlow
import net.corda.node.internal.StartedNode
import net.corda.finance.schemas.CashSchemaV1
import net.corda.node.services.network.NetworkMapService
import net.corda.node.services.transactions.ValidatingNotaryService
import net.corda.testing.DUMMY_NOTARY
import net.corda.testing.DUMMY_NOTARY_KEY
import net.corda.testing.chooseIdentity
import net.corda.testing.node.MockNetwork
import org.junit.After
import org.junit.Before
import org.junit.Test
import kotlin.test.assertEquals

class FxTransactionBuildTutorialTest {
    lateinit var mockNet: MockNetwork
    lateinit var notaryNode: StartedNode<MockNetwork.MockNode>
    lateinit var nodeA: StartedNode<MockNetwork.MockNode>
    lateinit var nodeB: StartedNode<MockNetwork.MockNode>

    @Before
    fun setup() {
        mockNet = MockNetwork(threadPerNode = true)
        val notaryService = ServiceInfo(ValidatingNotaryService.type)
        notaryNode = mockNet.createNode(
                legalName = DUMMY_NOTARY.name,
                overrideServices = mapOf(notaryService to DUMMY_NOTARY_KEY),
                advertisedServices = *arrayOf(ServiceInfo(NetworkMapService.type), notaryService))
        nodeA = mockNet.createPartyNode(notaryNode.network.myAddress)
        nodeB = mockNet.createPartyNode(notaryNode.network.myAddress)
        nodeA.internals.registerCustomSchemas(setOf(CashSchemaV1))
        nodeB.internals.registerCustomSchemas(setOf(CashSchemaV1))
        nodeB.internals.registerInitiatedFlow(ForeignExchangeRemoteFlow::class.java)
    }

    @After
    fun cleanUp() {
        mockNet.stopNodes()
    }

    @Test
    fun `Run ForeignExchangeFlow to completion`() {
        // Use NodeA as issuer and create some dollars
        val flowHandle1 = nodeA.services.startFlow(CashIssueFlow(DOLLARS(1000),
                OpaqueBytes.of(0x01),
                notaryNode.services.notaryIdentity.party))
        // Wait for the flow to stop and print
        flowHandle1.resultFuture.getOrThrow()
        printBalances()

        // Using NodeB as Issuer create some pounds.
        val flowHandle2 = nodeB.services.startFlow(CashIssueFlow(POUNDS(1000),
                OpaqueBytes.of(0x01),
                notaryNode.services.notaryIdentity.party))
        // Wait for flow to come to an end and print
        flowHandle2.resultFuture.getOrThrow()
        printBalances()

        // Setup some futures on the vaults to await the arrival of the exchanged funds at both nodes
        val nodeAVaultUpdate = nodeA.services.vaultService.updates.toFuture()
        val nodeBVaultUpdate = nodeB.services.vaultService.updates.toFuture()

        // Now run the actual Fx exchange
        val doIt = nodeA.services.startFlow(ForeignExchangeFlow("trade1",
                POUNDS(100).issuedBy(nodeB.info.chooseIdentity().ref(0x01)),
                DOLLARS(200).issuedBy(nodeA.info.chooseIdentity().ref(0x01)),
                nodeA.info.chooseIdentity(),
                nodeB.info.chooseIdentity()))
        // wait for the flow to finish and the vault updates to be done
        doIt.resultFuture.getOrThrow()
        // Get the balances when the vault updates
        nodeAVaultUpdate.get()
        val balancesA = nodeA.database.transaction {
            nodeA.services.getCashBalances()
        }
        nodeBVaultUpdate.get()
        val balancesB = nodeB.database.transaction {
            nodeB.services.getCashBalances()
        }
        println("BalanceA\n" + balancesA)
        println("BalanceB\n" + balancesB)
        // Verify the transfers occurred as expected
        assertEquals(POUNDS(100), balancesA[GBP])
        assertEquals(DOLLARS(1000 - 200), balancesA[USD])
        assertEquals(POUNDS(1000 - 100), balancesB[GBP])
        assertEquals(DOLLARS(200), balancesB[USD])
    }

    private fun printBalances() {
        // Print out the balances
        nodeA.database.transaction {
            println("BalanceA\n" + nodeA.services.getCashBalances())
        }
        nodeB.database.transaction {
            println("BalanceB\n" + nodeB.services.getCashBalances())
        }
    }
}
