package net.corda.loadtest.tests

import net.corda.client.mock.Generator
import net.corda.core.flows.FinalityFlow
import net.corda.core.flows.FlowException
import net.corda.core.internal.concurrent.thenMatch
import net.corda.core.messaging.startFlow
import net.corda.core.transactions.SignedTransaction
import net.corda.finance.contracts.asset.DUMMY_CASH_ISSUER
import net.corda.finance.contracts.asset.DUMMY_CASH_ISSUER_KEY
import net.corda.loadtest.LoadTest
import net.corda.loadtest.NodeConnection
import net.corda.testing.contracts.DummyContract
import net.corda.testing.node.MockServices
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger("NotaryTest")

data class NotariseCommand(val issueTx: SignedTransaction, val moveTx: SignedTransaction, val node: NodeConnection)

val dummyNotarisationTest = LoadTest<NotariseCommand, Unit>(
        "Notarising dummy transactions",
        generate = { _, _ ->
            val issuerServices = MockServices(DUMMY_CASH_ISSUER_KEY)
            val generateTx = Generator.pickOne(simpleNodes).flatMap { node ->
                Generator.int().map {
                    val issueBuilder = DummyContract.generateInitial(it, notary.info.legalIdentities[1], DUMMY_CASH_ISSUER) // TODO notary choice
                    val issueTx = issuerServices.signInitialTransaction(issueBuilder)
                    val asset = issueTx.tx.outRef<DummyContract.SingleOwnerState>(0)
                    val moveBuilder = DummyContract.move(asset, DUMMY_CASH_ISSUER.party)
                    val moveTx = issuerServices.signInitialTransaction(moveBuilder)
                    NotariseCommand(issueTx, moveTx, node)
                }
            }
            Generator.replicate(10, generateTx)
        },
        interpret = { _, _ -> },
        execute = { (issueTx, moveTx, node) ->
            try {
                val proxy = node.proxy
                val issueFlow = proxy.startFlow(::FinalityFlow, issueTx)
                issueFlow.returnValue.thenMatch({
                    proxy.startFlow(::FinalityFlow, moveTx)
                }, {})
            } catch (e: FlowException) {
                log.error("Failure", e)
            }
        },
        gatherRemoteState = {}
)
