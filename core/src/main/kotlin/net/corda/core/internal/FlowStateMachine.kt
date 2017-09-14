package net.corda.core.internal

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.concurrent.CordaFuture
import net.corda.core.crypto.SecureHash
import net.corda.core.flows.*
import net.corda.core.identity.Party
import net.corda.core.identity.PartyAndCertificate
import net.corda.core.node.ServiceHub
import net.corda.core.transactions.SignedTransaction
import net.corda.core.utilities.UntrustworthyData
import org.slf4j.Logger

/** This is an internal interface that is implemented by code in the node module. You should look at [FlowLogic]. */
interface FlowStateMachine<R> {
    @Suspendable
    fun getFlowContext(otherParty: Party, sessionFlow: FlowLogic<*>): FlowContext

    @Suspendable
    fun <T : Any> sendAndReceive(receiveType: Class<T>,
                                 otherParty: Party,
                                 payload: Any,
                                 sessionFlow: FlowLogic<*>,
                                 retrySend: Boolean = false): UntrustworthyData<T>

    @Suspendable
    fun <T : Any> receive(receiveType: Class<T>, otherParty: Party, sessionFlow: FlowLogic<*>): UntrustworthyData<T>

    @Suspendable
    fun send(otherParty: Party, payload: Any, sessionFlow: FlowLogic<*>): Unit

    @Suspendable
    fun waitForLedgerCommit(hash: SecureHash, sessionFlow: FlowLogic<*>): SignedTransaction

    fun checkFlowPermission(permissionName: String, extraAuditData: Map<String, String>): Unit

    fun recordAuditEvent(eventType: String, comment: String, extraAuditData: Map<String, String>): Unit

    @Suspendable
    fun flowStackSnapshot(flowClass: Class<out FlowLogic<*>>): FlowStackSnapshot?

    @Suspendable
    fun persistFlowStackSnapshot(flowClass: Class<out FlowLogic<*>>): Unit

    val serviceHub: ServiceHub
    val logger: Logger
    val id: StateMachineRunId
    val resultFuture: CordaFuture<R>
    val flowInitiator: FlowInitiator
    val ourIdentity: PartyAndCertificate
}
