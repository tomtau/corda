package net.corda.core.flows

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.identity.Party
import net.corda.core.utilities.UntrustworthyData

/**
 *
 * To port existing flows:
 *
 * Look for Deprecated usages of send/receive/sendAndReceive.
 *
 * If it's an InitiatingFlow:
 *
 *   Look the send/receive that kicks off the counter flow. Insert a
 *
 *     val session = initiateFlow(party)
 *
 *   and use this session afterwards for send/receives.
 *   For example:
 *     send(party, something)
 *   will become
 *     session.send(something)
 *
 * If it's an InitiatedBy flow:
 *
 *   Change the constructor to take an initiatingSession: FlowSession instead of a counterparty: Party
 *   Then look for usages of the deprecated functions and change them to use the FlowSession
 *   For example:
 *     send(party, something)
 *   will become
 *     initiatingSession.send(something)
 */
abstract class FlowSession {
    abstract val counterparty: Party

    /**
     * Returns a [FlowInfo] object describing the flow [otherParty] is using. With [FlowInfo.flowVersion] it
     * provides the necessary information needed for the evolution of flows and enabling backwards compatibility.
     *
     * This method can be called before any send or receive has been done with [otherParty]. In such a case this will force
     * them to start their flow.
     */
    @Suspendable
    abstract fun getCounterpartyFlowInfo(): FlowInfo

    /**
     * Serializes and queues the given [payload] object for sending to the [otherParty]. Suspends until a response
     * is received, which must be of the given [R] type.
     *
     * Remember that when receiving data from other parties the data should not be trusted until it's been thoroughly
     * verified for consistency and that all expectations are satisfied, as a malicious peer may send you subtly
     * corrupted data in order to exploit your code.
     *
     * Note that this function is not just a simple send+receive pair: it is more efficient and more correct to
     * use this when you expect to do a message swap than do use [send] and then [receive] in turn.
     *
     * @returns an [UntrustworthyData] wrapper around the received object.
     */
    @Suspendable
    inline fun <reified R : Any> sendAndReceive(payload: Any): UntrustworthyData<R> {
        return sendAndReceive(R::class.java, payload)
    }
    /**
     * Serializes and queues the given [payload] object for sending to the [otherParty]. Suspends until a response
     * is received, which must be of the given [receiveType]. Remember that when receiving data from other parties the data
     * should not be trusted until it's been thoroughly verified for consistency and that all expectations are
     * satisfied, as a malicious peer may send you subtly corrupted data in order to exploit your code.
     *
     * Note that this function is not just a simple send+receive pair: it is more efficient and more correct to
     * use this when you expect to do a message swap than do use [send] and then [receive] in turn.
     *
     * @returns an [UntrustworthyData] wrapper around the received object.
     */
    @Suspendable
    abstract fun <R : Any> sendAndReceive(receiveType: Class<R>, payload: Any): UntrustworthyData<R>

    /**
     * Suspends until the specified [otherParty] sends us a message of type [R].
     *
     * Remember that when receiving data from other parties the data should not be trusted until it's been thoroughly
     * verified for consistency and that all expectations are satisfied, as a malicious peer may send you subtly
     * corrupted data in order to exploit your code.
     */
    @Suspendable
    inline fun <reified R : Any> receive(): UntrustworthyData<R> {
        return receive(R::class.java)
    }
    /**
     * Suspends until the specified [otherParty] sends us a message of type [receiveType].
     *
     * Remember that when receiving data from other parties the data should not be trusted until it's been thoroughly
     * verified for consistency and that all expectations are satisfied, as a malicious peer may send you subtly
     * corrupted data in order to exploit your code.
     *
     * @returns an [UntrustworthyData] wrapper around the received object.
     */
    @Suspendable
    abstract fun <R : Any> receive(receiveType: Class<R>): UntrustworthyData<R>

    /**
     * Queues the given [payload] for sending to the [otherParty] and continues without suspending.
     *
     * Note that the other party may receive the message at some arbitrary later point or not at all: if [otherParty]
     * is offline then message delivery will be retried until it comes back or until the message is older than the
     * network's event horizon time.
     */
    @Suspendable
    abstract fun send(payload: Any)
}
