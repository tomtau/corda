package net.corda.vega.flows

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.InitiatedBy
import net.corda.core.flows.InitiatingFlow
import net.corda.core.flows.StartableByRPC
import net.corda.core.identity.Party
import net.corda.core.serialization.CordaSerializable
import net.corda.core.transactions.SignedTransaction
import net.corda.core.utilities.unwrap
import net.corda.finance.flows.TwoPartyDealFlow
import net.corda.vega.contracts.IRSState
import net.corda.vega.contracts.OGTrade
import net.corda.vega.contracts.SwapData

object IRSTradeFlow {
    @CordaSerializable
    data class OfferMessage(val notary: Party, val dealBeingOffered: IRSState)

    @InitiatingFlow
    @StartableByRPC
    class Requester(val swap: SwapData, val otherParty: Party) : FlowLogic<SignedTransaction>() {
        @Suspendable
        override fun call(): SignedTransaction {
            require(serviceHub.networkMapCache.notaryIdentities.isNotEmpty()) { "No notary nodes registered" }
            val notary = serviceHub.networkMapCache.notaryIdentities.first().party
            val (buyer, seller) =
                    if (swap.buyer.second == ourIdentity.owningKey) {
                        Pair(ourIdentity.party, otherParty)
                    } else {
                        Pair(otherParty, ourIdentity.party)
                    }
            val offer = IRSState(swap, buyer, seller)

            logger.info("Handshake finished, sending IRS trade offer message")
            val otherPartyAgreeFlag = sendAndReceive<Boolean>(otherParty, OfferMessage(notary, offer)).unwrap { it }
            require(otherPartyAgreeFlag)

            return subFlow(TwoPartyDealFlow.Instigator(
                    otherParty,
                    TwoPartyDealFlow.AutoOffer(notary, offer)))
        }

    }

    @InitiatedBy(Requester::class)
    class Receiver(private val replyToParty: Party) : FlowLogic<Unit>() {
        @Suspendable
        override fun call() {
            logger.info("IRSTradeFlow receiver started")
            logger.info("Handshake finished, awaiting IRS trade offer")

            val offer = receive<OfferMessage>(replyToParty).unwrap { it }
            // Automatically agree - in reality we'd vet the offer message
            require(serviceHub.networkMapCache.notaryIdentities.map { it.party }.contains(offer.notary))
            send(replyToParty, true)
            subFlow(TwoPartyDealFlow.Acceptor(replyToParty))
        }
    }
}
