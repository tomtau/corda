package net.corda.client.jfx.model

import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import javafx.beans.value.ObservableValue
import javafx.collections.FXCollections
import javafx.collections.ObservableList
import net.corda.client.jfx.utils.fold
import net.corda.client.jfx.utils.map
import net.corda.core.identity.AbstractParty
import net.corda.core.identity.AnonymousParty
import net.corda.core.node.NodeInfo
import net.corda.core.node.services.NetworkMapCache.MapChange
import java.security.PublicKey

class NetworkIdentityModel {
    private val networkIdentityObservable by observable(NodeMonitorModel::networkMap)

    val networkIdentities: ObservableList<NodeInfo> =
            networkIdentityObservable.fold(FXCollections.observableArrayList()) { list, update ->
                list.removeIf {
                    when (update) {
                        is MapChange.Removed -> it == update.node
                        is MapChange.Modified -> it == update.previousNode
                        else -> false
                    }
                }
                list.addAll(update.node)
            }

    private val rpcProxy by observableValue(NodeMonitorModel::proxyObservable)

    private val identityCache = CacheBuilder.newBuilder()
            .build<PublicKey, ObservableValue<NodeInfo?>>(CacheLoader.from {
                publicKey ->
                publicKey?.let { rpcProxy.map { it?.nodeIdentityFromParty(AnonymousParty(publicKey)) } }
            })

    val parties: ObservableList<NodeInfo> = networkIdentities.filtered { !it.isCordaService() }
    val notaries: ObservableList<NodeInfo> = networkIdentities.filtered { it.advertisedServices.any { it.info.type.isNotary() } }
    val myNodeInfo = rpcProxy.map { it?.nodeInfo() } // TODO Used only for querying for advertised services, remove with services.
    val myIdentity = myNodeInfo.map { it?.legalIdentitiesAndCerts?.first()?.party }

    private fun NodeInfo.isCordaService(): Boolean {
        // TODO: better way to identify Corda service?
        return advertisedServices.any { it.info.type.isNetworkMap() || it.info.type.isNotary() }
    }

    fun partyFromPublicKey(publicKey: PublicKey): ObservableValue<NodeInfo?> = identityCache[publicKey]
    //TODO rebase fix
//    // TODO: Use Identity Service in service hub instead?
//    fun lookup(publicKey: PublicKey): ObservableValue<PartyAndCertificate?> {
//        val party = parties.flatMap { it.legalIdentitiesAndCerts }.firstOrNull { publicKey in it.owningKey.keys } ?:
//                notaries.flatMap { it.legalIdentitiesAndCerts }.firstOrNull { it.owningKey.keys.any { it == publicKey }}
//        return ReadOnlyObjectWrapper(party)
//    }
}
