package net.corda.explorer.model

import javafx.collections.FXCollections
import javafx.collections.ObservableList
import net.corda.client.jfx.model.NetworkIdentityModel
import net.corda.client.jfx.model.observableList
import net.corda.client.jfx.model.observableValue
import net.corda.client.jfx.utils.ChosenList
import net.corda.client.jfx.utils.map
import net.corda.core.identity.Party
import net.corda.core.node.NodeInfo
import net.corda.core.node.ServiceEntry
import tornadofx.*
import java.util.*

val ISSUER_SERVICE_TYPE = Regex("corda.issuer.(USD|GBP|CHF|EUR)")

class IssuerModel {
    // TODO pass issuers separately from NetworkIdentityModel? OR just don't care if you contact someone that doesn't issue cash
    private val networkIdentities by observableList(NetworkIdentityModel::networkIdentities)
    private val myIdentity by observableValue(NetworkIdentityModel::myIdentity)
    private val supportedCurrencies by observableList(ReportingCurrencyModel::supportedCurrencies)

    // TODO
    val issuers: ObservableList<NodeInfo> = FXCollections.observableList(networkIdentities)//.flatMap { it.advertisedServices }.filter { it.info.type.id.matches(ISSUER_SERVICE_TYPE) })

    val currencyTypes = ChosenList(myIdentity.map { supportedCurrencies })
//        it?.issuerCurrency()?.let { (listOf(it)).observable() } ?: supportedCurrencies

    val transactionTypes = ChosenList(myIdentity.map {
        if (it?.isIssuerNode() ?: false)
            CashTransaction.values().asList().observable()
        else
            listOf(CashTransaction.Pay).observable()
    })

    private fun Party.isIssuerNode() = true//advertisedServices.any { it.info.type.id.matches(ISSUER_SERVICE_TYPE) }
}
