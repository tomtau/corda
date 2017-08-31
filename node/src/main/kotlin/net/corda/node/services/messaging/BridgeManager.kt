package net.corda.node.services.messaging

import io.netty.channel.Channel
import io.netty.handler.ssl.SslHandler
import net.corda.core.crypto.AddressFormatException
import net.corda.core.crypto.parsePublicKeyBase58
import net.corda.core.internal.toX509CertHolder
import net.corda.core.node.NodeInfo
import net.corda.core.node.services.NetworkMapCache
import net.corda.core.node.services.ServiceType
import net.corda.core.utilities.NetworkHostAndPort
import net.corda.core.utilities.debug
import net.corda.core.utilities.loggerFor
import net.corda.core.utilities.trace
import net.corda.node.services.config.NodeConfiguration
import net.corda.node.utilities.X509Utilities
import net.corda.nodeapi.ArtemisMessagingComponent
import net.corda.nodeapi.ArtemisTcpTransport
import net.corda.nodeapi.ConnectionDirection
import org.apache.activemq.artemis.api.core.SimpleString
import org.apache.activemq.artemis.api.core.client.*
import org.apache.activemq.artemis.api.core.management.CoreNotificationType
import org.apache.activemq.artemis.api.core.management.ManagementHelper
import org.apache.activemq.artemis.jms.bridge.ConnectionFactoryFactory
import org.apache.activemq.artemis.jms.bridge.DestinationFactory
import org.apache.activemq.artemis.jms.bridge.QualityOfServiceMode
import org.apache.activemq.artemis.jms.bridge.impl.JMSBridgeImpl
import org.apache.activemq.artemis.jms.client.ActiveMQConnectionFactory
import org.apache.activemq.artemis.jms.client.ActiveMQQueue
import org.apache.qpid.jms.JmsConnectionFactory
import org.apache.qpid.jms.JmsTopic
import org.apache.qpid.jms.transports.TransportOptions
import org.apache.qpid.jms.transports.netty.NettySslTransportFactory
import org.apache.qpid.jms.transports.netty.NettyTcpTransport
import org.bouncycastle.asn1.x500.X500Name
import java.net.URI
import java.util.concurrent.ConcurrentHashMap

class BridgeManager(private val serverLocator: ServerLocator,
                    private val serverAddress: NetworkHostAndPort,
                    private val username: String,
                    private val password: String,
                    private val networkMap: NetworkMapCache,
                    private val config: NodeConfiguration
) {
    companion object {
        val BRIDGE_MANAGER = "${ArtemisMessagingComponent.INTERNAL_PREFIX}bridge.manager"
        val BRIDGE_MANAGER_FILTER = "${ManagementHelper.HDR_NOTIFICATION_TYPE} = '${CoreNotificationType.BINDING_ADDED.name}' AND " +
                "${ManagementHelper.HDR_ROUTING_NAME} LIKE '${ArtemisMessagingComponent.INTERNAL_PREFIX}%'"
        private val log = loggerFor<BridgeManager>()

        private val expectedLegalName = ConcurrentHashMap<String, X500Name>()
    }

    private val bridges = mutableListOf<JMSBridgeImpl>()
    private lateinit var session: ClientSession
    private lateinit var consumer: ClientConsumer

    fun start() {
        log.trace { "Starting BridgeManager.." }
        val sessionFactory = serverLocator.createSessionFactory()
        session = sessionFactory.createSession(username, password, false, true, true, false, ActiveMQClient.DEFAULT_ACK_BATCH_SIZE)
        consumer = session.createConsumer(BRIDGE_MANAGER)
        consumer.setMessageHandler(this::bindingsAddedHandler)
        session.start()

        connectToNetworkMapService()
    }

    private fun connectToNetworkMapService() {
        config.networkMapService?.let { deployBridge(ArtemisMessagingComponent.NetworkMapAddress(it.address), it.legalName) }
        networkMap.changed.subscribe { updateBridgesOnNetworkChange(it) }
    }

    private fun bindingsAddedHandler(artemisMessage: ClientMessage) {
        val notificationType = artemisMessage.getStringProperty(ManagementHelper.HDR_NOTIFICATION_TYPE)
        require(notificationType == CoreNotificationType.BINDING_ADDED.name)

        val clientAddress = SimpleString(artemisMessage.getStringProperty(ManagementHelper.HDR_ROUTING_NAME))
        log.debug { "Queue bindings added, deploying JMS bridge to $clientAddress" }
        deployBridgesFromNewQueue(clientAddress.toString())
    }

    private fun deployBridgesFromNewQueue(queueName: String) {
        log.debug { "Queue created: $queueName, deploying bridge(s)" }

        fun deployBridgeToPeer(nodeInfo: NodeInfo) {
            log.debug("Deploying bridge for $queueName to $nodeInfo")
            val address = nodeInfo.addresses.first() // TODO Load balancing.
            deployBridge(queueName, address, nodeInfo.legalIdentity.name)
        }

        when {
            queueName.startsWith(ArtemisMessagingComponent.PEERS_PREFIX) -> try {
                val identity = parsePublicKeyBase58(queueName.substring(ArtemisMessagingComponent.PEERS_PREFIX.length))
                val nodeInfo = networkMap.getNodeByLegalIdentityKey(identity)
                if (nodeInfo != null) {
                    deployBridgeToPeer(nodeInfo)
                } else {
                    log.error("Queue created for a peer that we don't know from the network map: $queueName")
                }
            } catch (e: AddressFormatException) {
                log.error("Flow violation: Could not parse peer queue name as Base 58: $queueName")
            }

            queueName.startsWith(ArtemisMessagingComponent.SERVICES_PREFIX) -> try {
                val identity = parsePublicKeyBase58(queueName.substring(ArtemisMessagingComponent.SERVICES_PREFIX.length))
                val nodeInfos = networkMap.getNodesByAdvertisedServiceIdentityKey(identity)
                // Create a bridge for each node advertising the service.
                for (nodeInfo in nodeInfos) {
                    deployBridgeToPeer(nodeInfo)
                }
            } catch (e: AddressFormatException) {
                log.error("Flow violation: Could not parse service queue name as Base 58: $queueName")
            }
        }
    }

    private fun deployBridge(address: ArtemisMessagingComponent.ArtemisPeerAddress, legalName: X500Name) {
        deployBridge(address.queueName, address.hostAndPort, legalName)
    }

    /**
     * All nodes are expected to have a public facing address called [ArtemisMessagingComponent.P2P_QUEUE] for receiving
     * messages from other nodes. When we want to send a message to a node we send it to our internal address/queue for it,
     * as defined by ArtemisAddress.queueName. A bridge is then created to forward messages from this queue to the node's
     * P2P address.
     */
    private fun deployBridge(queueName: String, target: NetworkHostAndPort, legalName: X500Name) {
        expectedLegalName[target.toString()] = legalName

        val sourceConnectionFactoryFactory = buildSourceConnectionFactoryFactory()
        val destinationConnectionFactoryFactory = buildTargetConnectionFactoryFactory(target)

        val sourceQueue = DestinationFactory { ActiveMQQueue(queueName) }
        val destinationTopic = DestinationFactory { JmsTopic(ArtemisMessagingComponent.P2P_QUEUE) }

        val jmsBridge = JMSBridgeImpl(
                sourceConnectionFactoryFactory,
                destinationConnectionFactoryFactory,
                sourceQueue,
                destinationTopic,
                username,
                password,
                ArtemisMessagingComponent.PEER_USER,
                ArtemisMessagingComponent.PEER_USER,
                null,
                5000,
                10,
                QualityOfServiceMode.DUPLICATES_OK,
                1,
                -1,
                null,
                null,
                true)

        jmsBridge.bridgeName = "$queueName -> $target ($legalName)"

        jmsBridge.start()
        if (!jmsBridge.isFailed) bridges.add(jmsBridge)
    }

    private fun buildTargetConnectionFactoryFactory(target: NetworkHostAndPort): ConnectionFactoryFactory {
        val targetTransportOptions = mapOf(
                "keyStoreLocation" to config.sslKeystore.toString(),
                "keyStorePassword" to config.keyStorePassword,
                "trustStoreLocation" to config.trustStoreFile.toString(),
                "trustStorePassword" to config.trustStorePassword,
                "enabledCipherSuites" to ArtemisTcpTransport.CIPHER_SUITES.joinToString(","),
                "verifyHost" to "false"
        )
        val targetQueryString = targetTransportOptions.map { (k, v) -> "transport.$k=$v" }.joinToString("&")
        val targetServerURL = "amqps://${target.host}:${target.port}?$targetQueryString"

        return ConnectionFactoryFactory {
            JmsConnectionFactory(targetServerURL)
        }
    }

    private fun buildSourceConnectionFactoryFactory(): ConnectionFactoryFactory {
        val sourceTransportConfiguration = ArtemisTcpTransport.tcpTransport(
                ConnectionDirection.Outbound(),
                serverAddress,
                config
        )
        return ConnectionFactoryFactory {
            ActiveMQConnectionFactory(false, sourceTransportConfiguration)
        }
    }

    fun stop() {
        consumer.close()
        session.close()
        bridges.forEach { it.stop() }
    }

    private fun bridgeExists(bridgeName: String): Boolean {
        return bridges.any { it.bridgeName == bridgeName }
    }

    private fun queueExists(queueName: String) = session.queueQuery(SimpleString(queueName)).isExists

    private fun updateBridgesOnNetworkChange(change: NetworkMapCache.MapChange) {
        log.debug { "Updating bridges on network change: $change" }

        fun gatherAddresses(node: NodeInfo): Sequence<ArtemisMessagingComponent.ArtemisPeerAddress> {
            val peerAddress = getArtemisPeerAddress(node)
            val addresses = mutableListOf(peerAddress)
            node.advertisedServices.mapTo(addresses) { ArtemisMessagingComponent.NodeAddress.asService(it.identity.owningKey, peerAddress.hostAndPort) }
            return addresses.asSequence()
        }

        fun deployBridges(node: NodeInfo) {
            gatherAddresses(node)
                    .filter { queueExists(it.queueName) && !bridgeExists(node.legalIdentity.name.toString()) }
                    .forEach { deployBridge(it, node.legalIdentity.name) }
        }

        fun destroyBridges(node: NodeInfo) {
            gatherAddresses(node).forEach {
                val br = bridges.singleOrNull { it.bridgeName == node.legalIdentity.name.toString() }
                br?.let {
                    bridges.remove(it)
                    it.destroy()
                }
            }
        }

        when (change) {
            is NetworkMapCache.MapChange.Added -> {
                deployBridges(change.node)
            }
            is NetworkMapCache.MapChange.Removed -> {
                destroyBridges(change.node)
            }
            is NetworkMapCache.MapChange.Modified -> {
                // TODO Figure out what has actually changed and only destroy those bridges that need to be.
                destroyBridges(change.previousNode)
                deployBridges(change.node)
            }
        }
    }

    private fun getArtemisPeerAddress(nodeInfo: NodeInfo): ArtemisMessagingComponent.ArtemisPeerAddress {
        return if (nodeInfo.advertisedServices.any { it.info.type == ServiceType.networkMap }) {
            ArtemisMessagingComponent.NetworkMapAddress(nodeInfo.addresses.first())
        } else {
            ArtemisMessagingComponent.NodeAddress.asPeer(nodeInfo.legalIdentity.owningKey, nodeInfo.addresses.first())
        }
    }

    class VerifyingNettyTransport(remoteLocation: URI, options: TransportOptions) : NettyTcpTransport(remoteLocation, options) {
        override fun handleConnected(channel: Channel) {
            val expectedLegalName = expectedLegalName["$remoteHost:$remotePort"]
            val session = channel
                    .pipeline()
                    .get(SslHandler::class.java)
                    .engine()
                    .session

            try {
                // Checks the peer name is the one we are expecting.
                val peerLegalName = session.peerPrincipal.name.let(::X500Name)
                require(peerLegalName == expectedLegalName) {
                    "Peer has wrong CN - expected $expectedLegalName but got $peerLegalName. This is either a fatal " +
                            "misconfiguration by the remote peer or an SSL man-in-the-middle attack!"
                }
                // Make sure certificate has the same name.
                val peerCertificate = session.peerCertificateChain[0].toX509CertHolder()
                require(peerCertificate.subject == expectedLegalName) {
                    "Peer has wrong subject name in the certificate - expected $expectedLegalName but got ${peerCertificate.subject}. This is either a fatal " +
                            "misconfiguration by the remote peer or an SSL man-in-the-middle attack!"
                }
                X509Utilities.validateCertificateChain(session.localCertificates.last().toX509CertHolder(), *session.peerCertificates)
                super.handleConnected(channel)
            } catch (e: IllegalArgumentException) {
                handleException(channel, e)
            }
        }
    }

    class VerifyingNettyTransportFactory : NettySslTransportFactory() {
        override fun doCreateTransport(remoteURI: URI, transportOptions: TransportOptions): NettyTcpTransport {
            return VerifyingNettyTransport(remoteURI, transportOptions)
        }
    }
}

