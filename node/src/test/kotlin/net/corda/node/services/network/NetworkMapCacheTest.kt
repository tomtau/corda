package net.corda.node.services.network

import net.corda.core.node.services.NetworkMapCache
import net.corda.core.node.services.ServiceInfo
import net.corda.core.utilities.getOrThrow
import net.corda.testing.ALICE
import net.corda.testing.BOB
import net.corda.testing.DUMMY_NOTARY
import net.corda.testing.node.MockNetwork
import org.assertj.core.api.Assertions.assertThat
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.math.BigInteger
import kotlin.test.assertEquals

class NetworkMapCacheTest {
    lateinit var mockNet: MockNetwork

    @Before
    fun setUp() {
        mockNet = MockNetwork()
    }

    @After
    fun teardown() {
        mockNet.stopNodes()
    }

    @Test
    fun registerWithNetwork() {
        val mapNode = mockNet.createNotaryNode(null, DUMMY_NOTARY.name)
        val aliceNode = mockNet.createPartyNode(mapNode.network.myAddress, ALICE.name)
        val future = aliceNode.services.networkMapCache.addMapService(aliceNode.network, mapNode.network.myAddress, false, null)
        mockNet.runNetwork()
        future.getOrThrow()
    }

    @Test
    fun `key collision`() {
        val entropy = BigInteger.valueOf(24012017L)
        val nodeA = mockNet.createNode(nodeFactory = MockNetwork.DefaultFactory, legalName = ALICE.name, entropyRoot = entropy, advertisedServices = ServiceInfo(NetworkMapService.type))
        val nodeB = mockNet.createNode(nodeFactory = MockNetwork.DefaultFactory, legalName = BOB.name, entropyRoot = entropy, advertisedServices = ServiceInfo(NetworkMapService.type))
        assertEquals(nodeA.info.legalIdentity, nodeB.info.legalIdentity)

        mockNet.runNetwork()

        // Node A currently knows only about itself, so this returns node A
        assertEquals(nodeA.services.networkMapCache.getNodeByLegalIdentityKey(nodeA.info.legalIdentity.owningKey), nodeA.info)

        nodeA.services.networkMapCache.addNode(nodeB.info)
        // The details of node B write over those for node A
        assertEquals(nodeA.services.networkMapCache.getNodeByLegalIdentityKey(nodeA.info.legalIdentity.owningKey), nodeB.info)
    }

    @Test
    fun `getNodeByLegalIdentity`() {
        val n0 = mockNet.createNotaryNode(null, DUMMY_NOTARY.name)
        val n1 = mockNet.createPartyNode(n0.network.myAddress, ALICE.name)
        val node0Cache: NetworkMapCache = n0.services.networkMapCache
        val expected = n1.info

        mockNet.runNetwork()
        val actual = n0.database.transaction { node0Cache.getNodeByLegalIdentity(n1.info.legalIdentity) }
        assertEquals(expected, actual)

        // TODO: Should have a test case with anonymous lookup
    }

    @Test
    fun `remove node from cache`() {
        val n0 = mockNet.createNotaryNode(null, DUMMY_NOTARY.name)
        val n1 = mockNet.createPartyNode(n0.network.myAddress, ALICE.name)
        val node0Cache = n0.services.networkMapCache as PersistentNetworkMapCache
        mockNet.runNetwork()
        n0.database.transaction {
            assertThat(node0Cache.getNodeByLegalIdentity(n1.info.legalIdentity) != null)
            node0Cache.removeNode(n1.info)
            assertThat(node0Cache.getNodeByLegalIdentity(n1.info.legalIdentity) == null)
            assertThat(node0Cache.getNodeByLegalIdentity(n0.info.legalIdentity) != null)
            assertThat(node0Cache.getNodeByLegalName(n1.info.legalIdentity.name) == null)
        }
    }
}
