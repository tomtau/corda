.. highlight:: kotlin
.. raw:: html

   <script type="text/javascript" src="_static/jquery.js"></script>
   <script type="text/javascript" src="_static/codesets.js"></script>

Writing flow tests
==================

A flow can be a fairly complex thing that interacts with many services and other parties over the network. That
means unit testing one requires some infrastructure to provide lightweight mock implementations. The MockNetwork
provides this testing infrastructure layer; you can find this class in the test-utils module.

A good example to examine for learning how to unit test flows is the ``ResolveTransactionsFlow`` tests. This
flow takes care of downloading and verifying transaction graphs, with all the needed dependencies. We start
with this basic skeleton:

.. container:: codeset

   .. sourcecode:: kotlin

      class ResolveTransactionsFlowTest {
          lateinit var mockNet: MockNetwork
          lateinit var a: MockNetwork.MockNode
          lateinit var b: MockNetwork.MockNode
          lateinit var notary: Party

          @Before
          fun setup() {
              mockNet = MockNetwork()
              val nodes = mockNet.createSomeNodes()
              a = nodes.partyNodes[0]
              b = nodes.partyNodes[1]
              notary = nodes.notaryNode.services.notaryIdentity.party
              mockNet.runNetwork()
          }

          @After
          fun tearDown() {
              mockNet.stopNodes()
          }
      }

We create a mock network in our ``@Before`` setup method and create a couple of nodes. We also record the identity
of the notary in our test network, which will come in handy later. We also tidy up when we're done.

Next, we write a test case:

.. literalinclude:: ../../core/src/test/kotlin/net/corda/core/flows/ResolveTransactionsFlowTest.kt
    :language: kotlin
    :start-after: DOCSTART 1
    :end-before: DOCEND 1

We'll take a look at the ``makeTransactions`` function in a moment. For now, it's enough to know that it returns two
``SignedTransaction`` objects, the second of which spends the first. Both transactions are known by node A
but not node B.

The test logic is simple enough: we create the flow, giving it node A's identity as the target to talk to.
Then we start it on node B and use the ``mockNet.runNetwork()`` method to bounce messages around until things have
settled (i.e. there are no more messages waiting to be delivered). All this is done using an in memory message
routing implementation that is fast to initialise and use. Finally, we obtain the result of the flow and do
some tests on it. We also check the contents of node B's database to see that the flow had the intended effect
on the node's persistent state.

Here's what ``makeTransactions`` looks like:

.. literalinclude:: ../../core/src/test/kotlin/net/corda/core/flows/ResolveTransactionsFlowTest.kt
    :language: kotlin
    :start-after: DOCSTART 2
    :end-before: DOCEND 2

We're using the ``DummyContract``, a simple test smart contract which stores a single number in its states, along
with ownership and issuer information. You can issue such states, exit them and re-assign ownership (move them).
It doesn't do anything else. This code simply creates a transaction that issues a dummy state (the issuer is
``MEGA_CORP``, a pre-defined unit test identity), signs it with the test notary and MegaCorp keys and then
converts the builder to the final ``SignedTransaction``. It then does so again, but this time instead of issuing
it re-assigns ownership instead. The chain of two transactions is finally committed to node A by sending them
directly to the ``a.services.recordTransaction`` method (note that this method doesn't check the transactions are
valid) inside a ``database.transaction``.  All node flows run within a database transaction in the nodes themselves,
but any time we need to use the database directly from a unit test, you need to provide a database transaction as shown
here.

With regards to initiated flows (see :doc:`flow-state-machines` for information on initiated and initiating flows), the
full node automatically registers them by scanning the CorDapp jars. In a unit test environment this is not possible so
``MockNode`` has the ``registerInitiatedFlow`` method to manually register an initiated flow.

And that's it: you can explore the documentation for the `MockNetwork API <api/kotlin/corda/net.corda.testing.node/-mock-network/index.html>`_
here.
