# Solidus

Solidus is a protocol for confidential transactions on distributed ledgers.
This repository contains a prototype implementation of the protocol along with a driver allowing it to run atop [Apache ZooKeeper](https://zookeeper.apache.org/).


## What is Solidus?

Solidus is a cryptographic protocol for confidential distributed settlement of financial transactions on a public distributed ledger.
It operates in a framework based on real-world financial institutions: a modest number of banks each maintain a large number of user accounts.
Within this framework, Solidus hides both transaction values and the transaction graph (i.e., the identities of transacting entities)
while ensuring that all actions are fully publicly verifiable.

For a brief overview of the protocol, trust model, and problems Solidus aims to solve, see the [Brief Overview](#brief-overview) section below.
For a detailed explanation with formal definitions and theorems, see the [Solidus academic paper](https://eprint.iacr.org/2017/317.pdf).


## Running the Code

### Warning: This is Just a Prototype!

The code in this repository was originally created as a research prototype of Solidus.
***It is not production ready.***
While we hope that the prototype will serve as an effective guide for anyone wishing to incorporate the Solidus protocol into a real-world system,
in whole or in part, significant modifications would be necessary.

As this prototype was built only to test performance characteristics of the protocol, it does not implement several important features.
* The code cannot tolerate malformed user input or banks that fail to respond or respond incorrectly.
  While the _protocol_ is highly robust to such errors and this implementation can identify failures (aside from timeouts),
  this prototype cannot recover properly.
  We made this choice because recovery is nontrivial to implement and is unnecessary to benchmark performance in the absence of errors.
  * Validity checking is done at the application layer, not the consensus layer to avoid needing to modify Apache ZooKeeper.
    To properly recover from some types of failures, the consensus layer would need to perform verification.
  * Other failure tolerance mechanisms (e.g., response timeouts from other banks) require recomputing transactions or changing the order of requests in nontrivial ways.
* We do not implement [asset notaries](#asset-notaries)&mdash;the means for creating and destroying assets.
  * Since assets cannot be created, we do not verify that accounts start with a balance of zero.
* Each bank has a static set of accounts. We do not implement a means for banks to add or remove accounts after joining the system.
* Transaction ID timeouts are not checked as required by the protocol.
* There is no way to split a single bank across multiple hosts. Such distribution is important for performance scaling.
* Users are currently placed on the same hosts as their banks for simplicity.
* If a bank's PVORM stash overflows, we error instead of properly revealing an overflow and reinserting a value elsewhere in the PVORM.

Finally, though the Solidus protocol is agnostic to the underlying consensus algorithm, we only provide a driver to run it with ZooKeeper.
The suitability of ZooKeeper is highly dependent on the specific trust and reliability concerns of a given system.

### Getting Started

If you still want to run the Solidus prototype, you will need [JDK 1.8](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html) (or newer),
and an installation of [Apache ZooKeeper](https://zookeeper.apache.org/) (v3.4.9 or newer).
These must both be installed and set up on each machine that will run Solidus.
Each host should be running a single instance of ZooKeeper to which one more more Solidus banks can connect.
No other processes should connect to the ZooKeeper network.

Any number of Solidus banks can operate on a single host (each connecting to the same ZooKeeper process on that host),
but placing more than one bank on a single host will reduce performance;
bank-level verification is extremely CPU-intensive and having multiple banks on the same host will force them to compete for system resources.

#### Building and Running the Code

Building the Solidus prototype is done through `ant`.
The system contains the following `ant` targets:
* `solidus` (default): This compiles the basic Solidus system code
* `compile.bench`: The compiles the benchmarking utilities.
* `test`: Compiles and runs the Solidus unit tests. Reports are placed in the `test-reports/` directory.
* `doc`: Builds JavaDoc documentation into the `doc/` directory.
* `all`: Compiles all code, runs all unit tests, and builds documentation.
* `clean`: Removes all generated files.
* `full`: The same as `ant clean all`.

All compiled code is placed in the `bin/` directory.
To run benchmarks, simply use `javac` including `lib/` and `bin/` in the classpath.

#### ZooKeeper Driver

The [ZooKeeper Driver](src/solidus/zookeeper/ZooKeeperDriver.java) provides an asynchronous interface for applications to connect to a Solidus instance running on top of ZooKeeper.

In order to connect to a Solidus instance, an application must construct a [`Bank` object](src/solidus/state/Bank.java) with all accounts already created
(see above, we do not support dynamic account creation),
and pass that to a new `ZooKeeperDriver` object with the proper connection string
(same connection string as the Apache ZooKeeper's [ZooKeeper Object](https://zookeeper.apache.org/doc/r3.4.9/api/index.html?org/apache/zookeeper/ZooKeeper.html)).
From here, all interaction can occur through the `ZooKeeperDriver` object.

The primary means of interaction is through `ZooKeeperDriver`'s `requestTransaction` methods.
These methods allow a user to queue a transaction request which the driver will process using the local `Bank` object at the next available opportunity.
Outgoing requests from a single bank are processed asynchronously in a first-in-first-out (FIFO) order.
However, each bank can only process one transaction involving that bank (incoming or outgoing) at a time.
This means that requested transactions may be arbitrarily delayed if they are repeatedly preempted by new incoming transactions.

When requesting a transaction, a user may optionally specify a callback to execute when the transaction is processed.
This callback must contain a success operation to invoke if the transaction settles, and a failure operation to invoke if an error occurs.
If no callback is provided, the user will have no direct way of knowing when the transaction is processed.

Code can also register global transaction callbacks to be invoked whenever this node becomes aware of a new settled transaction (regardless of the banks involved).
The callbacks are simply provided with the transaction IDs of the settled transactions, so this is of little use beyond counting transactions and recording IDs.


## Brief Overview

Blockchain-based cryptocurrencies, such as Bitcoin, allow users to transfer value quickly and pseudonymously on a reliable distributed public ledger.
This ability to manage assets privately and authoritatively in a single ledger is appealing in many settings beyond cryptocurrencies.
In particular, financial institutions are exploring ledger-based systems for (nearly) instantaneous financial settlement.
For many of these companies, confidentiality is a major concern and Bitcoin-type systems are markedly insufficient;
they expose transaction values and pseudonyms of transacting entities, often permitting deanonymization of services and users&nbsp;[[3](#references)].
Direct peer-to-peer transactions, moreover, interfere with the customer-service role and know-your-customer regulatory requirements of financial institutions.

Solidus instead operates in a system modeled on the real-world financial system.
There are a modest number of banks each with a large number of accounts.
In order for two accounts to transact, they must go through their respective banks.
We refer to such systems as _bank-intermediated_.
Within this bank-intermediate system, Solidus aims to provide maximal confidentiality to both users and banks.

### System Architecture

The Solidus system consists of a predetermined set of banks, each with some number of user accounts.
Each user account is publicly associated with a single bank.
Account balances are stored on the ledger in a Publicly Verifiable Oblivious RAM Machine ([PVORM](#pvorm)),
encrypted under their bank's public encryption key.

In order to transfer money, a user authorizes its bank to send a certain amount of money to a specific account at a given bank.
The bank then forwards the request to the receiving bank, each of which update their respective PVORMs.
Once both updates are complete, the banks post the completed transaction to the ledger,
including publicly-verifiable proofs that the updates were performed correctly.
This constitutes settlement of the transaction.

#### Asset Notaries

In the above scheme, all transactions must be zero-sum.
That is, one account must lose exactly the amount of money another gains.
Generally speaking, however, financial systems are not closed; assets can enter and leave the system.
To account for this, specific users can be designed _asset notaires_.
Asset notaries do not have balances and are trusted to create and destroy assets within the system.
For a more complete explanation of asset notaries and an example of what they might represent, see Section 3 of the [Solidus paper](http://www.initc3.org/files/solidus.pdf).

### Trust Model

Solidus assumes that banks respect the confidentiality of their own users but otherwise nobody need not behave honestly.
Banks or users may attempt to steal money, illicitly give money to others, manipulate account balances, falsify proofs, etc.
Banks may also attempt to violate the confidentiality of other banks or those banks' users.
Similarly users may attempt to violate anyone's confidentiality.
We assume no bound on the number of corrupted (and colluding) users or banks; we merely make guarantees for honest users and banks.

We assume that the ledger is a public immutable ledger that banks may post to.
We moreover assume that it will verify that transactions are well-formed (including the validity of the proofs).
We also assume that it will remain available.
These requirements can be instantiated in a number of ways;
the banks could collectively maintain the ledger using a Byzantine fault-tolerant protocol (e.g. PBFT&nbsp;[[2](#references)]),
the ledger could be maintained by a separate set of servers all trusted for correctness (e.g., using ZooKeeper),
or even a single log server trusted for correctness and availability.

### Security Goals

Solidus maintains a simple but strong set of safety guarantees:
* No user's balance can decrease without explicit permission from that user and a single authorization cannot be replayed.
* A user cannot spend money not present in the sending account.
* Transactions not including asset notaries must be zero-sum.

Solidus similarly maintains a strong set of confidentiality guarantees:
* Account balances are not visible except to a user's bank.
* Transactions publicly reveal the sending and receiving banks, but no other information (except to transacting entities)
  * The sending bank learns the transaction value and identity of the sending account, but not the identity of the receiving account.
  * The receiving bank learns the transaction value and the identity of the receiving account, not the identity of the sending account.

We additionally support auditors which can be authorized to audit one or more banks.
Each auditor is able to read all information available to any banks it audits, but it cannot modify any values on the ledger.
Auditors can use this information investigate potential fraud or abuse.
For example, if a bank illegitimately freezes a user's assets, an auditor can help that user recover those assets with aid of an asset notary
by proving that the user had a given account balance to the asset notary, which can then reissue the assets to a new account at a new bank.

### PVORM

Solidus employs a Publicly Verifiable Oblivious RAM Machine (PVORM) to maintain confidentiality of account accesses in a publicly-verifiable fashion.
A PVORM is designed to be a publicly visible storage system that obscures data values and access patters, while restricting updates (e.g., all balances must be non-negative).
Anyone who can view the public component of the PVORM can verify that an update was performed correctly and conforms to the restriction.
For details, see the Section 4 of the [Solidus paper](http://www.initc3.org/files/solidus.pdf).

Our PVORM construction is based on Circuit ORAM [[4](#references)] and makes heavy use of Generalized Schnorr Proofs [[1](#references)] for public verifiability.


## References

[1] J. Camenisch, A. Kiayias, and M. Yung. On the Portability of Generalized Schnorr Proofs. In _EUROCRYPT_, 2009.

[2] M. Castro and B. Liskov. Practical Byzantine Fault Tolerance. In _OSDI_, 1999.

[3] S. Meiklejohn, M. Pomarole, G. Jordan, K. Levchenko, D. McCoy, G. M. Voelker, and S. Savage. A fistful of bitcoins: characterizing payments among men with no names. In _IMC_, 2013.

[4] X. S. Wang, T.-H. H. Chan, and E. Shi. Circuit ORAM: On Tightness of the Goldreich-Ostrovsky Lower Bound. In _CCS_, 2015.
