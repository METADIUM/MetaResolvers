const { sign, verifyIdentity, defaultErrorMessage } = require('../../common')

const IdentityRegistry = artifacts.require('./IdentityRegistry.sol')
const ServiceKeyResolver = artifacts.require('./examples/Resolvers/ServiceKey/ServiceKeyResolver.sol')

const privateKeys = [
  '0x2665671af93f210ddb5d5ffa16c77fcf961d52796f2b2d7afd32cc5d886350a8',
  '0x6bf410ff825d07346c110c5836b33ec76e7d1ee051283937392180b732aa3aff',
  '0xccc3c84f02b038a5d60d93977ab11eb57005f368b5f62dad29486edeb4566954',
  '0xccc3c84f02b038a5d60d93977ab11eb57005f368b5f62dad29486edeb4566955',
  '0xccc3c84f02b038a5d60d93977ab11eb57005f368b5f62dad29486edeb4566956'
]

// convenience variables
const instances = {}
let accountsPrivate
let identity

contract('Testing Service Key Resolver', function (accounts) {
  accountsPrivate = accounts.map((account, i) => { return { address: account, private: privateKeys[i] } })

  identity = {
    recoveryAddress:     accountsPrivate[0],
    associatedAddresses: accountsPrivate.slice(1, 3),
    providers: []
  }

  services = accountsPrivate.slice(4, 5)

  describe('Deploying Contracts', function () {
    it('IdentityRegistry contract deployed', async function () {
      instances.IdentityRegistry = await IdentityRegistry.new()
    })

    it('Resolver contract deployed', async function () {
      instances.Resolver = await ServiceKeyResolver.new(instances.IdentityRegistry.address)
      identity.resolvers = [instances.Resolver.address]
    })

    it('Identity can be created', async function () {
      await instances.IdentityRegistry.createIdentity(
        identity.recoveryAddress.address, [], [],
        { from: identity.associatedAddresses[0].address }
      )

      identity.identity = web3.utils.toBN(1)

      await verifyIdentity(identity.identity, instances.IdentityRegistry, {
        recoveryAddress:     identity.recoveryAddress.address,
        associatedAddresses: identity.associatedAddresses.map(address => address.address).slice(0, 1),
        providers:           [],
        resolvers:           []
      })
    })
  })

  describe('Testing Resolver', function () {
    it('resolver cannot be used when not set', async function () {
      await instances.Resolver.check({ from: identity.associatedAddresses[0].address })
        .then(() => assert.fail('key was added', 'transaction should fail'))
        .catch(error => assert.include(
          error.message, 'Check.', 'wrong rejection reason'
        ))
    })

    it('once added, email address can be set and read', async function () {
      await instances.IdentityRegistry.addResolvers(
        identity.resolvers,
        { from: identity.associatedAddresses[0].address }
      )

      const isResolverFor = await instances.IdentityRegistry.isResolverFor(identity.identity, instances.Resolver.address)
      assert.isTrue(isResolverFor, 'associated resolver was set incorrectly.')

      await instances.Resolver.check({ from: identity.associatedAddresses[0].address })
    })

    it('cannot access email addresses for non-existent EINs', async function () {
      await instances.Resolver.getEmail(100)
        .then(() => assert.fail('key was read', 'transaction should fail'))
        .catch(error => {
          if (error.message !== defaultErrorMessage) {
            assert.include(
              error.message, 'The referenced identity does not exist.', 'wrong rejection reason'
            )
          }
        })
    })
  })
})
