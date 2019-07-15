var _ = require('underscore')
const ethUtil = require('ethereumjs-util')

const { sign, verifyIdentity, defaultErrorMessage } = require('../../common')

const IdentityRegistry = artifacts.require('./IdentityRegistry.sol')
const PublicKeyResolver = artifacts.require('./examples/Resolvers/PublicKey/PublicKeyResolver.sol')

const privateKeys = [
  '0x2665671af93f210ddb5d5ffa16c77fcf961d52796f2b2d7afd32cc5d886350a8',
  '0x6bf410ff825d07346c110c5836b33ec76e7d1ee051283937392180b732aa3aff',
  '0xccc3c84f02b038a5d60d93977ab11eb57005f368b5f62dad29486edeb4566954',
  '0xfdf12368f9e0735dc01da9db58b1387236120359024024a31e611e82c8853d7f',
  '0x44e02845db8861094c519d72d08acb7435c37c57e64ec5860fb15c5f626cb77c',
  '0x12093c3cd8e0c6ceb7b1b397724cd82c4d84f81263f56a44f11d8bd3a61ffccb',
  '0xf65450adda73b32e056ed24246d8d370e49fc88b427f96f37bbf23f6b132b93b',
  '0x34a1f9ed996709f629d712d5b267d23f37be82bf8003a023264f71005f6486e6',
  '0x1711e5c516428d875c14dac234f36bbf3b4622aeac00566483a8087ed5a97297',
  '0xce5e2ea9c47caba88b3421d75023bd8c359e2aaf897e519a10a256d931028ca1'
]

// convenience variables
const instances = {}
let accountsPrivate
let identity

function privateToPublic( privateKey){
  const pubKeyBuffer = ethUtil.privateToPublic(privateKey)
  const pubKeyHex = ethUtil.bufferToHex(pubKeyBuffer)
  return pubKeyHex;
}

contract('Testing Public Key Resolver', function (accounts) {
  accountsPrivate = accounts.map((account, i) => { return { address: account, private: privateKeys[i], public:privateToPublic(privateKeys[i]) } })

  identity = {
    recoveryAddress:     accountsPrivate[0],
    associatedAddresses: accountsPrivate.slice(1, 3),
    providers:           accountsPrivate.slice(3, 4)
  }

  services = {
    p: accountsPrivate.slice(4, 6),
    names: ['sp1', 'sp2']
  }

  describe('Deploying Contracts', function () {
    it('IdentityRegistry contract deployed', async function () {
      instances.IdentityRegistry = await IdentityRegistry.new()
    })

    it('Resolver contract deployed', async function () {
      instances.Resolver = await PublicKeyResolver.new(instances.IdentityRegistry.address)
      identity.resolvers = [instances.Resolver.address]
    })

    it('Identity can be created', async function () {
      await instances.IdentityRegistry.createIdentity(
        identity.recoveryAddress.address, [identity.providers[0].address], [],
        { from: identity.associatedAddresses[0].address }
      )

      identity.identity = web3.utils.toBN(1)

      await verifyIdentity(identity.identity, instances.IdentityRegistry, {
        recoveryAddress:     identity.recoveryAddress.address,
        associatedAddresses: identity.associatedAddresses.map(address => address.address).slice(0, 1),
        providers:           identity.providers.map(address => address.address).slice(0, 1),
        resolvers:           []
      })

      await instances.IdentityRegistry.createIdentity(
        identity.recoveryAddress.address, [identity.providers[0].address], [],
        { from: identity.associatedAddresses[1].address }
      )

      await instances.IdentityRegistry.addResolvers(
        identity.resolvers,
        { from: identity.associatedAddresses[1].address }
      )



    })
  })

  describe('Testing Public Resolver', function () {
    it('resolver cannot be used before set', async function () {
      
      await instances.Resolver.addPublicKey( identity.associatedAddresses[0].public, { from: identity.associatedAddresses[0].address })
        .then(() => assert.fail('service key was added', 'transaction should fail'))
        .catch(error => assert.include(
          error.message, 'The calling identity does not have this resolver set.', 'wrong rejection reason'
        ))
    })

    it('once added, Public key can be set and read', async function () {
      await instances.IdentityRegistry.addResolvers(
        identity.resolvers,
        { from: identity.associatedAddresses[0].address }
      )

      const isResolverFor = await instances.IdentityRegistry.isResolverFor(identity.identity, instances.Resolver.address)
      assert.isTrue(isResolverFor, 'associated resolver was set incorrectly.')

      await instances.Resolver.addPublicKey( identity.associatedAddresses[0].public, { from: identity.associatedAddresses[0].address })

      const pubKey = await instances.Resolver.getPublicKey(identity.associatedAddresses[0].address)
      assert.equal(pubKey, identity.associatedAddresses[0].public, 'public key was set incorrectly.')
    })

    it('once added, same public key cannot be added again. even with other EIN', async function () {
      await instances.Resolver.addPublicKey(identity.associatedAddresses[0].public, { from: identity.associatedAddresses[0].address })
        .then(() => assert.fail('service key was added', 'transaction should fail'))
        .catch(error => assert.include(
          error.message, 'Key was already added by someone.', 'wrong rejection reason'
        ))
    })
/*
    it('cannot access public key for non-existent EINs', async function () {
      await instances.Resolver.isKeyFor(services.p[0].address, 100)
        .then(() => assert.fail('key was read', 'transaction should fail'))
        .catch(error => {
          if (error.message !== defaultErrorMessage) {
            assert.include(
              error.message, 'The referenced identity does not exist.', 'wrong rejection reason'
            )
          }
        })
    })
*/
    it('once added, public key can be removed', async function () {
      await instances.Resolver.removePublicKey( { from: identity.associatedAddresses[0].address })

      const pubKey = await instances.Resolver.getPublicKey(identity.associatedAddresses[0].address)

      assert.isTrue((pubKey == null), 'public key was removed incorrectly.')
    })

    it('public key can be added by delegator FAIL -- provider', async function () {
      const timestamp = Math.round(new Date() / 1000) - 1
      const permissionString = web3.utils.soliditySha3(
        '0x19', '0x00', instances.Resolver.address,
        'I authorize the addition of a public key on my behalf.',
        identity.associatedAddresses[1].address,
        identity.associatedAddresses[1].public,
        timestamp
      )
      const permission = await sign(
        permissionString, identity.associatedAddresses[1].address, identity.associatedAddresses[1].private
      )
      await instances.Resolver.addPublicKeyDelegated(
        identity.associatedAddresses[1].address,   identity.associatedAddresses[1].public,
        permission.v, permission.r, permission.s, timestamp,
        { from: services.p[1].address }
      )
        .then(() => assert.fail('able to add', 'transaction should fail'))
        .catch(error => {
          if (error.message !== defaultErrorMessage) {
            assert.include(
              error.message, 'Only provider can be delegated.', 'wrong rejection reason'
            )
          }
        })
    })

    it('public key can be added by delegator FAIL -- timestamp', async function () {
      const timestamp = Math.round(new Date() / 1000) + 1000
      const permissionString = web3.utils.soliditySha3(
        '0x19', '0x00', instances.Resolver.address,
        'I authorize the addition of a public key on my behalf.',
        identity.associatedAddresses[1].address,
        identity.associatedAddresses[1].public,
        timestamp
      )
      const permission = await sign(
        permissionString, identity.associatedAddresses[1].address, identity.associatedAddresses[1].private
      )

      await instances.Resolver.addPublicKeyDelegated(
        identity.associatedAddresses[1].address, identity.associatedAddresses[1].public,
        permission.v, permission.r, permission.s, timestamp,
        { from: identity.providers[0].address }
      )
        .then(() => assert.fail('able to add', 'transaction should fail'))
        .catch(error => {
          if (error.message !== defaultErrorMessage) {
            assert.include(
              error.message, 'Timestamp is not valid.', 'wrong rejection reason'
            )
          }
        })
    })

    it('public key can be added by delegator FAIL -- signature', async function () {
      const timestamp = Math.round(new Date() / 1000) - 1
      const permissionString = web3.utils.soliditySha3(
        '0x18', '0x00', instances.Resolver.address,
        'Wrong message.',
        identity.associatedAddresses[1].address,
        identity.associatedAddresses[1].public,
        timestamp
      )
      const permission = await sign(
        permissionString, identity.associatedAddresses[1].address, identity.associatedAddresses[1].private
      )
      await instances.Resolver.addPublicKeyDelegated(
        identity.associatedAddresses[1].address, identity.associatedAddresses[1].public,
        permission.v, permission.r, permission.s, timestamp,
        { from: identity.providers[0].address }
      )
        .then(() => assert.fail('able to add', 'transaction should fail'))
        .catch(error => {
          if (error.message !== defaultErrorMessage) {
            assert.include(
              error.message, 'Permission denied.', 'wrong rejection reason'
            )
          }
        })
    })

    it('public key can be added by delegator', async function () {
      const timestamp = Math.round(new Date() / 1000) - 1
      const permissionString = web3.utils.soliditySha3(
        '0x19', '0x00', instances.Resolver.address,
        'I authorize the addition of a public key on my behalf.',
        identity.associatedAddresses[1].address,
        identity.associatedAddresses[1].public,
        timestamp
      )
      const permission = await sign(
        permissionString, identity.associatedAddresses[1].address, identity.associatedAddresses[1].private
      )
      await instances.Resolver.addPublicKeyDelegated(
        identity.associatedAddresses[1].address, identity.associatedAddresses[1].public,
        permission.v, permission.r, permission.s, timestamp,
        { from: identity.providers[0].address }
      )
      const pubKey = await instances.Resolver.getPublicKey(identity.associatedAddresses[1].address)
      assert.equal(pubKey, identity.associatedAddresses[1].public, 'public key was set incorrectly.')
    })

    it('public key can be removed by delegator FAIL -- provider', async function () {
      const timestamp = Math.round(new Date() / 1000) - 1
      const permissionString = web3.utils.soliditySha3(
        '0x19', '0x00', instances.Resolver.address,
        'I authorize the removal of a pubic key on my behalf.',
        identity.associatedAddresses[1].address,
        timestamp
      )
      const permission = await sign(
        permissionString, identity.associatedAddresses[1].address, identity.associatedAddresses[1].private
      )
      await instances.Resolver.removePublicKeyDelegated(
        identity.associatedAddresses[1].address,
        permission.v, permission.r, permission.s, timestamp,
        { from: services.p[1].address }
      )
        .then(() => assert.fail('able to remove', 'transaction should fail'))
        .catch(error => {
          if (error.message !== defaultErrorMessage) {
            assert.include(
              error.message, 'Only provider can be delegated.', 'wrong rejection reason'
            )
          }
        })
    })

    it('public key can be removed by delegator FAIL -- timestamp', async function () {
      const timestamp = Math.round(new Date() / 1000) - (25*60*60) // 25 hours ago
      const permissionString = web3.utils.soliditySha3(
        '0x19', '0x00', instances.Resolver.address,
        'I authorize the removal of a public key on my behalf.',
        identity.associatedAddresses[1].address,
        timestamp
      )
      const permission = await sign(
        permissionString, identity.associatedAddresses[1].address, identity.associatedAddresses[1].private
      )
      await instances.Resolver.removePublicKeyDelegated(
        identity.associatedAddresses[1].address,
        permission.v, permission.r, permission.s, timestamp,
        { from: identity.providers[0].address }
      )
        .then(() => assert.fail('able to remove', 'transaction should fail'))
        .catch(error => {
          if (error.message !== defaultErrorMessage) {
            assert.include(
              error.message, 'Timestamp is not valid.', 'wrong rejection reason'
            )
          }
        })
    })

    it('public key can be removed by delegator FAIL -- signature', async function () {
      const timestamp = Math.round(new Date() / 1000) - 1
      const permissionString = web3.utils.soliditySha3(
        '0x19', '0x00', instances.Resolver.address,
        'I authorize the removal of a public key on my behalf.',
        identity.associatedAddresses[1].address,
        timestamp
      )
      const permission = await sign(
        permissionString, services.p[1].address, services.p[1].private
      )
      await instances.Resolver.removePublicKeyDelegated(
        identity.associatedAddresses[1].address,
        permission.v, permission.r, permission.s, timestamp,
        { from: identity.providers[0].address }
      )
        .then(() => assert.fail('able to remove', 'transaction should fail'))
        .catch(error => {
          if (error.message !== defaultErrorMessage) {
            assert.include(
              error.message, 'Permission denied.', 'wrong rejection reason'
            )
          }
        })
    })

    it('public key can be removed by delegator', async function () {
      const timestamp = Math.round(new Date() / 1000) - 1
      const permissionString = web3.utils.soliditySha3(
        '0x19', '0x00', instances.Resolver.address,
        'I authorize the removal of a public key on my behalf.',
        identity.associatedAddresses[1].address,
        timestamp
      )
      const permission = await sign(
        permissionString, identity.associatedAddresses[1].address, identity.associatedAddresses[1].private
      )
      await instances.Resolver.removePublicKeyDelegated(
        identity.associatedAddresses[1].address,
        permission.v, permission.r, permission.s, timestamp,
        { from: identity.providers[0].address }
      )

      const pubKey = await instances.Resolver.getPublicKey(identity.associatedAddresses[1].address)
      assert.isTrue((pubKey == null), 'public key was removed incorrectly.')
    })
  })
})
