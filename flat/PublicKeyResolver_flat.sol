pragma solidity ^0.5.0;

/// @title Provides helper functions to determine the validity of passed signatures.
/// @author Noah Zinsmeister
/// @dev Supports both prefixed and un-prefixed signatures.
contract SignatureVerifier {
    /// @notice Determines whether the passed signature of `messageHash` was made by the private key of `_address`.
    /// @param _address The address that may or may not have signed the passed messageHash.
    /// @param messageHash The messageHash that may or may not have been signed.
    /// @param v The v component of the signature.
    /// @param r The r component of the signature.
    /// @param s The s component of the signature.
    /// @return true if the signature can be verified, false otherwise.
    function isSigned(address _address, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) public pure returns (bool) {
        return _isSigned(_address, messageHash, v, r, s) || _isSignedPrefixed(_address, messageHash, v, r, s);
    }

    /// @dev Checks unprefixed signatures.
    function _isSigned(address _address, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s)
        internal pure returns (bool)
    {
        return ecrecover(messageHash, v, r, s) == _address;
    }

    /// @dev Checks prefixed signatures.
    function _isSignedPrefixed(address _address, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s)
        internal pure returns (bool)
    {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        return _isSigned(_address, keccak256(abi.encodePacked(prefix, messageHash)), v, r, s);
    }
}

interface IdentityRegistryInterface {
    function isSigned(address _address, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s)
        external pure returns (bool);

    // Identity View Functions /////////////////////////////////////////////////////////////////////////////////////////
    function identityExists(uint ein) external view returns (bool);
    function hasIdentity(address _address) external view returns (bool);
    function getEIN(address _address) external view returns (uint ein);
    function isAssociatedAddressFor(uint ein, address _address) external view returns (bool);
    function isProviderFor(uint ein, address provider) external view returns (bool);
    function isResolverFor(uint ein, address resolver) external view returns (bool);
    function getIdentity(uint ein) external view returns (
        address recoveryAddress,
        address[] memory associatedAddresses, address[] memory providers, address[] memory resolvers
    );

    // Identity Management Functions ///////////////////////////////////////////////////////////////////////////////////
    function createIdentity(address recoveryAddress, address[] calldata providers, address[] calldata resolvers)
        external returns (uint ein);
    function createIdentityDelegated(
        address recoveryAddress, address associatedAddress, address[] calldata providers, address[] calldata resolvers,
        uint8 v, bytes32 r, bytes32 s, uint timestamp
    ) external returns (uint ein);
    function addAssociatedAddress(
        address approvingAddress, address addressToAdd, uint8 v, bytes32 r, bytes32 s, uint timestamp
    ) external;
    function addAssociatedAddressDelegated(
        address approvingAddress, address addressToAdd,
        uint8[2] calldata v, bytes32[2] calldata r, bytes32[2] calldata s, uint[2] calldata timestamp
    ) external;
    function removeAssociatedAddress() external;
    function removeAssociatedAddressDelegated(address addressToRemove, uint8 v, bytes32 r, bytes32 s, uint timestamp)
        external;
    function addProviders(address[] calldata providers) external;
    function addProvidersFor(uint ein, address[] calldata providers) external;
    function removeProviders(address[] calldata providers) external;
    function removeProvidersFor(uint ein, address[] calldata providers) external;
    function addResolvers(address[] calldata resolvers) external;
    function addResolversFor(uint ein, address[] calldata resolvers) external;
    function removeResolvers(address[] calldata resolvers) external;
    function removeResolversFor(uint ein, address[] calldata resolvers) external;

    // Recovery Management Functions ///////////////////////////////////////////////////////////////////////////////////
    function triggerRecoveryAddressChange(address newRecoveryAddress) external;
    function triggerRecoveryAddressChangeFor(uint ein, address newRecoveryAddress) external;
    function triggerRecovery(uint ein, address newAssociatedAddress, uint8 v, bytes32 r, bytes32 s, uint timestamp)
        external;
    function triggerDestruction(
        uint ein, address[] calldata firstChunk, address[] calldata lastChunk, bool resetResolvers
    ) external;
}

contract PublicKeyResolver is SignatureVerifier {

    string public constant NAME = "PublicKeyResolver";

    IdentityRegistryInterface identityRegistry;

    mapping(address => bytes) internal addrToPubKey;

    // Signature Timeout ///////////////////////////////////////////////////////////////////////////////////////////////

    uint public signatureTimeout = 1 days;

    /// @dev Enforces that the passed timestamp is within signatureTimeout seconds of now.
    /// @param timestamp The timestamp to check the validity of.
    modifier ensureSignatureTimeValid(uint timestamp) {
        require(
            // solium-disable-next-line security/no-block-members
            block.timestamp >= timestamp && block.timestamp < timestamp + signatureTimeout, "Timestamp is not valid."
        );
        _;
    }

    event PublicKeyAdded(address indexed addr, uint indexed ein, bytes publicKey, bool delegated);
    event PublicKeyRemoved(address indexed addr, uint indexed ein, bool delegated);

    constructor (address identityRegistryAddress) public {
        identityRegistry = IdentityRegistryInterface(identityRegistryAddress);
    }

    modifier isResolverFor(uint ein) {
        require(identityRegistry.isResolverFor(ein, address(this)), "The calling identity does not have this resolver set.");
        _;
    }

    modifier identityExists(uint ein) {
        require(identityRegistry.identityExists(ein), "The referenced identity does not exist.");
        _;
    }

    modifier isValidPublicKey(address addr, bytes memory publicKey) {
        require(calculateAddress(publicKey) == addr, "The address is not the same as that converted from the public key.");
        _;
    }
    /// @notice calculate Address from public key
    /// @param publicKey A public Key
    function calculateAddress(bytes memory publicKey) public pure returns (address addr) {
        bytes32 hash = keccak256(publicKey);
        assembly {
            mstore(0, hash)
            addr := mload(0)
        }
    }

    /// @notice Allows adding a public key
    /// @param associatedAddress An associated address to add public key for the Identity (must have produced the signature).
    /// @param publicKey A publicKey.
    /// @param v The v component of the signature.
    /// @param r The r component of the signature.
    /// @param s The s component of the signature.
    /// @param timestamp The timestamp of the signature.
    function addPublicKeyDelegated(
        address associatedAddress, bytes calldata publicKey,
        uint8 v, bytes32 r, bytes32 s, uint timestamp
    )
        external ensureSignatureTimeValid(timestamp)
    {
        uint ein = identityRegistry.getEIN(associatedAddress);
        require(identityRegistry.isProviderFor(ein, msg.sender), "Only provider can be delegated.");
        require(
            isSigned(
                associatedAddress,
                keccak256(
                    abi.encodePacked(
                        byte(0x19), byte(0), address(this),
                        "I authorize the addition of a public key on my behalf.",
                        associatedAddress, publicKey, timestamp
                    )
                ),
                v, r, s
            ),
            "Permission denied."
        );

        _addPublicKey(ein, associatedAddress, publicKey, true);
    }

    function addPublicKey(bytes calldata publicKey) external {
        _addPublicKey(identityRegistry.getEIN(msg.sender), msg.sender, publicKey,false);
    }

    function _addPublicKey(
        uint ein, address associatedAddress, bytes memory publicKey, bool delegated
    )
        private isResolverFor(ein) isValidPublicKey(associatedAddress,publicKey)
    {
        require(addrToPubKey[associatedAddress].length == 0, "Key was already added by someone.");

        //keyToEin[key] = ein;
        addrToPubKey[associatedAddress] = publicKey;
        //einToKeys[ein].insert(key);
        emit PublicKeyAdded(associatedAddress, ein, publicKey, delegated);
    }

    /// @notice Allows removing a public key
    /// @param associatedAddress An associated address to remove public key for the new Identity (must have produced the signature).
    /// @param v The v component of the signature.
    /// @param r The r component of the signature.
    /// @param s The s component of the signature.
    /// @param timestamp The timestamp of the signature.
    function removePublicKeyDelegated(
        address associatedAddress,
        uint8 v, bytes32 r, bytes32 s, uint timestamp
    )
        external ensureSignatureTimeValid(timestamp)
    {
        uint ein = identityRegistry.getEIN(associatedAddress);
        require(identityRegistry.isProviderFor(ein, msg.sender), "Only provider can be delegated.");
        require(
            isSigned(
                associatedAddress,
                keccak256(
                    abi.encodePacked(
                        byte(0x19), byte(0), address(this),
                        "I authorize the removal of a public key on my behalf.",
                        associatedAddress, timestamp
                    )
                ),
                v, r, s
            ),
            "Permission denied."
        );

        _removePublicKey(ein, associatedAddress,true);
    }

    function removePublicKey() external {
        _removePublicKey(identityRegistry.getEIN(msg.sender), msg.sender, false);
    }

    function _removePublicKey(uint ein, address associatedAddress, bool delegated) private isResolverFor(ein) {
        delete addrToPubKey[associatedAddress];
        emit PublicKeyRemoved(associatedAddress, ein, delegated);
    }

    function getPublicKey(address addr) public view returns(bytes memory) {
        return addrToPubKey[addr];
    }
}
