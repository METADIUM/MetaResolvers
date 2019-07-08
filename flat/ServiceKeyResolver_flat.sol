pragma solidity ^0.5.0;

/// @title An implementation of the set data structure for addresses.
/// @author Noah Zinsmeister
/// @dev O(1) insertion, removal, contains, and length functions.
library AddressSet {
    struct Set {
        address[] members;
        mapping(address => uint) memberIndices;
    }

    /// @dev Inserts an element into a set. If the element already exists in the set, the function is a no-op.
    /// @param self The set to insert into.
    /// @param other The element to insert.
    function insert(Set storage self, address other) internal {
        if (!contains(self, other)) {
            self.memberIndices[other] = self.members.push(other);
        }
    }

    /// @dev Removes an element from a set. If the element does not exist in the set, the function is a no-op.
    /// @param self The set to remove from.
    /// @param other The element to remove.
    function remove(Set storage self, address other) internal {
        if (contains(self, other)) {
            // replace other with the last element
            self.members[self.memberIndices[other] - 1] = self.members[length(self) - 1];
            // reflect this change in the indices
            self.memberIndices[self.members[self.memberIndices[other] - 1]] = self.memberIndices[other];
            delete self.memberIndices[other];
            // remove the last element
            self.members.pop();
        }
    }

    /// @dev Checks set membership.
    /// @param self The set to check membership in.
    /// @param other The element to check membership of.
    /// @return true if the element is in the set, false otherwise.
    function contains(Set storage self, address other) internal view returns (bool) {
        return ( // solium-disable-line operator-whitespace
            self.memberIndices[other] > 0 && 
            self.members.length >= self.memberIndices[other] && 
            self.members[self.memberIndices[other] - 1] == other
        );
    }

    /// @dev Returns the number of elements in a set.
    /// @param self The set to check the length of.
    /// @return The number of elements in the set.
    function length(Set storage self) internal view returns (uint) {
        return self.members.length;
    }
}

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

contract ServiceKeyResolver is SignatureVerifier {
    using AddressSet for AddressSet.Set;

    string public constant NAME = "ServiceKeyResolver";

    IdentityRegistryInterface identityRegistry;

    mapping(uint => AddressSet.Set) internal einToKeys;
    mapping(address => uint) internal keyToEin;
    mapping(address => string) internal keyToSymbol;

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

    event KeyAdded(address indexed key, uint indexed ein, string symbol);
    event KeyRemoved(address indexed key, uint indexed ein);

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

    /// @notice Allows adding a service key
    /// @param associatedAddress An associated address to add service key for the Identity (must have produced the signature).
    /// @param key A service key to add.
    /// @param symbol A service symbol.
    /// @param v The v component of the signature.
    /// @param r The r component of the signature.
    /// @param s The s component of the signature.
    /// @param timestamp The timestamp of the signature.
    function addKeyDelegated(
        address associatedAddress, address key, string calldata symbol,
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
                        "I authorize the addition of a service key on my behalf.",
                        key, symbol, timestamp
                    )
                ),
                v, r, s
            ),
            "Permission denied."
        );

        _addKey(ein, key, symbol);
    }

    function addKey(address key, string calldata symbol) external {
        _addKey(identityRegistry.getEIN(msg.sender), key, symbol);
    }

    function _addKey(uint ein, address key, string memory symbol) private isResolverFor(ein) {
        require(keyToEin[key] == 0, "Key was already added by someone.");
        keyToEin[key] = ein;
        keyToSymbol[key] = symbol;
        einToKeys[ein].insert(key);
        emit KeyAdded(key, ein, symbol);
    }

    /// @notice Allows removing a service key
    /// @param associatedAddress An associated address to remove service key for the new Identity (must have produced the signature).
    /// @param key A service key to remove.
    /// @param v The v component of the signature.
    /// @param r The r component of the signature.
    /// @param s The s component of the signature.
    /// @param timestamp The timestamp of the signature.
    function removeKeyDelegated(
        address associatedAddress, address key,
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
                        "I authorize the removal of a service key on my behalf.",
                        key, timestamp
                    )
                ),
                v, r, s
            ),
            "Permission denied."
        );

        _removeKey(ein, key);
    }

    function removeKey(address key) external {
        _removeKey(identityRegistry.getEIN(msg.sender), key);
    }

    /// @notice Allows removing all service keys
    /// @param associatedAddress An associated address to remove service key for the new Identity (must have produced the signature).
    /// @param v The v component of the signature.
    /// @param r The r component of the signature.
    /// @param s The s component of the signature.
    /// @param timestamp The timestamp of the signature.
    function removeKeysDelegated(
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
                        "I authorize the removal of all service keys on my behalf.",
                        timestamp
                    )
                ),
                v, r, s
            ),
            "Permission denied."
        );

        _removeKeys(ein);
    }

    function removeKeys() external {
        _removeKeys(identityRegistry.getEIN(msg.sender));
    }

    function _removeKeys(uint ein) private {
        AddressSet.Set storage keys = einToKeys[ein];
        for (uint i = 0; i < keys.length(); ++i) {
            keyToEin[keys.members[i]] = 0;
            emit KeyRemoved(keys.members[i], ein);
        }
        delete keys.members;
    }

    function _removeKey(uint ein, address key) private isResolverFor(ein) {
        keyToEin[key] = 0;
        einToKeys[ein].remove(key);
        emit KeyRemoved(key, ein);
    }

    function isKeyFor(address key, uint ein) public view identityExists(ein) returns(bool) {
        return keyToEin[key] == ein;
    }

    function getSymbol(address key) public view returns(string memory) {
        return keyToSymbol[key];
    }

    function getKeys(uint ein) public view identityExists(ein) returns(address[] memory) {
        AddressSet.Set storage keys = einToKeys[ein];
        return keys.members;
    }
}
