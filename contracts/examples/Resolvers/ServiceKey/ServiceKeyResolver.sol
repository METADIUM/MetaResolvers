pragma solidity ^0.5.0;

import "../../../AddressSet/AddressSet.sol";
import "../../../SignatureVerifier.sol";
import "../../../interfaces/IdentityRegistryInterface.sol";

contract ServiceKeyResolver is SignatureVerifier {
    using AddressSet for AddressSet.Set;

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
        keyToEin[key] = ein;
        keyToSymbol[key] = symbol;
        einToKeys[ein].insert(key);

        // emit KeyAdded(key, ein, symbol);
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

    function removeKeys() external {
        uint ein = identityRegistry.getEIN(msg.sender);
        AddressSet.Set storage keys = einToKeys[ein];
        for (uint i = 0; i < keys.length(); ++i) {
            keyToEin[keys.members[i]] = 0;
        }
        delete keys.members;
    }

    function _removeKey(uint ein, address key) private isResolverFor(ein) {
        keyToEin[key] = 0;
        einToKeys[ein].remove(key);

        // emit KeyRemoved(key, ein);
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
