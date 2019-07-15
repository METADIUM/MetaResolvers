pragma solidity ^0.5.0;

import "../../../SignatureVerifier.sol";
import "../../../interfaces/IdentityRegistryInterface.sol";

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
