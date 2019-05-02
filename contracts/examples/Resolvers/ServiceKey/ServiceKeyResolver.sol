pragma solidity ^0.5.0;

import "../../../SignatureVerifier.sol";
import "../../../interfaces/IdentityRegistryInterface.sol";

contract ServiceKeyResolver is SignatureVerifier {
    IdentityRegistryInterface identityRegistry;

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

    /// @notice Allows adding a service key
    /// @param associatedAddress An associated address to set for the new Identity (must have produced the signature).
    /// @param key A service key to set.
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

        _addKey(identityRegistry.getEIN(associatedAddress), key, symbol);
    }

    function addKey(address key, string calldata symbol) external {
        _addKey(identityRegistry.getEIN(msg.sender), key, symbol);
    }

    function _addKey(uint ein, address key, string memory symbol)
        private isResolverFor(ein)
    {
        keyToEin[key] = ein;
        keyToSymbol[key] = symbol;

        // emit KeyAdded(key, ein, symbol);
    }

    function removeKey(address key)
        external
        isResolverFor(identityRegistry.getEIN(msg.sender))
    {
        keyToEin[key] = 0;

        // emit KeyRemoved(key, identityRegistry.getEIN(msg.sender));
    }

    function isKeyFor(address key, uint ein) public view returns(bool) {
        require(identityRegistry.identityExists(ein), "The referenced identity does not exist.");
        return keyToEin[key] == ein;
    }

    function getSymbol(address key) public view returns(string memory) {
        return keyToSymbol[key];
    }
}
