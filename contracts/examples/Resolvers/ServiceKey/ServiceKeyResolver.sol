pragma solidity ^0.5.0;

import "../../../interfaces/IdentityRegistryInterface.sol";

contract ServiceKeyResolver {
    IdentityRegistryInterface identityRegistry;

    mapping(address => uint) internal keyToEin;
    mapping(address => string) internal keyToSymbol;

    event KeyAdded(address indexed key, uint indexed ein, string symbol);
    event KeyRemoved(address indexed key, uint indexed ein);

    constructor (address identityRegistryAddress) public {
        identityRegistry = IdentityRegistryInterface(identityRegistryAddress);
    }

    modifier isResolverFor(uint ein) {
        require(identityRegistry.isResolverFor(ein, address(this)), "The calling identity does not have this resolver set.");
        _;
    }

    function addKey(address key, string calldata symbol)
        external
        isResolverFor(identityRegistry.getEIN(msg.sender))
    {
        uint ein = identityRegistry.getEIN(msg.sender);
        keyToEin[key] = ein;
        keyToSymbol[key] = symbol;

        emit KeyAdded(key, ein, symbol);
    }

    function removeKey(address key)
        external
        isResolverFor(identityRegistry.getEIN(msg.sender))
    {
        keyToEin[key] = 0;

        emit KeyRemoved(key, identityRegistry.getEIN(msg.sender));
    }

    function isKeyFor(address key, uint ein) public view returns(bool) {
        require(identityRegistry.identityExists(ein), "The referenced identity does not exist.");
        return keyToEin[key] == ein;
    }

    function getSymbol(address key) public view returns(string memory) {
        return keyToSymbol[key];
    }
}
