pragma solidity ^0.5.0;

import "../../../interfaces/IdentityRegistryInterface.sol";

contract ServiceKeyResolver {
    IdentityRegistryInterface identityRegistry;

    mapping(address => uint) internal keyToEin;
    mapping(address => string) internal keyToSymbol;

    constructor (address identityRegistryAddress) public {
        identityRegistry = IdentityRegistryInterface(identityRegistryAddress);
    }

    modifier isResolverFor(uint ein, address addr) {
        require(identityRegistry.isResolverFor(ein, addr), "The calling identity does not have this resolver set.");
        _;
    }

    function addKey(address key, string memory symbol)
        public
        isResolverFor(identityRegistry.getEIN(msg.sender), address(this))
    {
        keyToEin[key] = identityRegistry.getEIN(msg.sender);
        keyToSymbol[key] = symbol;
    }

    function isKeyFor(address key, uint ein) public view returns(bool) {
        require(identityRegistry.identityExists(ein), "The referenced identity does not exist.");
        return keyToEin[key] == ein;
    }

    function getSymbol(address key) public view returns(string memory) {
        return keyToSymbol[key];
    }
}
