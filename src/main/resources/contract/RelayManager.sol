pragma solidity ^0.4.26;

import "./utils/Ownable.sol";

contract RelayManager is Ownable {
    struct CertInfo {
        bytes cert;
        address relay;
        bool status;
    }

    struct RelayInfo {
        string vcId;
        bytes netAddress;
    }

    mapping(address => bool) private relayMap;

    mapping(string => CertInfo) private idToCertMap;

    mapping(string => RelayInfo) private domainNameToRelayMap;

    mapping(string => bytes) private domainNameToTPBTAMap;

    event addRelayCert(string vcId, bytes certificate);
    event revokeRelayCert(string vcId);
    event bindDomainNameWithRelay(string domainName, string relayVcId, bytes netAddress);
    event bindDomainNameWithTPBTA(string domainName, bytes tbbta);

    modifier onlyRelay() {
        require(relayMap[msg.sender], "caller is not the relay");
        _;
    }

    function addCertificate(string memory vcId, bytes memory certificate, address relay) public onlyOwner {
        require(
            idToCertMap[vcId].cert.length == 0,
            "certificate has been registered"
        );

        CertInfo memory cert;
        cert.cert = certificate;
        cert.relay = relay;
        cert.status = true;
        idToCertMap[vcId] = cert;
        relayMap[relay] = true;
        emit addRelayCert(vcId, certificate);
    }

    function revokeCertificate(string memory vcId) public onlyOwner {
        require(
            idToCertMap[vcId].status,
            "certificate has been revoked"
        );

        idToCertMap[vcId].status = false;
        relayMap[idToCertMap[vcId].relay] = false;
        emit revokeRelayCert(vcId);
    }

    function bindingDomainNameWithRelay(string memory domainName, string memory relayVcId, bytes memory netAddress) public onlyRelay {
        require(
            idToCertMap[relayVcId].status,
            "relay has not been registered"
        );

        RelayInfo memory relayInfo;
        relayInfo.vcId = relayVcId;
        relayInfo.netAddress = netAddress;
        domainNameToRelayMap[domainName] = relayInfo;
        emit bindDomainNameWithRelay(domainName, relayVcId, netAddress);
    }

    function bindingDomainNameWithTPBTA(string memory domainName, bytes memory tpbta) public onlyRelay {
        domainNameToTPBTAMap[domainName] = tpbta;
        emit bindDomainNameWithTPBTA(domainName, tpbta);
    }

    function getCertById(string memory vcId) public view returns (bytes memory) {
        return idToCertMap[vcId].cert;
    }

    function getCertStatusById(string memory vcId) public view returns (bool) {
        return idToCertMap[vcId].status;
    }

    function getRelayByDomainName(string memory domainName) public view returns (bytes memory, bytes memory) {
        return (idToCertMap[domainNameToRelayMap[domainName].vcId].cert, domainNameToRelayMap[domainName].netAddress);
    }

    function getTPBTAByDomainName(string memory domainName) public view returns (bytes memory) {
        return domainNameToTPBTAMap[domainName];
    }


    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}