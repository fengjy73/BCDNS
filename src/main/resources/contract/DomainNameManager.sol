pragma solidity ^0.4.26;

import "./utils/Ownable.sol";

contract DomainNameManager is Ownable {
    struct CertInfo {
        bytes cert;
        string domainName;
        bool status;
    }

    mapping(string => CertInfo) private idToCertMap;

    mapping(string => CertInfo) private nameToCertMap;

    event addDomainNameCert(string vcId, string domainName, bytes certificate);

    event revokeDomainNameCert(string vcId, string domainName);

    function addCertificate(string memory vcId, string memory domainName, bytes memory certificate) public onlyOwner {
        require(
            idToCertMap[vcId].cert.length == 0 &&
            nameToCertMap[domainName].status == false,
            "certificate has been registered"
        );

        CertInfo memory cert;
        cert.cert = certificate;
        cert.domainName = domainName;
        cert.status = true;
        idToCertMap[vcId] = cert;
        nameToCertMap[domainName] = cert;
        emit addDomainNameCert(vcId, domainName, certificate);
    }

    function revokeCertificate(string memory vcId) public onlyOwner {
        require(
            idToCertMap[vcId].status,
            "certificate has been revoked"
        );

        string memory domainName = idToCertMap[vcId].domainName;
        idToCertMap[vcId].status = false;
        nameToCertMap[domainName].status = false;
        emit revokeDomainNameCert(vcId, domainName);
    }

    function getCertById(string memory vcId) public view returns (bytes) {
        return idToCertMap[vcId].cert;
    }

    function getCertStatusById(string memory vcId) public view returns (bool) {
        return idToCertMap[vcId].status;
    }

    function getCertByName(string memory domainName) public view returns (bytes) {
        return nameToCertMap[domainName].cert;
    }

    function getCertStatusByName(string memory domainName) public view returns (bool) {
        return nameToCertMap[domainName].status;
    }
}