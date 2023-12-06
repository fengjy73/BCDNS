pragma solidity ^0.4.26;

import "./utils/Ownable.sol";

contract PTCManager is Ownable {
    struct CertInfo {
        bytes cert;
        bool status;
    }

    mapping(string => CertInfo) private idToCertMap;

    event addManagerCert(string vcId, bytes certificate);
    event revokeManagerCert(string vcId);

    function addCertificate(string memory vcId, bytes memory certificate) public onlyOwner {
        require(
            idToCertMap[vcId].cert.length == 0,
            "certificate has been registered"
        );
        CertInfo memory cert;
        cert.cert = certificate;
        cert.status = true;
        idToCertMap[vcId] = cert;
        emit addManagerCert(vcId, certificate);
    }

    function revokeCertificate(string memory vcId) public onlyOwner {
        require(
            idToCertMap[vcId].status,
            "certificate has been revoked"
        );

        idToCertMap[vcId].status = false;
        emit revokeManagerCert(vcId);
    }

    function getCertById(string memory vcId) public view returns (bytes memory) {
        return idToCertMap[vcId].cert;
    }

    function getCertStatusById(string memory vcId) public view returns (bool) {
        return idToCertMap[vcId].status;
    }


    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}