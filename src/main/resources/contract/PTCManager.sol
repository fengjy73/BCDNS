// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

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
}