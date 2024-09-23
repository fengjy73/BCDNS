// SPDX-License-Identifier: MIT
pragma solidity ^0.4.26;

import "./utils/Ownable.sol";

contract PTCTrustRootManager is Ownable {
    struct PTCTrustRootInfo {
        bytes ptcTrustRoot;
        bool status;
    }

    mapping(string => PTCTrustRootInfo) private idToPTCTrustRoot; // <ObjectIdentity, PTCTrustRoot>

    event addPTCTrustRoot(string ptcId, bytes ptcTrustRoot);
    event revokePTCTrustRoot(string ptcId);
    event upgradePTCTrustRoot(string ptcId, bytes newPTCTrustRoot);

    function addPTCTR(string memory ptcId, bytes memory ptcTrustRoot) public onlyOwner {
        require(
            idToPTCTrustRoot[ptcId].ptcTrustRoot.length == 0,
            "ptcTrustRoot has been registered"
        );

        PTCTrustRootInfo memory ptctr;
        ptctr.ptcTrustRoot = ptcTrustRoot;
        ptctr.status = true;
        idToPTCTrustRoot[ptcId] = ptctr;

        emit addPTCTrustRoot(ptcId, ptcTrustRoot);
    }

    function revokePTCTR(string memory ptcId) public onlyOwner {
        require(
            idToPTCTrustRoot[ptcId].status,
            "PTCTrustRoot has been revoked"
        );

        idToPTCTrustRoot[ptcId].status = false;
        emit revokePTCTrustRoot(ptcId);
    }

    function upgradePTCTR(string memory ptcId, bytes memory newPTCTrustRoot) public onlyOwner {
        require(
            idToPTCTrustRoot[ptcId].ptcTrustRoot.length != 0,
            "ptcTrustRoot has not been registered"
        );

        require(
            idToPTCTrustRoot[ptcId].status,
            "PTCTrustRoot has been revoked"
        );

        idToPTCTrustRoot[ptcId].ptcTrustRoot = newPTCTrustRoot;
        emit upgradePTCTrustRoot(ptcId, newPTCTrustRoot);
    }

    function getPTCTrustRootById(string memory ptcId) public view returns (bytes memory) {
        return idToPTCTrustRoot[ptcId].ptcTrustRoot;
    }

    function getPTCTrustRootStatusById(string memory ptcId) public view returns (bool) {
        return idToPTCTrustRoot[ptcId].status;
    }
}