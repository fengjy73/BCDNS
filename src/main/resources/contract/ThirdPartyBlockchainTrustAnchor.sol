// SPDX-License-Identifier: MIT
pragma solidity ^0.4.26;

import "./utils/Ownable.sol";

contract ThirdPartyBlockchainTrustAnchorManager is Ownable {
    struct ThirdPartyBlockchainTrustAnchorInfo {
        bytes thirdPartyBlockchainTrustAnchor;
        bool status;
    }

    mapping(string => ThirdPartyBlockchainTrustAnchorInfo) private idToTPBTA; // <ObjectIdentity, ThirdPartyBlockchainTrustAnchor>

    event addThirdPartyBlockchainTrustAnchor(string tpbtaId, bytes tpbta);
    event revokeThirdPartyBlockchainTrustAnchor(string tpbtaId);
    event upgradeThirdPartyBlockchainTrustAnchor(string tpbtaId, bytes newTpbta);

    function addTPBTA(string memory tpbtaId, bytes memory tpbta) public onlyOwner {
        require(
            idToTPBTA[tpbtaId].thirdPartyBlockchainTrustAnchor.length == 0,
            "ThirdPartyBlockchainTrustAnchor has been registered"
        );

        ThirdPartyBlockchainTrustAnchorInfo memory thirdPartyBTA;
        thirdPartyBTA.thirdPartyBlockchainTrustAnchor = tpbta;
        thirdPartyBTA.status = true;
        idToTPBTA[tpbtaId] = thirdPartyBTA;

        emit addThirdPartyBlockchainTrustAnchor(tpbtaId, tpbta);
    }

    function revokeTPBTA(string memory tpbtaId) public onlyOwner {
        require(
            idToTPBTA[tpbtaId].status,
            "ThirdPartyBlockchainTrustAnchor has been revoked"
        );

        idToTPBTA[tpbtaId].status = false;
        emit revokeThirdPartyBlockchainTrustAnchor(tpbtaId);
    }

    function upgradeTPBTA(string memory tpbtaId, bytes memory newTpbta) public onlyOwner {
        require(
            idToTPBTA[tpbtaId].thirdPartyBlockchainTrustAnchor.length != 0,
            "ThirdPartyBlockchainTrustAnchor has been registered"
        );

        require(
            idToTPBTA[tpbtaId].status,
            "ThirdPartyBlockchainTrustAnchor has been revoked"
        );

        idToTPBTA[tpbtaId].thirdPartyBlockchainTrustAnchor = newTpbta;
        emit upgradeThirdPartyBlockchainTrustAnchor(tpbtaId, newTpbta);
    }

    function getTPBTAById(string memory tpbtaId) public view returns (bytes memory) {
        return idToTPBTA[tpbtaId].thirdPartyBlockchainTrustAnchor;
    }

    function getTPBTAStatusById(string memory tpbtaId) public view returns (bool) {
        return idToTPBTA[tpbtaId].status;
    }
}