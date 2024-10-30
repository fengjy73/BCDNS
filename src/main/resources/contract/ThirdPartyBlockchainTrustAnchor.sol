// SPDX-License-Identifier: MIT
pragma solidity ^0.4.26;

import "./utils/Ownable.sol";

contract ThirdPartyBlockchainTrustAnchorManager is Ownable {
    struct ThirdPartyBlockchainTrustAnchorInfo {
        bytes thirdPartyBlockchainTrustAnchor;
        bool status;
        // bool exist;
    }

    // ThirdPartyBlockchainTrustAnchorLane: {
    //     ThirdPartyBlockchainTrustAnchorLaneVersion: {
    //         ThirdPartyBlockchainTrustAnchor
    //     }
    // }
    mapping(string => mapping(uint16 => ThirdPartyBlockchainTrustAnchorInfo)) private laneToTPBTA;
    mapping(string => uint16) private laneToTPBTALatestVersion;

    event addThirdPartyBlockchainTrustAnchor(string tpbtaLane, uint16 tpbtaVersion, bytes tpbta);
    event revokeThirdPartyBlockchainTrustAnchor(string tpbtaLane, uint16 tpbtaVersion);
    // event upgradeThirdPartyBlockchainTrustAnchor(string tpbtaLane, uint16 tpbtaVersion, bytes newTpbta);

    function addTPBTA(string memory tpbtaLane, uint16 tpbtaVersion, bytes memory tpbta) public onlyOwner {
        require(
            tpbtaVersion > 0,
            "tpbta version must gather than 0"
        );

        // require(
        //     laneToTPBTA[tpbtaLane][tpbtaVersion].thirdPartyBlockchainTrustAnchor.length == 0,
        //     "ThirdPartyBlockchainTrustAnchor has been registered"
        // );

        if(tpbtaVersion == 1) {
            require(laneToTPBTA[tpbtaLane][tpbtaVersion].thirdPartyBlockchainTrustAnchor.length == 0, "ThirdPartyBlockchainTrustAnchor has been registered");
        } else {
            require(laneToTPBTA[tpbtaLane][tpbtaVersion].thirdPartyBlockchainTrustAnchor.length == 0, "TPBTA in request version has been registered");
            require(laneToTPBTA[tpbtaLane][tpbtaVersion-1].thirdPartyBlockchainTrustAnchor.length != 0, "Last tpbtaVersion has not been registered");
        }

        ThirdPartyBlockchainTrustAnchorInfo memory thirdPartyBTA;
        thirdPartyBTA.thirdPartyBlockchainTrustAnchor = tpbta;
        // thirdPartyBTA.exist = true;
        thirdPartyBTA.status = true;
        laneToTPBTA[tpbtaLane][tpbtaVersion] = thirdPartyBTA;
        laneToTPBTALatestVersion[tpbtaLane] = tpbtaVersion;

        emit addThirdPartyBlockchainTrustAnchor(tpbtaLane, tpbtaVersion, tpbta);
    }

    function revokeTPBTA(string memory tpbtaLane, uint16 tpbtaVersion) public onlyOwner {
        require(
            laneToTPBTA[tpbtaLane][tpbtaVersion].thirdPartyBlockchainTrustAnchor.length != 0,
            "ThirdPartyBlockchainTrustAnchor has not been registered"
        );

        require(
            laneToTPBTA[tpbtaLane][tpbtaVersion].status,
            "ThirdPartyBlockchainTrustAnchor has been revoked"
        );

        laneToTPBTA[tpbtaLane][tpbtaVersion].status = false;
        emit revokeThirdPartyBlockchainTrustAnchor(tpbtaLane, tpbtaVersion);
    }

    // function upgradeTPBTA(string memory tpbtaLane, uint16 tpbtaVersion, bytes memory newTpbta) public onlyOwner {
    //     require(
    //         laneToTPBTA[tpbtaLane][tpbtaVersion].thirdPartyBlockchainTrustAnchor.length != 0,
    //         "ThirdPartyBlockchainTrustAnchor has not been registered"
    //     );

    //     require(
    //         laneToTPBTA[tpbtaLane][tpbtaVersion].status,
    //         "ThirdPartyBlockchainTrustAnchor has been revoked"
    //     );

    //     laneToTPBTA[tpbtaLane][tpbtaVersion].thirdPartyBlockchainTrustAnchor = newTpbta;
    //     emit upgradeThirdPartyBlockchainTrustAnchor(tpbtaLane, tpbtaVersion ,newTpbta);
    // }

    function getTPBTAByLane(string memory tpbtaLane, uint16 tpbtaVersion) public view returns (bytes memory) {
        if(tpbtaVersion == 0) {
            tpbtaVersion = getTPBTALatestVersionByLane(tpbtaLane);
        }
        return laneToTPBTA[tpbtaLane][tpbtaVersion].thirdPartyBlockchainTrustAnchor;
    }

    function getTPBTAStatusByLane(string memory tpbtaLane, uint16 tpbtaVersion) public view returns (bool) {
        return laneToTPBTA[tpbtaLane][tpbtaVersion].status;
    }

    // function checkTPBTAEverExist(string memory tpbtaLane, uint16 tpbtaVersion) public view returns (bool) {
    //     return laneToTPBTA[tpbtaLane][tpbtaVersion].exist;
    // }

    function getTPBTALatestVersionByLane(string memory tpbtaLane) public view  returns (uint16) {
        return laneToTPBTALatestVersion[tpbtaLane];
    }
}