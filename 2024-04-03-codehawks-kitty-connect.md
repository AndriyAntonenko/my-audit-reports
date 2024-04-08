# First Flight #12: Kitty Connect - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. Invalid allowlisted address verification in the KittyBridge::_ccipReceive](#H-01)
    - ### [H-02. Insufficient LINK Token Approval in `KittyBridge::bridgeNftWithData`](#H-02)

- ## Low Risk Findings
    - ### [L-01. Incomplete updating of owner token IDs in KittyConnect::mintBridgedNFT](#L-01)
    - ### [L-02. No ability to remove shop partner in the KittyConnect](#L-02)
    - ### [L-03. The function `KittyConnect::_updateOwnershipInfo` doesn't update the `KittyConnect::s_ownerToCatsTokenId` for new owner](#L-03)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #12: Kitty Connect

### Dates: Mar 28th, 2024 - Apr 4th, 2024

[See more contest details here](https://www.codehawks.com/contests/clu7ddcsa000fcc387vjv6rpt)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 2
   - Medium: 0
   - Low: 3


# High Risk Findings

## <a id='H-01'></a>H-01. Invalid allowlisted address verification in the KittyBridge::_ccipReceive            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2024-03-kitty-connect/blob/c0a6f2bb5c853d7a470eb684e1954dba261fb167/src/KittyBridge.sol#L83

## Summary

The `KittyBridge::_ccipReceive` function is triggered upon the receipt of each new incoming message from the CCIP protocol router. According to best practices, it is recommended to verify the sender of the CCIP message, whose value is stored as the property `sender` of `Client.Any2EVMMessage` structure. However, in the `KittyBridge::_ccipReceive` function, verification is attempted using `msg.sender`, which will always equal the CCIP router address.

## Vulnerability Details

- The `KittyBridge::_ccipReceive` function utilizes the `onlyAllowlisted` modifier to authenticate the sender of the CCIP message with the source chain selector.
- This function employs `msg.sender` for sender verification, where `msg.sender` will always be the router. This is guaranteed by the `onlyRouter` modifier from the `CCIPReceiver` smart contract.
- It is expected that this function should authenticate the actual sender from the source chain.

## Impact

- The verification of the CCIP message sender is incorrect, and without adding the router address to the `allowlistedSenders`, this method will consistently fail, regardless of who sends the message.
- Consequently, in most cases, `KittyBridge::_ccipReceive` will fail due to incorrect sender validation.

## Tools Used

Manual review and CCIP documentation.

## Recommendations

```diff
    function _ccipReceive(Client.Any2EVMMessage memory any2EvmMessage)
        internal
        override
-       onlyAllowlisted(any2EvmMessage.sourceChainSelector, msg.sender)
+      onlyAllowlisted(any2EvmMessage.sourceChainSelector, abi.decode(any2EvmMessage.sender, (address)))
    {
        KittyConnect(kittyConnect).mintBridgedNFT(any2EvmMessage.data);

        emit MessageReceived(
            any2EvmMessage.messageId,
            any2EvmMessage.sourceChainSelector,
            abi.decode(any2EvmMessage.sender, (address)),
            any2EvmMessage.data
        );
    }

``` 

The above changes rectify the issue by ensuring that `KittyBridge::_ccipReceive` correctly authenticates the sender of the CCIP message, thus addressing the identified vulnerability.
## <a id='H-02'></a>H-02. Insufficient LINK Token Approval in `KittyBridge::bridgeNftWithData`            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2024-03-kitty-connect/blob/c0a6f2bb5c853d7a470eb684e1954dba261fb167/src/KittyBridge.sol#L72

## Summary

The `KittyBridge` contract facilitates token transfers to another chain. To achieve this, the `KittyConnect` contract invokes `KittyBridge::bridgeNftWithData`. However, to bridge tokens between chains using CCIP, the `KittyBridge` must pay a fee in LINK tokens. This payment necessitates approval for LINK token transfer from `KittyBridge` to the CCIP `router`, which is currently absent.

## Vulnerability Details

The vulnerability resides within the `KittyBridge` contract. In the `bridgeNftWithData` function, `Router::ccipSend` is called without prior approval for LINK token transfer.
The CCIP `Router` contract attempts to levy a fee from the `KittyBridge` for dispatching CCIP messages in LINK. However, this attempt fails due to the lack of approval from `KittyBridge` for the transfer.

## Impact

The `KittyBridge::bridgeNftWithData` function consistently reverts due to insufficient allowance.

## Tools Used

Manual review and `forge` were employed.
To replicate this issue, utilize the provided `forge script` below (save it in the file `script/MintCatAndBridge.s.sol`):

```solidity
// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import {Script} from "forge-std/Script.sol";
import {KittyConnect} from "../src/KittyConnect.sol";
import {KittyBridge} from "../src/KittyBridge.sol";

contract MintCatAndBridge is Script {
  function run() external {
    if (block.chainid != 11155111) {
      // only run on Sepolia
      return;
    }

    uint256 receiverPk = vm.envUint("RECEIVER_PK");
    vm.startBroadcast();

    address receiver = 0x065D2517ba3267391eD48a0D63Dce44b23E34d06;
    KittyConnect kittyConnect = KittyConnect(0x304B6DB56659038F13868946805AF62eDfac76b3);

    uint256 tokenId = kittyConnect.getTokenCounter();
    kittyConnect.mintCatToNewOwner(receiver, "ipfs://QmWDK6uj7xS5NkBotM7VouqtZiZU4qvuFURa1E9DgM8JQ2", "Tom", "breed", block.timestamp);
    vm.stopBroadcast();

    vm.startBroadcast(receiverPk);

    uint64 mumbaiChainSelector = 12532609583862916517;
    address mumbaiBridgeAddress = 0xAafbFFff34E4416623C274BdEdc6984c5712E351;
    // this will fail due insufficient allowance
    kittyConnect.bridgeNftToAnotherChain(mumbaiChainSelector, mumbaiBridgeAddress, tokenId);
    vm.stopBroadcast();
  }
}
```

Ensure to set the appropriate values for `RECEIVER_PK`, `sepolia-rpc-url`, and adjust addresses as necessary. Running this script will consistently fail:

```bash
forge script script/MintCatAndBridge.s.sol \
  --private-key <shop-partner-pk> \
  --rpc-url <sepolia-rpc-rul> \
  --broadcast -vvvv
```

## Recommendations

Insert the following line before sending the CCIP message in the `KittyBridge::bridgeNftWithData` function:

```diff
+       s_linkToken.approve(address(router), fees);
        messageId = router.ccipSend(_destinationChainSelector, evm2AnyMessage);

        emit MessageSent(messageId, _destinationChainSelector, _receiver, _data, address(s_linkToken), fees);

        return messageId;
``` 

This addition ensures that `KittyBridge` appropriately approves the transfer of LINK tokens before dispatching CCIP messages, thereby rectifying the identified issue.
		


# Low Risk Findings

## <a id='L-01'></a>L-01. Incomplete updating of owner token IDs in KittyConnect::mintBridgedNFT            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2024-03-kitty-connect/blob/c0a6f2bb5c853d7a470eb684e1954dba261fb167/src/KittyConnect.sol#L176

## Summary

The `KittyConnect::mintBridgedNFT` function aims to mint the token received from the bridge and update the state variables accordingly. However, it currently fails to update the `s_ownerToCatsTokenId[catOwner]` variable.

## Vulnerability Details

- The vulnerability lies within the `KittyConnect` contract, specifically in the `mintBridgedNFT` function, where state changes for the `s_ownerToCatsTokenId` variable are not handled.
- It is expected that the function would append the new `tokenId` to `s_ownerToCatsTokenId[catOwner]`, but this action is currently omitted.

## Impact

- Upon receiving a bridged token from the source chain, the `tokenId` will not be added to `s_ownerToCatsTokenId[catOwner]`, resulting in an inaccurate list of owner token IDs.

## Tools Used

Manual review and 'forge'.

To replicate the issue, add the following test suite to the tests file `test/KittyConnect.t.sol`:

```solidity
  function test_mintBridgedNFTNotUpdateOwnerToCatsTokenId() public {
    address randomOwner = makeAddr("randomOwner");
    vm.prank(address(kittyBridge));
    bytes memory data = abi.encode(randomOwner, "Tom", "breed", "hash", block.timestamp, partnerA);
    kittyConnect.mintBridgedNFT(data);
    assert(kittyConnect.getCatsTokenIdOwnedBy(randomOwner).length == 1);
  }
```

Subsequently, execute this test suite:

```bash
forge test --mt test_mintBridgedNFTNotUpdateOwnerToCatsTokenId
```

This test will fail.

## Recommendations

Integrate the following changes into the `mintBridgedNFT` function:

```diff
        s_catInfo[tokenId] = CatInfo({
            catName: catName,
            breed: breed,
            image: imageIpfsHash,
            dob: dob,
            prevOwner: new address ,
            shopPartner: shopPartner,
            idx: s_ownerToCatsTokenId[catOwner].length
        });

+.       s_ownerToCatsTokenId[catOwner].push(tokenId);
        emit NFTBridged(block.chainid, tokenId);
        _safeMint(catOwner, tokenId);
``` 

These modifications ensure that `mintBridgedNFT` correctly updates the `s_ownerToCatsTokenId[catOwner]` variable, thereby resolving the identified vulnerability.
## <a id='L-02'></a>L-02. No ability to remove shop partner in the KittyConnect            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2024-03-kitty-connect/blob/c0a6f2bb5c853d7a470eb684e1954dba261fb167/src/KittyConnect.sol#L77

## Summary

The `KittyConnect` contract enables the addition of multiple shop partners. However, it lacks functionality to remove shop partners. Consequently, if a business decides not to collaborate with a specific shop, there is no mechanism to remove it, allowing the said shop to continue minting tokens for its users.

## Vulnerability Details

The absence of a function to remove shop partners within the `KittyConnect` contract constitutes a vulnerability. Without the ability to revoke access, unwanted shop partners retain the capability to mint tokens, compromising the integrity of the system.

## Impact

The inability to remove shop partners poses a significant operational risk. If a business no longer wishes to engage with a particular shop, it has no recourse to prevent the shop from minting tokens, potentially leading to unauthorized token issuance and misuse.

## Tools Used

Manual review, code analysis.

## Recommendations

Implementing a blacklist functionality within the KittyConnect contract would be advisable. This feature would enable the addition of unwanted shop partners to a blacklist, effectively revoking their ability to mint tokens. By incorporating this blacklist mechanism, businesses gain enhanced control over their partnerships, thereby mitigating the risks associated with unauthorized token issuance.
## <a id='L-03'></a>L-03. The function `KittyConnect::_updateOwnershipInfo` doesn't update the `KittyConnect::s_ownerToCatsTokenId` for new owner            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2024-03-kitty-connect/blob/c0a6f2bb5c853d7a470eb684e1954dba261fb167/src/KittyConnect.sol#L184

## Summary
The function `KittyConnect::_updateOwnershipInfo` is utilized within the execution of `KittyConnect::safeTransferFrom` to update data in both the `KittyConnect::s_ownerToCatsTokenId` and `KittyConnect::s_catInfo`. However, it fails to remove the `tokenId` from the `s_ownerToCatsTokenId[currCatOwner]` array.

## Vulnerability Details
The vulnerability resides within the `KittyConnect` contract, specifically in the `_updateOwnershipInfo` function, where there is no provision to update the `s_ownerToCatsTokenId` array for the `currCatOwner`.
The `s_ownerToCatsTokenId` array is intended to track the complete list of token IDs belonging to a specific user. It is expected that after invoking this function, the `tokenId` would be removed from the `s_ownerToCatsTokenId` array of the current owner. However, this removal does not occur.

## Impact
Following the invocation of `safeTransferFrom`, the `tokenId` persists within the current user array within `s_ownerToCatsTokenId`, rendering the utilization of `s_ownerToCatsTokenId` redundant.

## Tools Used
Manual review and `forge` were employed.
To identify this issue, execute the existing test within `test/KittyTest.t.sol`:

```bash
forge test --mt test_safetransferCatToNewOwner
```

This test suite fails due to the following assertion failure:

```solidity
assertEq(kittyConnect.getCatsTokenIdOwnedBy(user).length, 0);
```

## Recommendations
It is advised to incorporate code to properly handle the `s_ownerToCatsTokenId` for `currCatOwner`:

```diff
    function _updateOwnershipInfo(address currCatOwner, address newOwner, uint256 tokenId) internal {        
        s_catInfo[tokenId].prevOwner.push(currCatOwner);
+      uint256 prevIdx = s_catInfo[tokenId].idx;
        s_catInfo[tokenId].idx = s_ownerToCatsTokenId[newOwner].length;
        s_ownerToCatsTokenId[newOwner].push(tokenId);
+        
+      uint256 latestIdx = s_ownerToCatsTokenId[currCatOwner].length - 1;
+      if (prevIdx != latestIdx) {
+          uint256 lastItem = s_ownerToCatsTokenId[currCatOwner][latestIdx];
+          s_ownerToCatsTokenId[currCatOwner][prevIdx] = lastItem;
+       }
+       s_ownerToCatsTokenId[currCatOwner].pop();
    }
``` 

These changes ensure proper management of `s_ownerToCatsTokenId` for `currCatOwner`, thereby addressing the identified issue.


