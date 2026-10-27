// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC7786OpenBridge} from "../src/ERC7786OpenBridge.sol";
import {IERC7786Recipient} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

/// Test gateway: a contract (so it can be registered) that forwards deliveries to the bridge.
contract GW {
    function deliver(ERC7786OpenBridge b, bytes calldata sender, bytes calldata payload) external returns (bytes4) {
        return b.receiveMessage(bytes32(0), sender, payload);
    }
}

/// Outsider contract (not a registered gateway) used to exercise the "anyone can retry" path.
contract Outsider {
    function deliver(ERC7786OpenBridge b, bytes calldata sender, bytes calldata payload) external returns (bytes4) {
        return b.receiveMessage(bytes32(0), sender, payload);
    }
}

contract CountingRecipient is IERC7786Recipient {
    uint256 public execs;
    bytes public lastPayload;

    function receiveMessage(bytes32, bytes calldata, bytes calldata payload) external payable returns (bytes4) {
        execs++;
        lastPayload = payload;
        return IERC7786Recipient.receiveMessage.selector;
    }
}

contract FlakyRecipient is IERC7786Recipient {
    uint256 public execs;
    bool public fail = true;

    function setFail(bool f) external {
        fail = f;
    }

    function receiveMessage(bytes32, bytes calldata, bytes calldata) external payable returns (bytes4) {
        require(!fail, "flaky");
        execs++;
        return IERC7786Recipient.receiveMessage.selector;
    }
}

/// Recipient that re-enters the bridge (via a gateway it controls a handle to) while executing.
contract ReentrantRecipient is IERC7786Recipient {
    uint256 public execs;
    ERC7786OpenBridge public bridge;
    GW public gw;
    bytes public sender;
    bytes public payload;
    bool public reentryReverted;

    function arm(ERC7786OpenBridge b, GW g, bytes calldata s, bytes calldata p) external {
        bridge = b;
        gw = g;
        sender = s;
        payload = p;
    }

    function receiveMessage(bytes32, bytes calldata, bytes calldata) external payable returns (bytes4) {
        execs++;
        // Re-enter as a not-yet-delivered gateway for the SAME message while it is executing.
        try gw.deliver(bridge, sender, payload) returns (bytes4) {} catch {
            reentryReverted = true;
        }
        return IERC7786Recipient.receiveMessage.selector;
    }
}

/// N-of-M OpenBridge: fuzz + property tests on the receive-side state machine.
contract OpenBridgeFuzzTest is Test {
    uint256 constant REMOTE_CHAIN = 999;
    address constant REMOTE_BRIDGE = address(0xB21D6E);
    uint8 constant THRESHOLD = 2;

    ERC7786OpenBridge bridge;
    GW[3] gws;
    Outsider outsider;
    CountingRecipient recipient;
    bytes remoteSender; // canonical interop address of the trusted remote bridge

    function setUp() public {
        address[] memory list = new address[](3);
        for (uint256 i; i < 3; ++i) {
            gws[i] = new GW();
            list[i] = address(gws[i]);
        }
        bridge = new ERC7786OpenBridge(address(this), list, THRESHOLD);
        remoteSender = InteroperableAddress.formatEvmV1(REMOTE_CHAIN, REMOTE_BRIDGE);
        bridge.registerRemoteBridge(remoteSender);
        outsider = new Outsider();
        recipient = new CountingRecipient();
    }

    function _payload(uint256 nonce, bytes memory userPayload) internal view returns (bytes memory) {
        bytes memory origSender = InteroperableAddress.formatEvmV1(REMOTE_CHAIN, address(0xA11CE));
        bytes memory rcpt = InteroperableAddress.formatEvmV1(block.chainid, address(recipient));
        return abi.encode(nonce, origSender, rcpt, userPayload);
    }

    function _deliver(uint8 who, bytes memory sender, bytes memory payload) internal returns (bool ok) {
        if (who < 3) {
            try gws[who].deliver(bridge, sender, payload) returns (bytes4) { ok = true; } catch { ok = false; }
        } else {
            try outsider.deliver(bridge, sender, payload) returns (bytes4) { ok = true; } catch { ok = false; }
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // P1: execution happens exactly once, and only after >= THRESHOLD distinct registered gateways delivered,
    //     for ANY interleaving of gateway / duplicate-gateway / outsider deliveries.
    // ------------------------------------------------------------------------------------------------------
    function testFuzz_ExactlyOnceAfterThreshold(uint8[12] memory order, uint256 nonce, bytes memory userPayload) public {
        bytes memory payload = _payload(nonce, userPayload);
        bool[3] memory seen;
        uint256 distinct;
        for (uint256 i; i < order.length; ++i) {
            uint8 who = order[i] % 4; // 0..2 gateways, 3 outsider
            _deliver(who, remoteSender, payload);
            if (who < 3 && !seen[who]) {
                seen[who] = true;
                distinct++;
            }
            uint256 expected = distinct >= THRESHOLD ? 1 : 0;
            assertEq(recipient.execs(), expected, "exec count mismatch vs distinct-gateway count");
        }
        assertLe(recipient.execs(), 1, "double execution");
    }

    // ------------------------------------------------------------------------------------------------------
    // P2: an outsider (non-gateway) can never move the counter: N outsider calls never execute.
    // ------------------------------------------------------------------------------------------------------
    function testFuzz_OutsiderCannotCount(uint8 calls, uint256 nonce) public {
        bytes memory payload = _payload(nonce, hex"01");
        for (uint256 i; i < uint256(calls % 32) + 1; ++i) _deliver(3, remoteSender, payload);
        // one real gateway is still below threshold
        _deliver(0, remoteSender, payload);
        assertEq(recipient.execs(), 0, "outsider deliveries counted toward threshold");
    }

    // ------------------------------------------------------------------------------------------------------
    // P3: forged sender (anything but the canonical registered remote bridge) is always rejected, even from a
    //     registered gateway — covers trailing-junk / non-canonical interop-address encodings.
    // ------------------------------------------------------------------------------------------------------
    function testFuzz_ForgedSenderRejected(bytes memory forged, uint256 nonce) public {
        vm.assume(keccak256(forged) != keccak256(remoteSender));
        bytes memory payload = _payload(nonce, hex"02");
        for (uint8 g; g < 3; ++g) assertFalse(_deliver(g, forged, payload), "forged sender accepted");
        assertEq(recipient.execs(), 0);
    }

    function test_TrailingJunkSenderRejected() public {
        bytes memory payload = _payload(1, hex"03");
        bytes memory junk = bytes.concat(remoteSender, hex"deadbeef"); // parses to the same (type,ref,addr)
        for (uint8 g; g < 3; ++g) assertFalse(_deliver(g, junk, payload), "non-canonical sender accepted");
        assertEq(recipient.execs(), 0);
    }

    // ------------------------------------------------------------------------------------------------------
    // P4 (observation): the dedup key is keccak(sender, RAW payload). A non-canonical payload encoding (trailing
    //     bytes) decodes to the same message but opens a SEPARATE tracker. Reaching threshold on the variant still
    //     needs THRESHOLD distinct gateways to deliver the *same variant bytes* — i.e. the gateways themselves.
    // ------------------------------------------------------------------------------------------------------
    function test_PayloadVariantSplitsTrackers() public {
        bytes memory p = _payload(7, hex"04");
        bytes memory pVariant = bytes.concat(p, hex"00"); // abi.decode ignores trailing bytes
        _deliver(0, remoteSender, p);
        _deliver(1, remoteSender, pVariant);
        assertEq(recipient.execs(), 0, "split encodings should not combine");
        // Same logical message executes twice only if >= THRESHOLD gateways each deliver both variants:
        _deliver(1, remoteSender, p); // canonical reaches 2 -> exec #1
        _deliver(0, remoteSender, pVariant); // variant reaches 2 -> exec #2 (same logical msg)
        assertEq(recipient.execs(), 2, "documents: logical replay requires THRESHOLD gateways to collude");
    }

    // ------------------------------------------------------------------------------------------------------
    // P5 (documented behavior): a removed gateway's earlier receipt still counts.
    // ------------------------------------------------------------------------------------------------------
    function test_RemovedGatewayReceiptStillCounts() public {
        bytes memory p = _payload(9, hex"05");
        _deliver(2, remoteSender, p);
        bridge.removeGateway(address(gws[2])); // threshold 2 <= 2 remaining: allowed
        _deliver(0, remoteSender, p); // count -> 2 with only ONE currently-registered gateway
        assertEq(recipient.execs(), 1, "documents NatSpec: stale receipt from removed gateway counts");
    }

    // ------------------------------------------------------------------------------------------------------
    // P6: a re-added gateway cannot double count (receivedBy persists across removal/re-add).
    // ------------------------------------------------------------------------------------------------------
    function test_ReaddedGatewayCannotDoubleCount() public {
        bytes memory p = _payload(10, hex"06");
        _deliver(2, remoteSender, p);
        bridge.removeGateway(address(gws[2]));
        bridge.addGateway(address(gws[2]));
        _deliver(2, remoteSender, p);
        assertEq(recipient.execs(), 0, "re-added gateway counted twice");
    }

    // ------------------------------------------------------------------------------------------------------
    // P7 (observation): recipient chainid is ignored at destination — a recipient tagged for another chain is
    //     executed on this chain if gateways deliver it here.
    // ------------------------------------------------------------------------------------------------------
    function test_RecipientChainIdIgnored() public {
        bytes memory origSender = InteroperableAddress.formatEvmV1(REMOTE_CHAIN, address(0xA11CE));
        bytes memory rcptOtherChain = InteroperableAddress.formatEvmV1(block.chainid + 12345, address(recipient));
        bytes memory p = abi.encode(uint256(11), origSender, rcptOtherChain, hex"07");
        _deliver(0, remoteSender, p);
        _deliver(1, remoteSender, p);
        assertEq(recipient.execs(), 1, "documents: dest does not check recipient chainid");
    }

    // ------------------------------------------------------------------------------------------------------
    // P8: a malformed recipient (EVM addr length != 20) makes the threshold-crossing delivery revert; the message
    //     is stuck (self-inflicted by the original sender), counter is not advanced by the reverting delivery.
    // ------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------
    // P9: recipient re-entering mid-execution (as the 3rd, not-yet-delivered gateway) cannot cause a 2nd execution.
    // ------------------------------------------------------------------------------------------------------
    function test_ReentrancyNoDoubleExecution() public {
        ReentrantRecipient rr = new ReentrantRecipient();
        bytes memory origSender = InteroperableAddress.formatEvmV1(REMOTE_CHAIN, address(0xA11CE));
        bytes memory rcpt = InteroperableAddress.formatEvmV1(block.chainid, address(rr));
        bytes memory p = abi.encode(uint256(13), origSender, rcpt, hex"09");
        rr.arm(bridge, gws[2], remoteSender, p);
        _deliver(0, remoteSender, p);
        _deliver(1, remoteSender, p); // crosses threshold -> executes -> re-enters as gw2
        assertEq(rr.execs(), 1, "re-entrancy caused double execution");
        // gw2 re-entry is graceful (counted, already-executed branch) — no revert expected
        assertFalse(rr.reentryReverted(), "graceful already-executed path expected for first-time gateway");
        // and any later retry by an outsider reverts AlreadyExecuted, no 2nd exec
        assertFalse(_deliver(3, remoteSender, p));
        assertEq(rr.execs(), 1);
    }

    // ------------------------------------------------------------------------------------------------------
    // P10: after a FAILED execution (recipient reverts), anyone can retry; retry executes exactly once.
    // ------------------------------------------------------------------------------------------------------
    function test_FailedExecutionRetryOnce() public {
        FlakyRecipient fr = new FlakyRecipient();
        bytes memory origSender = InteroperableAddress.formatEvmV1(REMOTE_CHAIN, address(0xA11CE));
        bytes memory rcpt = InteroperableAddress.formatEvmV1(block.chainid, address(fr));
        bytes memory p = abi.encode(uint256(14), origSender, rcpt, hex"0a");
        _deliver(0, remoteSender, p);
        _deliver(1, remoteSender, p); // threshold crossed, recipient reverts -> rollback, ExecutionFailed
        assertEq(fr.execs(), 0);
        fr.setFail(false);
        assertTrue(_deliver(3, remoteSender, p), "outsider retry should succeed");
        assertEq(fr.execs(), 1);
        assertFalse(_deliver(3, remoteSender, p), "second retry must revert AlreadyExecuted");
        _deliver(2, remoteSender, p); // late 3rd gateway: graceful, no re-exec
        assertEq(fr.execs(), 1, "late gateway re-executed");
    }

    function test_MalformedRecipientStuck() public {
        bytes memory origSender = InteroperableAddress.formatEvmV1(REMOTE_CHAIN, address(0xA11CE));
        bytes memory badRcpt = InteroperableAddress.formatV1(bytes2(0x0000), hex"01", new bytes(19));
        bytes memory p = abi.encode(uint256(12), origSender, badRcpt, hex"08");
        assertTrue(_deliver(0, remoteSender, p), "first delivery (below threshold) should succeed");
        assertFalse(_deliver(1, remoteSender, p), "threshold delivery should revert on parseEvmV1");
        assertFalse(_deliver(2, remoteSender, p), "every later threshold delivery reverts too");
        assertEq(recipient.execs(), 0);
    }
}
