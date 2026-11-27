// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.39;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {SecurityToken} from "../src/SecurityToken.sol";

/// 역할별 허용·거부, 다른 기관 계좌의 대체 거부, 처분제한, 유통 정지(작업지시서 T3.1)
contract SecurityTokenTest is Test {
    SecurityToken token;

    address admin = makeAddr("contract-admin");
    address controller = makeAddr("emergency");
    address issuerA = makeAddr("inst-a-issue");
    address agentA = makeAddr("inst-a-transfer");
    address agentB = makeAddr("inst-b-transfer");
    address outsider = makeAddr("outsider");

    address acctA1 = makeAddr("acct-a-1");
    address acctA2 = makeAddr("acct-a-2");
    address acctB1 = makeAddr("acct-b-1");

    event Issued(address indexed account, uint256 amount);
    event Transferred(address indexed from, address indexed to, uint256 amount, address indexed agent);
    event CirculationChanged(bool active);

    function setUp() public {
        token = new SecurityToken("Demo Bond 1", "KRDEMO000001", admin);
        vm.startPrank(admin);
        token.grantRole(token.CONTROLLER_ROLE(), controller);
        token.grantRole(token.ISSUER_ROLE(), issuerA);
        token.grantRole(token.TRANSFER_AGENT_ROLE(), agentA);
        token.grantRole(token.TRANSFER_AGENT_ROLE(), agentB);
        token.setAgentInstitution(issuerA, "inst-a");
        token.setAgentInstitution(agentA, "inst-a");
        token.setAgentInstitution(agentB, "inst-b");
        vm.stopPrank();

        vm.prank(agentA);
        token.registerAccount(acctA1, "inst-a");
        vm.prank(agentA);
        token.registerAccount(acctA2, "inst-a");
        vm.prank(agentB);
        token.registerAccount(acctB1, "inst-b");

        vm.prank(issuerA);
        token.issue(acctA1, 1000);
    }

    function _unauthorized(address who, bytes32 role) internal {
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, who, role));
    }

    // ---- 기본값 ----

    function test_Metadata() public view {
        assertEq(token.name(), "Demo Bond 1");
        assertEq(token.symbol(), "KRDEMO000001");
        assertEq(token.decimals(), 0);
        assertTrue(token.circulationActive());
        assertTrue(token.hasRole(token.DEFAULT_ADMIN_ROLE(), admin));
        assertEq(token.totalSupply(), 1000);
        assertEq(token.balanceOf(acctA1), 1000);
    }

    function test_ConstructorRejectsZeroAdmin() public {
        vm.expectRevert(SecurityToken.ZeroAddress.selector);
        new SecurityToken("x", "y", address(0));
    }

    /// 일반 ERC-20 의 transfer·approve·transferFrom 이 없다.
    function test_NoErc20TransferOrApprove() public {
        bytes[3] memory calls = [
            abi.encodeWithSignature("transfer(address,uint256)", acctA2, 1),
            abi.encodeWithSignature("approve(address,uint256)", acctA2, 1),
            abi.encodeWithSignature("transferFrom(address,address,uint256)", acctA1, acctA2, 1)
        ];
        for (uint256 i = 0; i < calls.length; i++) {
            vm.prank(acctA1);
            (bool ok,) = address(token).call(calls[i]);
            assertFalse(ok);
        }
        assertEq(token.balanceOf(acctA1), 1000);
    }

    // ---- 관리 역할 ----

    function test_OnlyAdminGrantsRoles() public {
        bytes32 issuer = token.ISSUER_ROLE();
        bytes32 adminRole = token.DEFAULT_ADMIN_ROLE();
        address[3] memory others = [issuerA, agentA, controller];
        for (uint256 i = 0; i < others.length; i++) {
            _unauthorized(others[i], adminRole);
            vm.prank(others[i]);
            token.grantRole(issuer, outsider);
        }
        vm.prank(admin);
        token.grantRole(issuer, outsider);
        assertTrue(token.hasRole(issuer, outsider));
        vm.prank(admin);
        token.revokeRole(issuer, outsider);
        assertFalse(token.hasRole(issuer, outsider));
    }

    function test_OnlyAdminSetsAgentInstitution() public {
        _unauthorized(agentA, token.DEFAULT_ADMIN_ROLE());
        vm.prank(agentA);
        token.setAgentInstitution(agentA, "inst-b");
        assertEq(token.agentInstitution(agentA), "inst-a");

        vm.prank(admin);
        vm.expectRevert(SecurityToken.ZeroAddress.selector);
        token.setAgentInstitution(address(0), "inst-a");
    }

    // ---- 발행·말소 ----

    function test_IssueRoleRequired() public {
        address[3] memory others = [agentA, controller, admin];
        for (uint256 i = 0; i < others.length; i++) {
            _unauthorized(others[i], token.ISSUER_ROLE());
            vm.prank(others[i]);
            token.issue(acctA1, 1);
        }
    }

    function test_IssueAndRedeem() public {
        vm.expectEmit(address(token));
        emit Issued(acctB1, 50);
        vm.prank(issuerA);
        token.issue(acctB1, 50);
        vm.prank(issuerA);
        token.redeem(acctA1, 300);
        assertEq(token.balanceOf(acctA1), 700);
        assertEq(token.balanceOf(acctB1), 50);
        assertEq(token.totalSupply(), 750);
    }

    function test_IssueRejects() public {
        vm.startPrank(issuerA);
        vm.expectRevert(abi.encodeWithSelector(SecurityToken.AccountNotRegistered.selector, outsider));
        token.issue(outsider, 1);
        vm.expectRevert(SecurityToken.ZeroAmount.selector);
        token.issue(acctA1, 0);
        vm.expectRevert(abi.encodeWithSelector(SecurityToken.InsufficientBalance.selector, acctA1, 1000, 1001));
        token.redeem(acctA1, 1001);
        vm.stopPrank();
    }

    // ---- 계좌 등록 ----

    function test_RegisterAccountRoleRequired() public {
        _unauthorized(issuerA, token.TRANSFER_AGENT_ROLE());
        vm.prank(issuerA);
        token.registerAccount(outsider, "inst-a");
    }

    function test_RegisterAccountInstitutionMustMatchAgent() public {
        vm.prank(agentB);
        vm.expectRevert(abi.encodeWithSelector(SecurityToken.InstitutionMismatch.selector, agentB, outsider));
        token.registerAccount(outsider, "inst-a");

        // 기관이 대응되지 않은 대체 키는 어떤 계좌도 등록하지 못한다.
        address agentX = makeAddr("agent-x");
        bytes32 role = token.TRANSFER_AGENT_ROLE();
        vm.prank(admin);
        token.grantRole(role, agentX);
        vm.prank(agentX);
        vm.expectRevert(abi.encodeWithSelector(SecurityToken.InstitutionMismatch.selector, agentX, outsider));
        token.registerAccount(outsider, "inst-a");
    }

    function test_RegisterAccountRejects() public {
        vm.startPrank(agentA);
        vm.expectRevert(abi.encodeWithSelector(SecurityToken.AccountAlreadyRegistered.selector, acctA1));
        token.registerAccount(acctA1, "inst-a");
        vm.expectRevert(SecurityToken.ZeroAddress.selector);
        token.registerAccount(address(0), "inst-a");
        vm.expectRevert(SecurityToken.EmptyInstitution.selector);
        token.registerAccount(outsider, "");
        vm.stopPrank();
    }

    // ---- 계좌대체 ----

    function test_TransferByAgentSameInstitution() public {
        vm.expectEmit(address(token));
        emit Transferred(acctA1, acctB1, 400, agentA);
        vm.prank(agentA);
        token.transferByAgent(acctA1, acctB1, 400);
        assertEq(token.balanceOf(acctA1), 600);
        assertEq(token.balanceOf(acctB1), 400);
        assertEq(token.totalSupply(), 1000);
    }

    /// 다른 기관 계좌에서의 대체 거부(B-2-2)
    function test_TransferByAgentOtherInstitutionRejected() public {
        vm.prank(agentB);
        vm.expectRevert(abi.encodeWithSelector(SecurityToken.InstitutionMismatch.selector, agentB, acctA1));
        token.transferByAgent(acctA1, acctB1, 1);
        assertEq(token.balanceOf(acctA1), 1000);
    }

    function test_TransferByAgentRoleRequired() public {
        address[3] memory others = [issuerA, admin, controller];
        for (uint256 i = 0; i < others.length; i++) {
            _unauthorized(others[i], token.TRANSFER_AGENT_ROLE());
            vm.prank(others[i]);
            token.transferByAgent(acctA1, acctA2, 1);
        }
    }

    /// 역할을 회수하면 같은 키로 더는 대체하지 못한다(키 교체·도난 대응, 설계서 9절).
    function test_RevokedAgentRejected() public {
        bytes32 role = token.TRANSFER_AGENT_ROLE();
        vm.prank(admin);
        token.revokeRole(role, agentA);
        _unauthorized(agentA, role);
        vm.prank(agentA);
        token.transferByAgent(acctA1, acctA2, 1);
    }

    function test_TransferByAgentRejects() public {
        vm.startPrank(agentA);
        vm.expectRevert(abi.encodeWithSelector(SecurityToken.AccountNotRegistered.selector, outsider));
        token.transferByAgent(acctA1, outsider, 1);
        vm.expectRevert(SecurityToken.ZeroAmount.selector);
        token.transferByAgent(acctA1, acctA2, 0);
        vm.expectRevert(abi.encodeWithSelector(SecurityToken.SameAccount.selector, acctA1));
        token.transferByAgent(acctA1, acctA1, 1);
        vm.expectRevert(abi.encodeWithSelector(SecurityToken.InsufficientBalance.selector, acctA1, 1000, 1001));
        token.transferByAgent(acctA1, acctA2, 1001);
        vm.stopPrank();
    }

    // ---- 처분제한 ----

    function test_RestrictedAccountCannotSend() public {
        vm.prank(agentA);
        token.setAccountRestricted(acctA1, true);
        assertTrue(token.accountOf(acctA1).restricted);

        vm.prank(agentA);
        vm.expectRevert(abi.encodeWithSelector(SecurityToken.AccountRestricted.selector, acctA1));
        token.transferByAgent(acctA1, acctA2, 1);

        // 입고는 막지 않는다.
        vm.prank(issuerA);
        token.issue(acctA2, 10);
        vm.prank(agentA);
        token.transferByAgent(acctA2, acctA1, 10);
        assertEq(token.balanceOf(acctA1), 1010);

        vm.prank(agentA);
        token.setAccountRestricted(acctA1, false);
        vm.prank(agentA);
        token.transferByAgent(acctA1, acctA2, 1);
    }

    function test_RestrictionOnlyByOwnInstitution() public {
        vm.prank(agentB);
        vm.expectRevert(abi.encodeWithSelector(SecurityToken.InstitutionMismatch.selector, agentB, acctA1));
        token.setAccountRestricted(acctA1, true);
        _unauthorized(issuerA, token.TRANSFER_AGENT_ROLE());
        vm.prank(issuerA);
        token.setAccountRestricted(acctA1, true);
        vm.prank(agentA);
        vm.expectRevert(abi.encodeWithSelector(SecurityToken.AccountNotRegistered.selector, outsider));
        token.setAccountRestricted(outsider, true);
    }

    // ---- 유통 정지·일시 정지 ----

    function test_CirculationHaltBlocksTransferOnly() public {
        vm.expectEmit(address(token));
        emit CirculationChanged(false);
        vm.prank(controller);
        token.setCirculation(false);

        vm.prank(agentA);
        vm.expectRevert(SecurityToken.CirculationHalted.selector);
        token.transferByAgent(acctA1, acctA2, 1);

        // 발행·말소는 유통 정지로 막지 않는다(D-3-2).
        vm.startPrank(issuerA);
        token.issue(acctA1, 1);
        token.redeem(acctA1, 1);
        vm.stopPrank();

        vm.prank(controller);
        token.setCirculation(true);
        vm.prank(agentA);
        token.transferByAgent(acctA1, acctA2, 1);
    }

    function test_PauseBlocksIssueRedeemTransfer() public {
        vm.prank(controller);
        token.pause();
        vm.prank(issuerA);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        token.issue(acctA1, 1);
        vm.prank(issuerA);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        token.redeem(acctA1, 1);
        vm.prank(agentA);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        token.transferByAgent(acctA1, acctA2, 1);

        vm.prank(controller);
        token.unpause();
        vm.prank(issuerA);
        token.issue(acctA1, 1);
    }

    function test_ControllerRoleRequired() public {
        bytes32 role = token.CONTROLLER_ROLE();
        address[3] memory others = [admin, issuerA, agentA];
        for (uint256 i = 0; i < others.length; i++) {
            vm.startPrank(others[i]);
            _unauthorized(others[i], role);
            token.setCirculation(false);
            _unauthorized(others[i], role);
            token.pause();
            vm.stopPrank();
        }
        vm.prank(controller);
        token.pause();
        _unauthorized(admin, role);
        vm.prank(admin);
        token.unpause();
    }

    /// 수량 보존: 어떤 대체 순서에서도 잔고 합계가 총 발행 수량과 같다.
    function testFuzz_TransferConservesSupply(uint96 a, uint96 b) public {
        uint256 x = bound(a, 1, 1000);
        vm.prank(agentA);
        token.transferByAgent(acctA1, acctB1, x);
        uint256 y = bound(b, 1, x);
        vm.prank(agentB);
        token.transferByAgent(acctB1, acctA2, y);
        assertEq(token.balanceOf(acctA1) + token.balanceOf(acctA2) + token.balanceOf(acctB1), token.totalSupply());
    }
}
