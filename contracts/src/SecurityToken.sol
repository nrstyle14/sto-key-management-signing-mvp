// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.39;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title SecurityToken
/// @notice 종목 하나의 토큰증권 원장(설계서 10.2). 종목마다 하나를 배포하고 소수 자리는 0이다.
/// @dev 계좌(온체인 주소)는 개인키가 없는 무작위 주소이므로(D-7) 일반 ERC-20 의 transfer·approve 를 두지 않는다.
///      모든 잔고 변경은 역할을 가진 기관 키(서명 서버의 HSM 키)만 호출한다.
contract SecurityToken is AccessControl, Pausable {
    /// @notice 발행·말소(기관 ISSUE 키)
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    /// @notice 계좌대체·계좌 등록·처분제한(기관 TRANSFER 키)
    bytes32 public constant TRANSFER_AGENT_ROLE = keccak256("TRANSFER_AGENT_ROLE");
    /// @notice 유통 상태·일시 정지(플랫폼 EMERGENCY 키)
    bytes32 public constant CONTROLLER_ROLE = keccak256("CONTROLLER_ROLE");

    struct Account {
        bool registered;
        bool restricted;
        string institutionId;
    }

    /// @notice 종목명
    string public name;
    /// @notice 종목 코드
    string public symbol;
    /// @notice 총 발행 수량
    uint256 public totalSupply;
    /// @notice 유통 상태. false 이면 계좌대체가 막힌다(D-3-2). 발행·말소는 pause 로만 막는다.
    bool public circulationActive;

    mapping(address => uint256) private _balances;
    mapping(address => Account) private _accounts;
    /// @dev 기관 키 주소 → 기관 ID. 계좌 등록·처분제한·계좌대체의 기관 일치 검사(B-2-2)에 쓴다.
    mapping(address => string) private _agentInstitution;

    event Issued(address indexed account, uint256 amount);
    event Redeemed(address indexed account, uint256 amount);
    event Transferred(address indexed from, address indexed to, uint256 amount, address indexed agent);
    event AccountRegistered(address indexed account, string institutionId);
    event AccountRestrictionChanged(address indexed account, bool restricted);
    event CirculationChanged(bool active);
    event AgentInstitutionSet(address indexed agent, string institutionId);

    error ZeroAddress();
    error ZeroAmount();
    error EmptyInstitution();
    error AccountNotRegistered(address account);
    error AccountAlreadyRegistered(address account);
    error AccountRestricted(address account);
    error InstitutionMismatch(address agent, address account);
    error CirculationHalted();
    error InsufficientBalance(address account, uint256 balance, uint256 amount);
    error SameAccount(address account);

    /// @param name_ 종목명
    /// @param symbol_ 종목 코드
    /// @param admin 플랫폼 CONTRACT_ADMIN 키 주소(DEFAULT_ADMIN_ROLE)
    constructor(string memory name_, string memory symbol_, address admin) {
        if (admin == address(0)) revert ZeroAddress();
        name = name_;
        symbol = symbol_;
        circulationActive = true;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice 소수 자리는 0이다.
    function decimals() external pure returns (uint8) {
        return 0;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function accountOf(address account) external view returns (Account memory) {
        return _accounts[account];
    }

    function agentInstitution(address agent) external view returns (string memory) {
        return _agentInstitution[agent];
    }

    // ---- 관리(DEFAULT_ADMIN_ROLE) ----

    /// @notice 기관 키 주소와 기관을 대응시킨다(설계서 10.2, D-17). 빈 값이면 대응을 지운다.
    function setAgentInstitution(address agent, string calldata institutionId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (agent == address(0)) revert ZeroAddress();
        _agentInstitution[agent] = institutionId;
        emit AgentInstitutionSet(agent, institutionId);
    }

    // ---- 발행·말소(ISSUER_ROLE) ----

    function issue(address account, uint256 amount) external onlyRole(ISSUER_ROLE) whenNotPaused {
        if (amount == 0) revert ZeroAmount();
        _requireRegistered(account);
        totalSupply += amount;
        _balances[account] += amount;
        emit Issued(account, amount);
    }

    function redeem(address account, uint256 amount) external onlyRole(ISSUER_ROLE) whenNotPaused {
        if (amount == 0) revert ZeroAmount();
        _requireRegistered(account);
        uint256 bal = _balances[account];
        if (bal < amount) revert InsufficientBalance(account, bal, amount);
        unchecked {
            _balances[account] = bal - amount;
            totalSupply -= amount;
        }
        emit Redeemed(account, amount);
    }

    // ---- 계좌관리(TRANSFER_AGENT_ROLE) ----

    /// @notice 계좌를 등록한다. 호출 키의 기관과 같은 기관의 계좌만 등록할 수 있다.
    function registerAccount(address account, string calldata institutionId) external onlyRole(TRANSFER_AGENT_ROLE) {
        if (account == address(0)) revert ZeroAddress();
        if (bytes(institutionId).length == 0) revert EmptyInstitution();
        if (_accounts[account].registered) revert AccountAlreadyRegistered(account);
        if (!_sameString(_agentInstitution[msg.sender], institutionId)) revert InstitutionMismatch(msg.sender, account);
        _accounts[account] = Account({registered: true, restricted: false, institutionId: institutionId});
        emit AccountRegistered(account, institutionId);
    }

    /// @notice 처분제한을 걸거나 푼다. 계좌의 기관과 호출 키의 기관이 같아야 한다.
    function setAccountRestricted(address account, bool restricted) external onlyRole(TRANSFER_AGENT_ROLE) {
        _requireRegistered(account);
        _requireSameInstitution(account);
        _accounts[account].restricted = restricted;
        emit AccountRestrictionChanged(account, restricted);
    }

    /// @notice 계좌대체. 호출 키의 기관이 출고 계좌의 기관과 같아야 한다(B-2-2).
    function transferByAgent(address from, address to, uint256 amount) external onlyRole(TRANSFER_AGENT_ROLE) whenNotPaused {
        if (!circulationActive) revert CirculationHalted();
        if (amount == 0) revert ZeroAmount();
        if (from == to) revert SameAccount(from);
        _requireRegistered(from);
        _requireRegistered(to);
        _requireSameInstitution(from);
        if (_accounts[from].restricted) revert AccountRestricted(from);
        uint256 bal = _balances[from];
        if (bal < amount) revert InsufficientBalance(from, bal, amount);
        unchecked {
            _balances[from] = bal - amount;
        }
        _balances[to] += amount;
        emit Transferred(from, to, amount, msg.sender);
    }

    // ---- 비상 통제(CONTROLLER_ROLE) ----

    function setCirculation(bool active) external onlyRole(CONTROLLER_ROLE) {
        circulationActive = active;
        emit CirculationChanged(active);
    }

    function pause() external onlyRole(CONTROLLER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(CONTROLLER_ROLE) {
        _unpause();
    }

    // ---- 내부 ----

    function _requireRegistered(address account) private view {
        if (!_accounts[account].registered) revert AccountNotRegistered(account);
    }

    function _requireSameInstitution(address account) private view {
        string storage agentInst = _agentInstitution[msg.sender];
        if (bytes(agentInst).length == 0 || !_sameString(agentInst, _accounts[account].institutionId)) {
            revert InstitutionMismatch(msg.sender, account);
        }
    }

    function _sameString(string memory a, string memory b) private pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
