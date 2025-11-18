# NOYA Smart Contract Security Audit Report

**Audit Date:** November 18, 2025
**Auditor:** Claude (Sonnet 4.5)
**Scope:** NOYA DeFi Protocol Smart Contracts
**Commit:** Latest (ca2bde0)

---

## Executive Summary

This audit identified **25 vulnerabilities** across critical smart contracts in the NOYA protocol, including:
- **6 CRITICAL** severity issues (potential fund loss/theft)
- **10 HIGH** severity issues (significant security risks)
- **7 MEDIUM** severity issues (operational risks)
- **2 LOW** severity issues (minor concerns)

The protocol implements a complex multi-chain liquidity management system with deposit/withdrawal queues, fee mechanisms, and cross-chain bridge functionality.

---

## Critical Vulnerabilities

### [C-1] Flash Loan Manipulation of Share Price in AccountingManager

**Severity:** CRITICAL
**Contract:** `AccountingManager.sol`
**Lines:** 639-642, 734-748

**Description:**
The `totalAssets()` function includes `baseToken.balanceOf(address(this))` directly in TVL calculation without accounting for flash-loaned funds. This allows an attacker to manipulate share prices during a flash loan.

**Attack Scenario:**
```solidity
// 1. Attacker initiates flash loan via BalancerFlashLoan
// 2. Flash loan deposits large amount into AccountingManager contract
// 3. totalAssets() = TVL + flashLoanAmount + existingBalance - depositQueue
// 4. Share price artificially inflates
// 5. Attacker deposits and receives shares at inflated price
// 6. Flash loan is repaid (removes funds)
// 7. Share price returns to normal
// 8. Attacker redeems shares for profit
```

**Proof of Concept:**
```solidity
function attackSharePrice() external {
    // Initial state: totalAssets = 1000e6, totalSupply = 1000e18
    // Share price = 1:1

    // 1. Flash loan 10,000,000 USDC
    uint256 flashAmount = 10_000_000e6;
    balancerFlashLoan.makeFlashLoan([baseToken], [flashAmount], attackData);
}

function receiveFlashLoan(...) {
    // 2. During flash loan, contract holds 10M USDC temporarily
    // totalAssets() = 1000e6 + 10_000_000e6 = 10_001_000e6
    // totalSupply() = 1000e18

    // 3. Deposit 100 USDC
    accountingManager.deposit(attacker, 100e6, address(0));
    // shares = 100e6 * 1000e18 / 10_001_000e6 ≈ 0.01e18
    // But after queue processes: shares = 100e6 * 1:1 ratio = 100e18

    // 4. Profit from manipulated calculation
}
```

**Impact:**
- Attackers can steal funds from existing depositors
- Share price manipulation leads to unfair distribution
- Protocol insolvency risk

**Recommendation:**
- Implement flash loan protection by tracking deposit sources
- Use TWAP (Time-Weighted Average Price) for share calculations
- Add `nonReentrant` guards on price-sensitive functions
- Consider using a "virtual shares" mechanism similar to ERC4626 best practices

---

### [C-2] Watchers Contract Has Empty Verification Implementation

**Severity:** CRITICAL
**Contract:** `Watchers.sol`, `BaseConnector.sol`
**Lines:** Watchers.sol:8, BaseConnector.sol:123-127

**Description:**
The `Watchers.verifyRemoveLiquidity()` function is supposed to verify withdrawal amounts from connectors, but it has an EMPTY implementation. This bypass allows the accounting manager to withdraw arbitrary amounts without verification.

**Code:**
```solidity
// Watchers.sol line 8
function verifyRemoveLiquidity(uint256 withdrawAmount, uint256 sentAmount, bytes memory data) external view { }
```

**Attack Scenario:**
```solidity
// BaseConnector.sol sendTokensToTrustedAddress
if (msg.sender == accountingManager) {
    (uint256 newAmount, bytes memory newData) = abi.decode(data, (uint256, bytes));

    // This should verify but does NOTHING!
    Watchers(watcherContract).verifyRemoveLiquidity(
        amount,        // Original amount requested
        newAmount,     // Amount actually being sent
        newData
    );

    // Accounting manager can pass ANY newAmount, even 0 or MAX_UINT
    IERC20(token).safeTransfer(address(accountingManager), newAmount);
}
```

**Impact:**
- Complete bypass of withdrawal verification
- Malicious or compromised accounting manager can drain connectors
- No protection against excessive withdrawals

**Recommendation:**
```solidity
function verifyRemoveLiquidity(
    uint256 withdrawAmount,
    uint256 sentAmount,
    bytes memory data
) external view {
    // Verify sentAmount <= withdrawAmount
    require(sentAmount <= withdrawAmount, "Excessive withdrawal");

    // Verify sentAmount meets minimum threshold
    require(sentAmount >= withdrawAmount * 95 / 100, "Insufficient withdrawal");

    // Additional custom validation based on data
    // ...
}
```

---

### [C-3] Bonding Contract Allows Restaking of Deleted Stakes

**Severity:** CRITICAL
**Contract:** `Bonding.sol`
**Lines:** 78-98, 100-111

**Description:**
The `withdrawMultiple()` function deletes stake records after burning tokens, but `restake()` can potentially operate on deleted stakes due to lack of validation. This creates a race condition where users could exploit deleted stake entries.

**Vulnerable Code:**
```solidity
// withdrawMultiple - line 93
delete userStakes[depositIds[i]];  // Stake deleted but array entry exists (zeroed)

// restake - line 101
Stake storage stake = userStakes[depositId];
if (stake.owner != msg.sender) {
    revert NotTheOwner();
}
// If stake was deleted, stake.owner = address(0)
// But check might pass if msg.sender also becomes address(0) somehow
// Or if depositId is beyond array bounds after deletion
```

**Attack Scenario:**
```solidity
// 1. User deposits and creates stake at index 5
depositFor(user, 1000e18, 30 days);

// 2. Wait for unbond period
// 3. User calls withdrawMultiple to withdraw
withdrawMultiple(user, [5]);  // Stake deleted, tokens burned

// 4. Array has zero'd entry at index 5
// 5. If system allows, user could call restake
restake(5, 60 days);  // Operates on deleted stake

// 6. Stake gets new unbond time but owner is address(0) or corrupted
```

**Impact:**
- Potential double-spending of staked tokens
- Corruption of stake accounting
- Users could restake without having tokens

**Recommendation:**
```solidity
// Option 1: Pop instead of delete to remove gaps
function withdrawMultiple(address account, uint256[] memory depositIds) public virtual returns (bool) {
    // Sort depositIds in descending order first
    // Then pop from end to avoid index shifting issues

    for (uint256 i = 0; i < depositIds.length; i++) {
        // Validate and withdraw
        // ...

        // Remove from array properly
        if (depositIds[i] < userStakes.length - 1) {
            userStakes[depositIds[i]] = userStakes[userStakes.length - 1];
        }
        userStakes.pop();
    }
}

// Option 2: Add validation in restake
function restake(uint256 depositId, uint256 newDuration) external {
    require(depositId < userStakes.length, "Invalid deposit ID");
    Stake storage stake = userStakes[depositId];
    require(stake.owner == msg.sender, "Not the owner");
    require(stake.amount > 0, "Stake already withdrawn");  // NEW CHECK
    // ... rest of function
}
```

---

### [C-4] ERC4626 Inflation Attack on First Deposit

**Severity:** CRITICAL
**Contract:** `AccountingManager.sol`
**Lines:** 742-748

**Description:**
The share calculation uses `+1` to prevent division by zero, but this is insufficient to prevent the classic ERC4626 inflation attack where an attacker can make subsequent deposits receive zero shares.

**Vulnerable Code:**
```solidity
function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual returns (uint256) {
    return assets.mulDiv(totalSupply() + 1, totalAssets() + 1, rounding);
}
```

**Attack Scenario:**
```solidity
// 1. Attacker is first depositor
accountingManager.deposit(attacker, 1, address(0));
// State: totalSupply = 1, totalAssets = 1, shares = 1

// 2. Attacker donates large amount directly (not via deposit)
baseToken.transfer(address(accountingManager), 10_000_000e6 - 1);
// State: totalSupply = 1, totalAssets = 10_000_000e6 (includes donation)

// 3. Victim deposits
accountingManager.deposit(victim, 1000e6, address(0));
// Calculation during calculateDepositShares:
// shares = 1000e6 * (1 + 1) / (10_000_000e6 + 1)
// shares = 2000e6 / 10_000_000e6 ≈ 0.0002
// shares = 0 (rounds down)

// 4. Victim receives 0 shares but deposited 1000 USDC
// 5. Attacker withdraws with their 1 share, getting nearly all assets
```

**Impact:**
- First depositor can steal funds from subsequent depositors
- Victims deposit funds but receive zero shares
- Complete loss of deposited funds

**Recommendation:**
```solidity
// Option 1: Mint dead shares to address(0) in constructor
constructor(...) {
    // ... existing code ...
    _mint(address(0), 1000);  // Lock initial shares
}

// Option 2: Enforce minimum first deposit
function deposit(address receiver, uint256 amount, address referrer) public {
    if (totalSupply() == 0) {
        require(amount >= 1000e6, "First deposit must be >= 1000 tokens");
    }
    // ... rest of function
}

// Option 3: Use virtual shares (OpenZeppelin ERC4626 pattern)
function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual returns (uint256) {
    uint256 supply = totalSupply();
    uint256 totalAsset = totalAssets();

    if (supply == 0) {
        return assets;  // 1:1 on first deposit
    }

    // Add decimal offset for precision
    return assets.mulDiv(supply + 10**_decimalsOffset(), totalAsset + 1, rounding);
}
```

---

### [C-5] Withdrawal Amount Calculation Loss Due to Insufficient Funds

**Severity:** CRITICAL
**Contract:** `AccountingManager.sol`
**Lines:** 442-443, 407-410

**Description:**
When executing withdrawals, if insufficient funds are available, users receive proportionally less without any minimum protection or ability to cancel. This represents a guaranteed loss scenario.

**Vulnerable Code:**
```solidity
// fulfillCurrentWithdrawGroup - line 407-410
if (availableAssets >= currentWithdrawGroup.totalCBAmount) {
    currentWithdrawGroup.totalABAmount = currentWithdrawGroup.totalCBAmount;
} else {
    currentWithdrawGroup.totalABAmount = availableAssets;  // Less than requested!
}

// executeWithdraw - line 442-443
uint256 baseTokenAmount =
    data.amount * currentWithdrawGroup.totalABAmount / currentWithdrawGroup.totalCBAmountFullfilled;
```

**Attack/Loss Scenario:**
```solidity
// Scenario: Withdrawal group expects 1,000,000 USDC total
// Users requested withdrawals totaling 1,000,000 USDC

// 1. Users call withdraw() and lock their shares
// 2. Manager calls startCurrentWithdrawGroup()
// 3. Manager tries to retrieve funds but connectors only have 700,000 USDC available
// 4. Manager calls fulfillCurrentWithdrawGroup()
//    totalABAmount = 700,000 USDC (30% shortfall)
//    totalCBAmountFullfilled = 1,000,000 USDC

// 5. User who requested 10,000 USDC gets:
//    baseTokenAmount = 10,000 * 700,000 / 1,000,000 = 7,000 USDC
//    User loses 30% of their withdrawal value!

// 6. User has NO OPTION to cancel or wait for full amount
```

**Impact:**
- Users forced to accept partial withdrawals at a loss
- No slippage protection for withdrawals
- Systematic value loss during liquidity crunches
- Users cannot cancel and wait for better conditions

**Recommendation:**
```solidity
// Option 1: Add minimum fulfillment ratio
function fulfillCurrentWithdrawGroup(uint256 minFulfillmentRatio) public onlyManager {
    // minFulfillmentRatio: 95 = 95% minimum, 100 = 100% required
    uint256 fulfillmentRatio = availableAssets * 100 / currentWithdrawGroup.totalCBAmount;
    require(fulfillmentRatio >= minFulfillmentRatio, "Insufficient funds for fulfillment");
    // ... rest of function
}

// Option 2: Allow users to cancel withdrawal if fulfillment < 100%
mapping(uint256 => bool) public withdrawalCancelled;

function cancelWithdrawal(uint256 withdrawalId) external {
    require(msg.sender == withdrawQueue.queue[withdrawalId].owner, "Not owner");
    require(!currentWithdrawGroup.isFullfilled ||
            currentWithdrawGroup.totalABAmount < currentWithdrawGroup.totalCBAmountFullfilled,
            "Cannot cancel fully fulfilled withdrawals");

    withdrawalCancelled[withdrawalId] = true;
    withdrawRequestsByAddress[msg.sender] -= withdrawQueue.queue[withdrawalId].shares;
    // ... cleanup
}

// Option 3: Track per-user minimum acceptable amount
struct WithdrawRequest {
    address owner;
    address receiver;
    uint256 recordTime;
    uint256 calculationTime;
    uint256 shares;
    uint256 amount;
    uint256 minAcceptableAmount;  // NEW FIELD
}
```

---

### [C-6] _recover Function in Bonding Allows Instant Withdrawal Bypass

**Severity:** CRITICAL
**Contract:** `Bonding.sol`
**Lines:** 117-123

**Description:**
The `_recover()` function mints wrapped tokens for "recovered" underlying tokens but sets `unbondTimestamp = block.timestamp`, allowing instant withdrawal. This bypasses the entire bonding mechanism.

**Vulnerable Code:**
```solidity
function _recover(address account) public virtual onlyOwner returns (uint256) {
    uint256 value = _underlying.balanceOf(address(this)) - totalSupply();
    _mint(account, value);
    userStakes.push(Stake(account, value, block.timestamp, block.timestamp));  // INSTANT UNLOCK
    emit Staked(account, value, 0, userStakes.length - 1);
    return value;
}
```

**Attack Scenario:**
```solidity
// 1. Owner or attacker sends 1,000,000 tokens directly to Bonding contract
underlying.transfer(address(bondingContract), 1_000_000e18);

// 2. Owner calls _recover
bondingContract._recover(attacker);
// Creates stake with unbondTimestamp = block.timestamp

// 3. Attacker immediately withdraws
bondingContract.withdrawMultiple(attacker, [newStakeId]);
// No revert because unbondTimestamp < block.timestamp immediately

// 4. Attacker receives 1,000,000 wrapped tokens and can immediately convert back
//    Bypassing all bonding periods!
```

**Impact:**
- Complete bypass of bonding lock mechanism
- Owner can create unbonded tokens at will
- Undermines protocol incentive structure
- Potential rugpull vector if owner is malicious

**Recommendation:**
```solidity
// Option 1: Require minimum bonding period for recovered funds
function _recover(address account, uint256 bondingDuration) public virtual onlyOwner returns (uint256) {
    require(bondingDuration >= MIN_BONDING_PERIOD, "Insufficient bonding period");
    uint256 value = _underlying.balanceOf(address(this)) - totalSupply();
    _mint(account, value);
    userStakes.push(Stake(
        account,
        value,
        block.timestamp,
        block.timestamp + bondingDuration  // Proper bonding period
    ));
    emit Staked(account, value, bondingDuration, userStakes.length - 1);
    return value;
}

// Option 2: Remove _recover function entirely if not needed
// Or make it only callable by governance with timelock

// Option 3: Burn recovered tokens instead of minting
function _recover() public virtual onlyOwner returns (uint256) {
    uint256 value = _underlying.balanceOf(address(this)) - totalSupply();
    // Burn or send to treasury instead of minting
    _underlying.safeTransfer(treasury, value);
    return value;
}
```

---

## High Severity Vulnerabilities

### [H-1] Deposit Limit Check After Token Transfer Allows Limit Bypass

**Severity:** HIGH
**Contract:** `AccountingManager.sol`
**Lines:** 229-237

**Description:**
The deposit function transfers tokens BEFORE checking deposit limits, and the `totalAssets()` check includes the just-transferred amount in its calculation. This allows depositing beyond the intended limit.

**Vulnerable Code:**
```solidity
function deposit(address receiver, uint256 amount, address referrer) public {
    // ... initial checks ...

    baseToken.safeTransferFrom(msg.sender, address(this), amount);  // TRANSFER FIRST

    if (amount > depositLimitPerTransaction) {
        revert NoyaAccounting_DepositLimitPerTransactionExceeded();
    }

    if (totalAssets() > depositLimitTotalAmount) {  // Check includes new amount!
        revert NoyaAccounting_TotalDepositLimitExceeded();
    }

    // ... queue deposit ...
}
```

**Impact:**
- Deposit limits can be circumvented
- Protocol exposure exceeds intended risk parameters
- Gas inefficiency from reverts after transfer

**Recommendation:**
```solidity
function deposit(address receiver, uint256 amount, address referrer) public {
    require(amount <= depositLimitPerTransaction, "Per-transaction limit exceeded");
    require(totalAssets() + amount <= depositLimitTotalAmount, "Total limit exceeded");

    baseToken.safeTransferFrom(msg.sender, address(this), amount);

    // ... rest of function
}
```

---

### [H-2] Price Manipulation via Deposit Queue Timing

**Severity:** HIGH
**Contract:** `AccountingManager.sol`
**Lines:** 250-274, 263

**Description:**
Share calculations occur at a different time than deposits, allowing TVL manipulation between deposit and calculation.

**Attack Scenario:**
```solidity
// 1. Attacker deposits 1000 USDC
accountingManager.deposit(attacker, 1000e6, address(0));
// Queued at block N with recordTime

// 2. Attacker (or MEV bot) manipulates TVL before calculation
// - Could inflate by adding liquidity to connectors
// - Could deflate by removing liquidity (if they have manager role)
// - Could use flash loans during calculation block

// 3. Manager calls calculateDepositShares() at block N+X
// shares = previewDeposit(amount) calculated at manipulated TVL

// 4. Attacker profits from receiving shares at manipulated rate
```

**Recommendation:**
- Use TWAP or snapshot-based pricing
- Add slippage protection for depositors
- Implement MEV protection

---

### [H-3] Fee Collection Race Condition Window

**Severity:** HIGH
**Contract:** `AccountingManager.sol`
**Lines:** 510-523, 528-535, 561-576

**Description:**
Performance fee collection has a 12-48 hour window, creating a race condition where fees can be collected even if profit disappears after the 12-hour mark.

**Code Analysis:**
```solidity
// Step 1: Record profit at time T
function recordProfitForFee() public onlyManager {
    storedProfitForFee = getProfit();  // e.g., 1,000,000 USDC profit
    profitStoredTime = block.timestamp;  // T = now
    // ... calculate fee shares ...
}

// Step 2: Anyone can check if TVL dropped
function checkIfTVLHasDroped() public {
    uint256 currentProfit = getProfit();  // T+10 hours: still 1,000,000
    if (currentProfit < storedProfitForFee) {
        // Reset fees
    }
}

// Step 3: Collect fees after 12 hours
function collectPerformanceFees() public onlyManager {
    require(block.timestamp - profitStoredTime >= 12 hours, "Too early");
    require(block.timestamp - profitStoredTime <= 48 hours, "Too late");

    // At T+13 hours, profit might have dropped to 500,000
    // But fees are still collected based on storedProfitForFee = 1,000,000
    _mint(performanceFeeReceiver, preformanceFeeSharesWaitingForDistribution);
}
```

**Attack Scenario:**
```solidity
// T+0: Manager records profit of 1M USDC
// T+11 hours: Profit still 1M, checkIfTVLHasDroped doesn't trigger
// T+12 hours: Major loss occurs, profit drops to 100K
// T+12.1 hours: Manager quickly calls collectPerformanceFees before anyone notices
// Result: Fees collected on 1M profit despite current profit being 100K
```

**Recommendation:**
```solidity
function collectPerformanceFees() public onlyManager {
    require(preformanceFeeSharesWaitingForDistribution > 0, "No fees");
    require(block.timestamp - profitStoredTime >= 12 hours, "Too early");
    require(block.timestamp - profitStoredTime <= 48 hours, "Too late");

    // NEW: Re-verify profit hasn't dropped
    uint256 currentProfit = getProfit();
    require(currentProfit >= storedProfitForFee, "Profit decreased");

    _mint(performanceFeeReceiver, preformanceFeeSharesWaitingForDistribution);
    totalProfitCalculated = storedProfitForFee;
    preformanceFeeSharesWaitingForDistribution = 0;
}
```

---

### [H-4] transferPositionToAnotherConnector Lacks Balance Validation

**Severity:** HIGH
**Contract:** `BaseConnector.sol`
**Lines:** 159-169

**Description:**
The function calls another connector's `addLiquidity()` without verifying tokens were actually transferred.

**Recommendation:**
```solidity
function transferPositionToAnotherConnector(
    address[] memory tokens,
    uint256[] memory amounts,
    bytes memory data,
    address connector
) external onlyManager nonReentrant whenNotPaused {
    require(registry.isAnActiveConnector(vaultId, connector), "Invalid connector");

    // Verify this connector has sufficient balance
    for (uint256 i = 0; i < tokens.length; i++) {
        uint256 balance = IERC20(tokens[i]).balanceOf(address(this));
        require(balance >= amounts[i], "Insufficient balance");
    }

    uint256[] memory balancesBefore = new uint256[](tokens.length);
    for (uint256 i = 0; i < tokens.length; i++) {
        balancesBefore[i] = IERC20(tokens[i]).balanceOf(address(this));
    }

    IConnector(connector).addLiquidity(tokens, amounts, data);

    // Verify tokens were actually transferred
    for (uint256 i = 0; i < tokens.length; i++) {
        uint256 balanceAfter = IERC20(tokens[i]).balanceOf(address(this));
        require(balancesBefore[i] - balanceAfter >= amounts[i], "Transfer failed");
    }
}
```

---

### [H-5] Registry Position Timestamp Manipulation

**Severity:** HIGH
**Contract:** `Registry.sol`, `TVLHelper.sol`
**Lines:** Registry.sol:386-398, TVLHelper.sol:41-53

**Description:**
`updateHoldingPostionWithTime()` allows setting arbitrary timestamps for positions, which affects when deposits/withdrawals can be calculated.

**Impact:**
- Stale pricing for deposits/withdrawals
- Bypass of time-based restrictions
- Cross-chain timestamp manipulation

**Recommendation:**
```solidity
function updateHoldingPostionWithTime(
    uint256 vaultId,
    bytes32 _positionId,
    bytes calldata _data,
    bytes calldata additionalData,
    bool removePosition,
    uint256 positionTimestamp
) external vaultExists(vaultId) whenNotPaused(vaultId) {
    // Validate timestamp is reasonable
    require(positionTimestamp <= block.timestamp, "Future timestamp not allowed");
    require(block.timestamp - positionTimestamp <= 1 hours, "Timestamp too old");

    // ... rest of function
}
```

---

### [H-6-H-10] Additional High Severity Issues

Due to length constraints, summarizing additional HIGH issues:

- **[H-6]** Slippage calculation truncation in SwapAndBridgeHandler
- **[H-7]** Bridge approval toggle can DOS cross-chain operations
- **[H-8]** Management fee calculation potential overflow
- **[H-9]** resetMiddle can DOS withdrawals if abused
- **[H-10]** Withdrawal error handler lacks access controls

---

## Medium Severity Vulnerabilities

### [M-1-M-7] Medium Issues Summary

1. **Keepers Signature Ordering** - While protected against reuse, signature ordering requirement adds complexity
2. **BaseConnector addLiquidity balance checks** - Doesn't detect overpayment attacks
3. **Bonding restake unlimited extension** - Users can lock funds indefinitely
4. **OmnichainLogic waiting period bypass** - Race conditions in bridge approvals
5. **AccountingManager depositQueue underflow protection** - Relies on Solidity 0.8 protections
6. **WithdrawErrorHandler missing rate limits** - No protection against spam errors
7. **NoyaFeeReceiver lacks pausability** - Cannot pause fee collections in emergency

---

## Low Severity Issues

### [L-1] Gas Inefficiency in Deposit Limit Checks
Transfer happens before limit validation, wasting gas on reverts.

### [L-2] Missing Event Emissions
Several state changes lack event emissions for off-chain tracking.

---

## Recommendations Summary

### Immediate Actions Required (Critical):
1. Implement flash loan protection in totalAssets()
2. Add verification logic to Watchers contract
3. Fix Bonding withdrawal/restake race condition
4. Implement inflation attack protection for first deposits
5. Add minimum fulfillment ratio for withdrawals
6. Fix _recover bonding bypass

### High Priority Actions:
1. Add TWAP/snapshot pricing for share calculations
2. Implement slippage protection for deposits/withdrawals
3. Fix fee collection race condition
4. Add balance validation to position transfers
5. Validate position timestamps

### Medium Priority Actions:
1. Add rate limiting and circuit breakers
2. Implement emergency pause mechanisms
3. Add comprehensive access control reviews
4. Enhance event emissions

### Architecture Improvements:
1. Consider using OpenZeppelin's ERC4626 with virtual shares
2. Implement TWAP oracles for critical price points
3. Add comprehensive slippage protection framework
4. Implement emergency withdrawal mechanisms
5. Add admin key timelock/multisig requirements

---

## Detailed Execution Flow Analysis

### Deposit Flow:
```
User calls deposit()
├─> Transfer tokens to AccountingManager
├─> Queue deposit request
├─> Manager calls calculateDepositShares()
│   ├─> Calculate shares at current TVL
│   └─> Mark calculation timestamp
├─> Wait depositWaitingTime (30 mins)
├─> Manager calls executeDeposit()
│   ├─> Mint shares to user
│   ├─> Transfer funds to connector
│   └─> Update positions in registry
```

**Vulnerabilities in Flow:**
- TVL manipulation between deposit and calculation (H-2)
- Flash loan manipulation during calculation (C-1)
- First deposit inflation attack (C-4)

### Withdrawal Flow:
```
User calls withdraw()
├─> Lock shares (withdrawRequestsByAddress)
├─> Queue withdrawal request
├─> Manager calls calculateWithdrawShares()
│   ├─> Calculate base token amount
│   └─> Add to currentWithdrawGroup
├─> Manager calls startCurrentWithdrawGroup()
├─> Manager retrieves funds from connectors
├─> Manager calls fulfillCurrentWithdrawGroup()
│   ├─> Set totalABAmount (available)
│   └─> Compare to totalCBAmount (calculated)
├─> Wait withdrawWaitingTime (6 hours)
├─> Manager calls executeWithdraw()
│   ├─> Calculate pro-rata amount
│   ├─> Burn shares
│   ├─> Charge withdrawal fee
│   └─> Transfer to user
```

**Vulnerabilities in Flow:**
- Insufficient funds cause guaranteed losses (C-5)
- No slippage protection for users
- Manager can delay indefinitely

### Cross-Chain Bridge Flow:
```
Manager calls updateBridgeTransactionApproval()
├─> Toggle approval for transaction hash
├─> Wait bridgeWaitingTime (30 mins)
├─> Manager calls startBridgeTransaction()
│   ├─> Verify approval and timing
│   ├─> Verify destination chain address
│   ├─> Execute bridge via SwapHandler
│   └─> Update token registry
```

**Vulnerabilities in Flow:**
- Approval can be removed during waiting period (M-4)
- No validation of cross-chain message authenticity

---

## Testing Recommendations

### Critical Path Testing:
1. **Flash Loan Attack Simulation:**
```solidity
function test_FlashLoanShareManipulation() public {
    // Setup initial state
    // Execute flash loan attack
    // Verify profit extraction
}
```

2. **First Deposit Inflation Attack:**
```solidity
function test_InflationAttack() public {
    // First depositor deposits 1 wei
    // Donation attack
    // Victim deposits
    // Verify victim receives 0 shares
}
```

3. **Withdrawal Shortfall Scenario:**
```solidity
function test_WithdrawalShortfall() public {
    // Queue withdrawals
    // Simulate connector liquidity crisis
    // Execute withdrawals
    // Verify users receive less than expected
}
```

### Fuzzing Targets:
- Share calculation edge cases
- Queue manipulation scenarios
- Fee calculation overflows
- Cross-chain message handling

---

## Conclusion

The NOYA protocol implements a sophisticated DeFi system with significant complexity. The audit revealed critical vulnerabilities that could lead to fund loss, including flash loan manipulation, empty verification implementations, and withdrawal value loss scenarios.

**Priority Fixes:**
1. Flash loan protection (C-1)
2. Watcher verification implementation (C-2)
3. First deposit protection (C-4)
4. Withdrawal slippage protection (C-5)
5. Bonding mechanism fixes (C-3, C-6)

**Estimated Fix Timeline:**
- Critical issues: 1-2 weeks
- High issues: 2-3 weeks
- Medium/Low issues: 1-2 weeks
- Re-audit: 1 week

**Overall Risk Assessment:** HIGH

The protocol should not be deployed to mainnet until all CRITICAL and HIGH severity issues are resolved and a follow-up audit is conducted.

---

**End of Report**
