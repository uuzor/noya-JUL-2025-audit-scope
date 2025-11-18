# NOYA Protocol - Security Improvements & Architectural Recommendations

This document provides detailed recommendations for improving the security, efficiency, and robustness of the NOYA protocol based on the comprehensive audit findings.

---

## Table of Contents

1. [Critical Security Patches](#critical-security-patches)
2. [Architecture Improvements](#architecture-improvements)
3. [Code Quality Enhancements](#code-quality-enhancements)
4. [Gas Optimizations](#gas-optimizations)
5. [Monitoring & Circuit Breakers](#monitoring--circuit-breakers)
6. [Testing Enhancements](#testing-enhancements)
7. [Documentation Improvements](#documentation-improvements)

---

## Critical Security Patches

### 1. Flash Loan Protection for Share Price

**Current Issue:** totalAssets() includes flash-loaned funds, allowing price manipulation.

**Recommended Fix:**

```solidity
// AccountingManager.sol

// Add state variable to track legitimate deposits
uint256 public legitimateAssets;

// Track in-flight flash loans
mapping(address => bool) public isFlashLoanActive;

// Modifier to prevent flash loan manipulation
modifier noFlashLoan() {
    require(!isFlashLoanActive[tx.origin], "Flash loan detected");
    _;
}

// Updated totalAssets function
function totalAssets() public view returns (uint256) {
    // Use tracked legitimate assets instead of raw balance
    return TVLHelper.getTVL(vaultId, registry, address(baseToken)) +
           legitimateAssets -
           depositQueue.totalAWFDeposit;
}

// Update deposit to track legitimate assets
function deposit(address receiver, uint256 amount, address referrer)
    public
    nonReentrant
    whenNotPaused
    noFlashLoan
{
    // ... existing checks ...

    baseToken.safeTransferFrom(msg.sender, address(this), amount);
    legitimateAssets += amount; // Track legitimate deposit

    // ... rest of function ...
}

// Update withdraw to track legitimate assets
function executeWithdraw(uint256 maxIterations)
    public
    onlyManager
    nonReentrant
    whenNotPaused
{
    // ... existing logic ...

    legitimateAssets -= processedBaseTokenAmount; // Update tracked assets

    // ... rest of function ...
}
```

**Additional Protection - TWAP Integration:**

```solidity
// Add TWAP oracle for share price
ITWAPOracle public twapOracle;

struct PriceObservation {
    uint256 timestamp;
    uint256 pricePerShare;
}

PriceObservation[] public priceObservations;
uint256 public constant OBSERVATION_INTERVAL = 10 minutes;
uint256 public constant MAX_OBSERVATIONS = 144; // 24 hours

function updatePriceObservation() external {
    require(
        block.timestamp >= priceObservations[priceObservations.length - 1].timestamp + OBSERVATION_INTERVAL,
        "Too soon"
    );

    uint256 currentPrice = totalAssets() * 1e18 / totalSupply();

    if (priceObservations.length >= MAX_OBSERVATIONS) {
        // Shift array and update last element
        for (uint256 i = 0; i < MAX_OBSERVATIONS - 1; i++) {
            priceObservations[i] = priceObservations[i + 1];
        }
        priceObservations[MAX_OBSERVATIONS - 1] = PriceObservation(block.timestamp, currentPrice);
    } else {
        priceObservations.push(PriceObservation(block.timestamp, currentPrice));
    }
}

function getTWAPPrice() public view returns (uint256) {
    require(priceObservations.length > 0, "No observations");

    uint256 sum = 0;
    for (uint256 i = 0; i < priceObservations.length; i++) {
        sum += priceObservations[i].pricePerShare;
    }

    return sum / priceObservations.length;
}

// Use TWAP for share calculations
function _convertToShares(uint256 assets, Math.Rounding rounding)
    internal
    view
    returns (uint256)
{
    uint256 supply = totalSupply();
    if (supply == 0) return assets;

    // Use TWAP price instead of current price for large deposits
    if (assets > depositLimitPerTransaction / 10) {
        uint256 twapPrice = getTWAPPrice();
        return assets.mulDiv(1e18, twapPrice, rounding);
    }

    return assets.mulDiv(supply + 1, totalAssets() + 1, rounding);
}
```

---

### 2. First Deposit Inflation Attack Prevention

**Recommended Fix - Virtual Shares:**

```solidity
// AccountingManager.sol

uint8 private constant _DECIMALS_OFFSET = 3;

constructor(AccountingManagerConstructorParams memory p) {
    // ... existing code ...

    // Mint virtual shares to dead address
    _mint(address(0xdead), 10 ** (_DECIMALS_OFFSET + decimals()));
}

function _convertToShares(uint256 assets, Math.Rounding rounding)
    internal
    view
    virtual
    returns (uint256)
{
    uint256 supply = totalSupply();
    uint256 totalAsset = totalAssets();

    // Virtual shares mechanism
    return assets.mulDiv(
        supply + 10 ** _DECIMALS_OFFSET,
        totalAsset + 1,
        rounding
    );
}

function _convertToAssets(uint256 shares, Math.Rounding rounding)
    internal
    view
    virtual
    returns (uint256)
{
    uint256 supply = totalSupply();
    uint256 totalAsset = totalAssets();

    return shares.mulDiv(
        totalAsset + 1,
        supply + 10 ** _DECIMALS_OFFSET,
        rounding
    );
}
```

**Alternative - Minimum First Deposit:**

```solidity
// AccountingManager.sol

uint256 public constant MINIMUM_FIRST_DEPOSIT = 1000e6; // 1000 USDC minimum

function deposit(address receiver, uint256 amount, address referrer)
    public
    nonReentrant
    whenNotPaused
{
    // Enforce minimum first deposit
    if (totalSupply() == 0) {
        require(amount >= MINIMUM_FIRST_DEPOSIT, "First deposit too small");
    }

    // ... rest of function ...
}
```

---

### 3. Watcher Verification Implementation

**Critical Fix for Empty Verification:**

```solidity
// Watchers.sol

// Add state variables for verification parameters
mapping(address => VerificationConfig) public verificationConfigs;

struct VerificationConfig {
    uint256 maxSlippageBps; // Max allowed slippage in basis points
    uint256 minWithdrawalRatio; // Minimum ratio of sent/requested (95% = 9500)
    bool strictMode; // If true, require exact amount
}

constructor(address[] memory _owners, uint8 _threshold)
    Keepers(_owners, _threshold)
{
    // Set default verification parameters
    // Can be updated per connector
}

function setVerificationConfig(
    address connector,
    uint256 maxSlippageBps,
    uint256 minWithdrawalRatio,
    bool strictMode
) external onlyOwner {
    require(minWithdrawalRatio <= 10000, "Invalid ratio");
    require(maxSlippageBps <= 1000, "Slippage too high");

    verificationConfigs[connector] = VerificationConfig({
        maxSlippageBps: maxSlippageBps,
        minWithdrawalRatio: minWithdrawalRatio,
        strictMode: strictMode
    });
}

function verifyRemoveLiquidity(
    uint256 withdrawAmount,
    uint256 sentAmount,
    bytes memory data
) external view {
    address connector = msg.sender;
    VerificationConfig memory config = verificationConfigs[connector];

    // Default config if not set
    if (config.maxSlippageBps == 0) {
        config.maxSlippageBps = 500; // 5% max slippage
        config.minWithdrawalRatio = 9500; // 95% minimum
        config.strictMode = false;
    }

    // Verify sent amount is not zero
    require(sentAmount > 0, "Cannot send zero");

    // Verify sent amount doesn't exceed requested
    require(sentAmount <= withdrawAmount, "Sent exceeds requested");

    if (config.strictMode) {
        // In strict mode, must send exact amount
        require(sentAmount == withdrawAmount, "Exact amount required");
    } else {
        // Verify minimum ratio
        uint256 ratio = (sentAmount * 10000) / withdrawAmount;
        require(ratio >= config.minWithdrawalRatio, "Insufficient withdrawal");
    }

    // Additional verification based on data
    if (data.length > 0) {
        (uint256 expectedMinimum, address token) = abi.decode(data, (uint256, address));
        require(sentAmount >= expectedMinimum, "Below expected minimum");
    }

    emit WithdrawalVerified(connector, withdrawAmount, sentAmount);
}

event WithdrawalVerified(address indexed connector, uint256 requested, uint256 sent);
```

---

### 4. Withdrawal Slippage Protection

**Recommended Implementation:**

```solidity
// AccountingManager.sol

struct WithdrawRequest {
    address owner;
    address receiver;
    uint256 recordTime;
    uint256 calculationTime;
    uint256 shares;
    uint256 amount;
    uint256 minAcceptableAmount; // NEW: User-specified minimum
    bool cancelled; // NEW: Cancellation flag
}

function withdraw(
    uint256 share,
    address receiver,
    uint256 minAcceptableAmount // NEW PARAMETER
) public nonReentrant whenNotPaused {
    require(share > minWithdrawalAmount, "Amount too small");
    require(balanceOf(msg.sender) >= share + withdrawRequestsByAddress[msg.sender], "Insufficient balance");

    withdrawRequestsByAddress[msg.sender] += share;

    withdrawQueue.queue[withdrawQueue.last] = WithdrawRequest({
        owner: msg.sender,
        receiver: receiver,
        recordTime: block.timestamp,
        calculationTime: 0,
        shares: share,
        amount: 0,
        minAcceptableAmount: minAcceptableAmount,
        cancelled: false
    });

    emit RecordWithdraw(withdrawQueue.last, msg.sender, receiver, share, block.timestamp);
    withdrawQueue.last += 1;
}

function cancelWithdrawal(uint256 withdrawalId) external nonReentrant {
    WithdrawRequest storage request = withdrawQueue.queue[withdrawalId];

    require(request.owner == msg.sender, "Not owner");
    require(!request.cancelled, "Already cancelled");
    require(
        currentWithdrawGroup.isFullfilled == false ||
        currentWithdrawGroup.totalABAmount < currentWithdrawGroup.totalCBAmountFullfilled,
        "Cannot cancel fulfilled withdrawal"
    );

    request.cancelled = true;
    withdrawRequestsByAddress[msg.sender] -= request.shares;

    emit WithdrawalCancelled(withdrawalId, msg.sender, request.shares);
}

function executeWithdraw(uint256 maxIterations) public onlyManager nonReentrant whenNotPaused {
    require(currentWithdrawGroup.isFullfilled, "Group not fulfilled");

    uint64 i = 0;
    uint256 firstTemp = withdrawQueue.first;
    uint256 withdrawFeeAmount = 0;
    uint256 processedBaseTokenAmount = 0;

    while (
        currentWithdrawGroup.lastId > firstTemp &&
        withdrawQueue.queue[firstTemp].calculationTime + withdrawWaitingTime <= block.timestamp &&
        i < maxIterations
    ) {
        i += 1;
        WithdrawRequest memory data = withdrawQueue.queue[firstTemp];

        // Skip cancelled withdrawals
        if (data.cancelled) {
            delete withdrawQueue.queue[firstTemp];
            firstTemp += 1;
            continue;
        }

        uint256 shares = data.shares;
        uint256 baseTokenAmount =
            data.amount * currentWithdrawGroup.totalABAmount / currentWithdrawGroup.totalCBAmountFullfilled;

        // NEW: Check minimum acceptable amount
        if (baseTokenAmount < data.minAcceptableAmount) {
            // User's minimum not met, refund shares and skip
            withdrawRequestsByAddress[data.owner] -= shares;
            delete withdrawQueue.queue[firstTemp];
            firstTemp += 1;

            emit WithdrawalBelowMinimum(firstTemp, data.owner, baseTokenAmount, data.minAcceptableAmount);
            continue;
        }

        // ... rest of existing execution logic ...
    }

    // ... rest of function ...
}

event WithdrawalCancelled(uint256 indexed withdrawalId, address indexed owner, uint256 shares);
event WithdrawalBelowMinimum(uint256 indexed withdrawalId, address indexed owner, uint256 actual, uint256 minimum);
```

---

### 5. Bonding Contract Fixes

**Fix for Deletion Race Condition:**

```solidity
// Bonding.sol

struct Stake {
    address owner;
    uint256 amount;
    uint256 startTimestamp;
    uint256 unbondTimestamp;
    bool withdrawn; // NEW: Track withdrawal status
}

function withdrawMultiple(address account, uint256[] memory depositIds)
    public
    virtual
    returns (bool)
{
    require(account == _msgSender(), "Not the owner");

    uint256 value = 0;
    for (uint256 i = 0; i < depositIds.length; i++) {
        require(depositIds[i] < userStakes.length, "Invalid deposit ID");
        Stake storage stake = userStakes[depositIds[i]];

        require(stake.owner == account, "Not the owner");
        require(!stake.withdrawn, "Already withdrawn");
        require(stake.unbondTimestamp < block.timestamp, "Bonding not finished");

        value += stake.amount;
        stake.withdrawn = true; // Mark as withdrawn instead of deleting

        emit Unbonded(account, stake.amount, depositIds[i]);
    }

    _burn(account, value);
    SafeERC20.safeTransfer(_underlying, account, value);
    return true;
}

function restake(uint256 depositId, uint256 newDuration) external {
    require(depositId < userStakes.length, "Invalid deposit ID");
    Stake storage stake = userStakes[depositId];

    require(stake.owner == msg.sender, "Not the owner");
    require(!stake.withdrawn, "Already withdrawn"); // NEW CHECK
    require(stake.unbondTimestamp < block.timestamp, "Bonding not finished");
    require(newDuration > 0 && newDuration <= maxBondingDuration, "Invalid duration");

    stake.unbondTimestamp = block.timestamp + newDuration;

    emit Restaked(msg.sender, stake.amount, newDuration, depositId);
}

function _recover(address account, uint256 bondingDuration)
    public
    virtual
    onlyOwner
    returns (uint256)
{
    require(bondingDuration >= 30 days, "Minimum bonding period required");
    require(bondingDuration <= maxBondingDuration, "Exceeds max bonding");

    uint256 value = _underlying.balanceOf(address(this)) - totalSupply();
    _mint(account, value);

    userStakes.push(Stake({
        owner: account,
        amount: value,
        startTimestamp: block.timestamp,
        unbondTimestamp: block.timestamp + bondingDuration,
        withdrawn: false
    }));

    emit Staked(account, value, bondingDuration, userStakes.length - 1);
    return value;
}
```

---

## Architecture Improvements

### 1. Separation of Concerns

**Current Issue:** AccountingManager handles too many responsibilities.

**Recommended Architecture:**

```
AccountingManager (ERC20 + Core Accounting)
├── DepositQueue (Deposit queue management)
├── WithdrawalQueue (Withdrawal queue management)
├── FeeManager (Fee calculations and distribution)
└── PositionManager (TVL and position tracking)
```

**Implementation:**

```solidity
// DepositQueue.sol
library DepositQueue {
    struct Queue {
        mapping(uint256 => DepositRequest) queue;
        uint256 first;
        uint256 middle;
        uint256 last;
        uint256 totalAWFDeposit;
    }

    function add(Queue storage q, DepositRequest memory request) internal {
        q.queue[q.last] = request;
        q.last += 1;
        q.totalAWFDeposit += request.amount;
    }

    function calculateShares(
        Queue storage q,
        uint256 maxIterations,
        function(uint256) view returns (uint256) previewDeposit,
        uint256 oldestUpdateTime
    ) internal returns (uint256 processed) {
        // ... calculation logic ...
    }

    // ... other queue operations ...
}

// FeeManager.sol
library FeeManager {
    struct FeeConfig {
        uint256 withdrawFee;
        uint256 performanceFee;
        uint256 managementFee;
        address withdrawFeeReceiver;
        address performanceFeeReceiver;
        address managementFeeReceiver;
    }

    function calculateManagementFee(
        FeeConfig memory config,
        uint256 totalShares,
        uint256 timePassed
    ) internal pure returns (uint256) {
        // ... fee calculation ...
    }

    // ... other fee operations ...
}
```

---

### 2. Circuit Breakers & Emergency Controls

**Recommended Implementation:**

```solidity
// CircuitBreaker.sol
contract CircuitBreaker {
    enum CircuitState { CLOSED, OPEN, HALF_OPEN }

    struct CircuitConfig {
        uint256 threshold; // Error threshold
        uint256 cooldownPeriod; // Cooldown before half-open
        uint256 testPeriod; // Test period in half-open
        uint256 consecutiveSuccesses; // Required successes to close
    }

    mapping(bytes32 => CircuitState) public circuits;
    mapping(bytes32 => uint256) public errorCounts;
    mapping(bytes32 => uint256) public lastErrorTime;
    mapping(bytes32 => CircuitConfig) public configs;

    function checkCircuit(bytes32 circuitId) external view returns (bool allowed) {
        CircuitState state = circuits[circuitId];

        if (state == CircuitState.OPEN) {
            CircuitConfig memory config = configs[circuitId];
            if (block.timestamp >= lastErrorTime[circuitId] + config.cooldownPeriod) {
                return true; // Move to HALF_OPEN
            }
            return false;
        }

        return true;
    }

    function recordSuccess(bytes32 circuitId) external {
        if (circuits[circuitId] == CircuitState.HALF_OPEN) {
            // ... transition logic ...
        }
    }

    function recordError(bytes32 circuitId) external {
        errorCounts[circuitId]++;

        if (errorCounts[circuitId] >= configs[circuitId].threshold) {
            circuits[circuitId] = CircuitState.OPEN;
            lastErrorTime[circuitId] = block.timestamp;
        }
    }
}

// Integration in AccountingManager
contract AccountingManager {
    CircuitBreaker public circuitBreaker;

    modifier circuitCheck(bytes32 operation) {
        require(circuitBreaker.checkCircuit(operation), "Circuit open");
        _;
    }

    function executeDeposit(...) public circuitCheck(keccak256("DEPOSIT")) {
        try {
            // ... execution ...
            circuitBreaker.recordSuccess(keccak256("DEPOSIT"));
        } catch {
            circuitBreaker.recordError(keccak256("DEPOSIT"));
            revert();
        }
    }
}
```

---

### 3. Rate Limiting

**Implementation:**

```solidity
// RateLimiter.sol
library RateLimiter {
    struct RateLimit {
        uint256 maxAmount;
        uint256 windowSize;
        uint256 currentAmount;
        uint256 windowStart;
    }

    function checkAndUpdate(
        RateLimit storage limit,
        uint256 amount
    ) internal returns (bool) {
        // Reset window if expired
        if (block.timestamp >= limit.windowStart + limit.windowSize) {
            limit.currentAmount = 0;
            limit.windowStart = block.timestamp;
        }

        // Check if within limit
        if (limit.currentAmount + amount > limit.maxAmount) {
            return false;
        }

        limit.currentAmount += amount;
        return true;
    }
}

// Usage in AccountingManager
contract AccountingManager {
    using RateLimiter for RateLimiter.RateLimit;

    RateLimiter.RateLimit public depositRateLimit;
    RateLimiter.RateLimit public withdrawRateLimit;

    function deposit(...) public {
        require(
            depositRateLimit.checkAndUpdate(amount),
            "Deposit rate limit exceeded"
        );

        // ... rest of function ...
    }
}
```

---

## Gas Optimizations

### 1. Storage Packing

```solidity
// Current: Multiple storage slots
uint256 public minWithdrawalAmount;
uint256 public minDepositAmount;
uint256 public depositWaitingTime;
uint256 public withdrawWaitingTime;

// Optimized: Pack into fewer slots
struct Limits {
    uint128 minWithdrawalAmount;
    uint128 minDepositAmount;
}

struct WaitingTimes {
    uint128 depositWaitingTime;
    uint128 withdrawWaitingTime;
}

Limits public limits;
WaitingTimes public waitingTimes;
```

### 2. Loop Optimizations

```solidity
// Current: Multiple loops
for (uint256 i = 0; i < tokens.length; i++) {
    _updateTokenInRegistry(tokens[i]);
}

// Optimized: Batch operations
function _updateTokensInRegistry(address[] memory tokens) internal {
    unchecked {
        uint256 length = tokens.length;
        for (uint256 i; i < length; ++i) {
            _updateTokenInRegistry(tokens[i]);
        }
    }
}
```

---

## Monitoring & Alerts

### Event Emission Strategy

```solidity
// Enhanced events with indexed parameters
event DepositProcessed(
    address indexed user,
    uint256 indexed queueId,
    uint256 amount,
    uint256 shares,
    uint256 pricePerShare,
    uint256 timestamp
) indexed;

event AnomalousActivity(
    bytes32 indexed activityType,
    address indexed actor,
    uint256 value,
    string reason
) indexed;

event CircuitBreakerTriggered(
    bytes32 indexed operation,
    uint256 errorCount,
    uint256 timestamp
) indexed;
```

### Off-Chain Monitoring

```javascript
// Monitoring script pseudocode
const monitorProtocol = async () => {
  // Monitor share price volatility
  const priceChange = await calculatePriceChange();
  if (Math.abs(priceChange) > 10%) {
    alert('High price volatility detected');
  }

  // Monitor large withdrawals
  const pendingWithdrawals = await getPendingWithdrawals();
  if (pendingWithdrawals > tvl * 0.3) {
    alert('Large withdrawal group detected');
  }

  // Monitor circuit breaker status
  const circuitStatus = await getCircuitStatus();
  if (circuitStatus.open) {
    alert(`Circuit breaker open for ${circuitStatus.operation}`);
  }
};
```

---

## Testing Enhancements

### Invariant Tests

```solidity
// Invariant: Total shares should equal sum of all balances
function invariant_SharesBalance() public {
    uint256 totalShares = accountingManager.totalSupply();
    uint256 sumOfBalances = 0;

    for (uint256 i = 0; i < users.length; i++) {
        sumOfBalances += accountingManager.balanceOf(users[i]);
    }

    assertEq(totalShares, sumOfBalances, "Shares invariant violated");
}

// Invariant: TVL should always be >= 0
function invariant_PositiveTVL() public {
    uint256 tvl = accountingManager.totalAssets();
    assertGe(tvl, 0, "TVL cannot be negative");
}

// Invariant: Withdrawn amount + current TVL >= deposited amount
function invariant_ValueConservation() public {
    uint256 deposited = accountingManager.totalDepositedAmount();
    uint256 withdrawn = accountingManager.totalWithdrawnAmount();
    uint256 tvl = accountingManager.totalAssets();

    assertGe(withdrawn + tvl, deposited, "Value conservation violated");
}
```

---

## Documentation Improvements

### NatSpec Comments

```solidity
/**
 * @title AccountingManager
 * @author NOYA Team
 * @notice Manages deposits, withdrawals, and accounting for the NOYA vault
 * @dev Implements ERC4626-like vault with queue-based deposit/withdrawal system
 *
 * Key Features:
 * - Queue-based deposit processing to protect against price manipulation
 * - Group-based withdrawal system for efficient liquidity management
 * - Performance, management, and withdrawal fee mechanisms
 * - Integration with multiple connectors for yield strategies
 *
 * Security Considerations:
 * - Flash loan protection via TWAP pricing
 * - Slippage protection for deposits and withdrawals
 * - Circuit breakers for abnormal activity
 * - Rate limiting on deposits and withdrawals
 *
 * @custom:security-contact security@noya.com
 */
contract AccountingManager {
    // ...
}
```

### Sequence Diagrams

Include in documentation:

```
Deposit Flow:
User -> AccountingManager: deposit()
AccountingManager -> BaseToken: transferFrom()
AccountingManager -> DepositQueue: add()
Manager -> AccountingManager: calculateDepositShares()
AccountingManager -> TVLHelper: getTVL()
AccountingManager -> TWAPOracle: getPrice()
Manager -> AccountingManager: executeDeposit()
AccountingManager -> Connector: addLiquidity()
AccountingManager -> User: mint shares
```

---

## Summary of Priority Actions

### Phase 1 (Week 1) - Critical Fixes
- [ ] Implement flash loan protection
- [ ] Add Watcher verification logic
- [ ] Fix bonding deletion race condition
- [ ] Implement first deposit protection
- [ ] Add withdrawal slippage protection

### Phase 2 (Week 2-3) - Architecture Improvements
- [ ] Implement TWAP pricing
- [ ] Add circuit breakers
- [ ] Implement rate limiting
- [ ] Add proper access control reviews
- [ ] Enhance event emissions

### Phase 3 (Week 3-4) - Testing & Documentation
- [ ] Write comprehensive unit tests
- [ ] Add invariant tests
- [ ] Perform fuzzing campaigns
- [ ] Update documentation
- [ ] Conduct internal re-audit

### Phase 4 (Week 4-5) - Final Review
- [ ] External audit of fixes
- [ ] Deploy to testnet
- [ ] Bug bounty program
- [ ] Gradual mainnet rollout

---

**End of Improvements Document**
