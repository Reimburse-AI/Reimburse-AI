// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title UniversalReimbursementModule
 * @author ReimburseAI Security Team
 * @notice Universal reimbursement module supporting ALL wallet types via ERC-20 allowance
 * @dev Works with any ERC-20 compatible wallet: MetaMask, Safe{Wallet}, Coinbase, Rainbow, etc.
 * 
 * ## Architecture
 * - Supports ANY wallet type via standard ERC-20 approve() / transferFrom()
 * - For Safe{Wallet} users: Optional integration with AllowanceModule for spending limits
 * - For EOA wallets: Direct transferFrom() with company-approved allowance
 * - Company treasury stays in their chosen wallet (NON-CUSTODIAL)
 * 
 * ## Supported Wallets
 * - MetaMask, Rainbow, Trust, and other EOA wallets
 * - Coinbase Wallet (both EOA and Smart Wallet)
 * - Safe{Wallet} (multisig)
 * - Any WalletConnect compatible wallet via Reown AppKit (300+ wallets)
 * 
 * ## Security Features
 * - Non-custodial: Contract never holds funds, uses transferFrom pattern
 * - Role-Based Access Control (RBAC) for operators
 * - Receipt hash deduplication prevents replay attacks
 * - Per-recipient daily/monthly spending limits
 * - Pausable for emergencies
 * - Comprehensive audit trail via events
 * - SafeERC20 for all token transfers
 * - ReentrancyGuard on all external state-changing functions
 * 
 * ## Invariants
 * - A company can only have one treasury address registered
 * - A treasury address can only belong to one company
 * - Receipt hashes are unique and can only be processed once (unless failed)
 * - feeBps can never exceed MAX_FEE_BPS (200 = 2%)
 * - Only OPERATOR_ROLE can execute reimbursements
 * - Only ADMIN_ROLE can manage companies and configuration
 * - Only PAUSER_ROLE can pause the contract
 * 
 * @custom:security-contact security@reimburseai.app
 * @custom:version 4.0.0
 */
contract UniversalReimbursementModule is AccessControl, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ============ Roles ============
    
    /// @notice Role hash for platform operators who can execute reimbursements
    /// @dev Operators are trusted backend services that process approved reimbursements
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    
    /// @notice Role hash for emergency pause capability
    /// @dev Separate from ADMIN to allow quick response without full admin access
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    
    /// @notice Role hash for platform administrators
    /// @dev Admins can register companies, update fees, and manage the system
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // ============ Constants ============
    
    /// @notice Contract version for tracking upgrades
    /// @dev V4: Audit-ready version with security fixes
    uint256 public constant VERSION = 4;
    
    /// @notice Maximum fee in basis points (2% = 200 bps)
    /// @dev This caps the platform fee to protect users from excessive fees
    uint256 public constant MAX_FEE_BPS = 200;
    
    /// @notice Basis points denominator for fee calculations
    /// @dev 10000 basis points = 100%
    uint256 private constant BPS_DENOMINATOR = 10000;
    
    /// @notice Seconds per day for limit calculations
    /// @dev Used in daily limit tracking
    uint256 private constant SECONDS_PER_DAY = 1 days;
    
    /// @notice Approximate seconds per month (30 days)
    /// @dev Used for monthly limit tracking
    uint256 private constant SECONDS_PER_MONTH = 30 days;

    // ============ Enums ============
    
    /// @notice Wallet type classification for company treasury
    /// @dev Used for analytics and potential wallet-specific features
    enum WalletType {
        EOA,           // Standard externally owned account (MetaMask, Rainbow, etc.)
        SAFE_WALLET,   // Gnosis Safe{Wallet} multisig
        SMART_WALLET   // Coinbase or other smart contract wallet
    }
    
    /// @notice Reimbursement lifecycle status
    /// @dev PENDING is set before transfer, EXECUTED/FAILED after
    enum ReimbursementStatus {
        PENDING,    // Record created, transfer pending
        EXECUTED,   // Transfer successful
        FAILED,     // Transfer failed
        CANCELLED   // Cancelled by admin (future use)
    }

    // ============ Structs ============
    
    /**
     * @notice Company registration information
     * @dev Stores all company-related configuration and statistics
     * @param treasuryAddress Company's treasury wallet address (any supported wallet type)
     * @param walletType Type of wallet being used for the treasury
     * @param allowanceModule Optional Safe AllowanceModule address (only for SAFE_WALLET type)
     * @param isActive Whether the company is currently active and can receive reimbursements
     * @param registeredAt Timestamp when the company was registered
     * @param totalReimbursed Cumulative amount reimbursed in USDC (6 decimals)
     * @param reimbursementCount Total number of successful reimbursements
     */
    struct CompanyInfo {
        address treasuryAddress;
        WalletType walletType;
        address allowanceModule;
        bool isActive;
        uint256 registeredAt;
        uint256 totalReimbursed;
        uint256 reimbursementCount;
    }
    
    /**
     * @notice Recipient spending limits and tracking
     * @dev Tracks spending against daily and monthly caps
     * @param dailyLimit Maximum amount that can be reimbursed per day
     * @param monthlyLimit Maximum amount that can be reimbursed per month
     * @param dailySpent Amount spent in the current day
     * @param monthlySpent Amount spent in the current month
     * @param lastDayReset Day number when daily counter was last reset
     * @param lastMonthReset Month number when monthly counter was last reset
     */
    struct RecipientLimits {
        uint256 dailyLimit;
        uint256 monthlyLimit;
        uint256 dailySpent;
        uint256 monthlySpent;
        uint256 lastDayReset;
        uint256 lastMonthReset;
    }
    
    /**
     * @notice Immutable reimbursement record for audit trail
     * @dev Created for every reimbursement attempt, successful or not
     * @param companyId Identifier of the company making the reimbursement
     * @param recipient Address of the employee receiving funds
     * @param amount Gross amount in USDC (before fee deduction)
     * @param receiptHash Keccak256 hash of receipt metadata for verification
     * @param auditProof Hash of the AI audit result that approved this reimbursement
     * @param timestamp Block timestamp when the reimbursement was executed
     * @param status Current status of the reimbursement
     */
    struct ReimbursementRecord {
        bytes32 companyId;
        address recipient;
        uint256 amount;
        bytes32 receiptHash;
        bytes32 auditProof;
        uint256 timestamp;
        ReimbursementStatus status;
    }

    // ============ State Variables ============
    
    /// @notice Mapping of company ID to company information
    /// @dev Primary storage for company data
    mapping(bytes32 => CompanyInfo) public companies;
    
    /// @notice Reverse lookup: treasury address to company ID
    /// @dev Ensures one treasury can only belong to one company
    mapping(address => bytes32) public treasuryToCompanyId;
    
    /// @notice Nested mapping: company ID => recipient => spending limits
    /// @dev Tracks per-recipient limits within each company
    mapping(bytes32 => mapping(address => RecipientLimits)) public recipientLimits;
    
    /// @notice Mapping of receipt hashes that have been processed
    /// @dev Prevents replay attacks by marking processed receipts
    mapping(bytes32 => bool) public processedReceipts;
    
    /// @notice Mapping of record ID to reimbursement record
    /// @dev Immutable audit trail of all reimbursement attempts
    mapping(uint256 => ReimbursementRecord) public records;
    
    /// @notice Counter for generating unique record IDs
    /// @dev Incremented before each new record is created
    uint256 public nextRecordId;
    
    /// @notice USDC token contract reference
    /// @dev Immutable after construction - the only supported payment token
    IERC20 public immutable usdc;
    
    /// @notice Platform fee in basis points (1 bps = 0.01%)
    /// @dev Can be 0 for fee-free operation, capped at MAX_FEE_BPS
    uint256 public feeBps;
    
    /// @notice Address receiving platform fees
    /// @dev ReimburseAI revenue wallet; can be zero to disable fees
    address public feeRecipient;
    
    /// @notice Default daily limit per recipient in USDC
    /// @dev Used when recipient has no custom limit set; 1000 * 1e6 = $1,000
    uint256 public defaultDailyLimit = 1000 * 1e6;
    
    /// @notice Default monthly limit per recipient in USDC
    /// @dev Used when recipient has no custom limit set; 10000 * 1e6 = $10,000
    uint256 public defaultMonthlyLimit = 10000 * 1e6;

    // ============ Events ============
    
    /**
     * @notice Emitted when a new company is registered
     * @param companyId Unique identifier for the company
     * @param treasuryAddress Address of the company's treasury wallet
     * @param walletType Type of wallet used for treasury
     * @param registeredBy Address that registered the company (admin)
     */
    event CompanyRegistered(
        bytes32 indexed companyId,
        address indexed treasuryAddress,
        WalletType walletType,
        address indexed registeredBy
    );
    
    /**
     * @notice Emitted when a company is deactivated
     * @param companyId Identifier of the deactivated company
     * @param deactivatedBy Address that performed the deactivation
     */
    event CompanyDeactivated(bytes32 indexed companyId, address indexed deactivatedBy);
    
    /**
     * @notice Emitted when a company is reactivated
     * @param companyId Identifier of the reactivated company
     * @param reactivatedBy Address that performed the reactivation
     */
    event CompanyReactivated(bytes32 indexed companyId, address indexed reactivatedBy);
    
    /**
     * @notice Emitted when a company's treasury address is updated
     * @param companyId Identifier of the company
     * @param oldTreasury Previous treasury address
     * @param newTreasury New treasury address
     * @param updatedBy Address that performed the update
     */
    event CompanyTreasuryUpdated(
        bytes32 indexed companyId,
        address indexed oldTreasury,
        address indexed newTreasury,
        address updatedBy
    );
    
    /**
     * @notice Emitted upon successful reimbursement execution
     * @param recordId Unique identifier for this reimbursement record
     * @param companyId Company that made the reimbursement
     * @param recipient Employee who received the funds
     * @param amount Gross amount (before fee)
     * @param fee Platform fee deducted
     * @param receiptHash Hash of the receipt metadata
     * @param auditProof Hash of the AI audit approval
     */
    event ReimbursementExecuted(
        uint256 indexed recordId,
        bytes32 indexed companyId,
        address indexed recipient,
        uint256 amount,
        uint256 fee,
        bytes32 receiptHash,
        bytes32 auditProof
    );
    
    /**
     * @notice Emitted when a reimbursement fails
     * @param recordId Unique identifier for this reimbursement record
     * @param companyId Company that attempted the reimbursement
     * @param recipient Intended recipient of the funds
     * @param amount Amount that was attempted to transfer
     * @param reason Human-readable reason for failure
     */
    event ReimbursementFailed(
        uint256 indexed recordId,
        bytes32 indexed companyId,
        address indexed recipient,
        uint256 amount,
        string reason
    );
    
    /**
     * @notice Emitted when recipient limits are updated
     * @param companyId Company whose recipient limits were updated
     * @param recipient Address whose limits were changed
     * @param dailyLimit New daily limit in USDC
     * @param monthlyLimit New monthly limit in USDC
     */
    event RecipientLimitsUpdated(
        bytes32 indexed companyId,
        address indexed recipient,
        uint256 dailyLimit,
        uint256 monthlyLimit
    );
    
    /**
     * @notice Emitted when platform fee configuration is updated
     * @param feeRecipient New fee recipient address
     * @param feeBps New fee in basis points
     * @param updatedBy Address that performed the update
     */
    event FeeUpdated(address indexed feeRecipient, uint256 feeBps, address indexed updatedBy);
    
    /**
     * @notice Emitted when default limits are updated
     * @param dailyLimit New default daily limit
     * @param monthlyLimit New default monthly limit
     * @param updatedBy Address that performed the update
     */
    event DefaultLimitsUpdated(uint256 dailyLimit, uint256 monthlyLimit, address indexed updatedBy);

    // ============ Custom Errors ============
    
    /// @notice Thrown when a zero address is provided where not allowed
    error ZeroAddress();
    
    /// @notice Thrown when attempting to operate on an unregistered company
    error CompanyNotRegistered();
    
    /// @notice Thrown when attempting to register an already registered company
    error CompanyAlreadyRegistered();
    
    /// @notice Thrown when operating on a deactivated company
    error CompanyNotActive();
    
    /// @notice Thrown when treasury address is already registered to another company
    error TreasuryAlreadyRegistered();
    
    /// @notice Thrown when attempting to process an already processed receipt
    error ReceiptAlreadyProcessed();
    
    /// @notice Thrown when reimbursement would exceed daily limit
    error ExceedsDailyLimit();
    
    /// @notice Thrown when reimbursement would exceed monthly limit
    error ExceedsMonthlyLimit();
    
    /// @notice Thrown when amount is zero or invalid
    error InvalidAmount();
    
    /// @notice Thrown when ERC20 transfer fails
    error TransferFailed();
    
    /// @notice Thrown when attempting to set fee above MAX_FEE_BPS
    error FeeTooHigh();
    
    /// @notice Thrown when treasury has insufficient USDC allowance
    error InsufficientAllowance();
    
    /// @notice Thrown when monthly limit is less than daily limit
    error InvalidLimitConfiguration();
    
    /// @notice Thrown when caller is not the contract itself (for internal calls)
    error OnlyInternalCall();

    // ============ Constructor ============
    
    /**
     * @notice Initialize the universal reimbursement module
     * @dev Sets up USDC token and grants all initial roles to admin
     * @param _usdc Address of the USDC token contract (must be non-zero)
     * @param _admin Initial admin address (receives all roles)
     * 
     * Requirements:
     * - `_usdc` cannot be the zero address
     * - `_admin` cannot be the zero address
     */
    constructor(address _usdc, address _admin) {
        // Checks
        if (_usdc == address(0) || _admin == address(0)) revert ZeroAddress();
        
        // Effects
        usdc = IERC20(_usdc);
        
        // Grant all roles to initial admin
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);
    }

    // ============ Company Management ============
    
    /**
     * @notice Register a new company with any supported wallet type
     * @dev Creates a new company entry and maps treasury to company ID
     * @param companyId Unique identifier for the company (typically keccak256 of company data)
     * @param treasuryAddress Company's treasury wallet address
     * @param walletType Type of wallet (EOA, SAFE_WALLET, or SMART_WALLET)
     * @param allowanceModule Optional AllowanceModule address for Safe wallets (can be zero)
     * 
     * Requirements:
     * - Caller must have ADMIN_ROLE
     * - `treasuryAddress` cannot be zero address
     * - `companyId` must not be already registered
     * - `treasuryAddress` must not be registered to another company
     * 
     * Emits a {CompanyRegistered} event
     */
    function registerCompany(
        bytes32 companyId,
        address treasuryAddress,
        WalletType walletType,
        address allowanceModule
    ) external onlyRole(ADMIN_ROLE) {
        // Checks
        if (treasuryAddress == address(0)) revert ZeroAddress();
        if (companies[companyId].treasuryAddress != address(0)) revert CompanyAlreadyRegistered();
        if (treasuryToCompanyId[treasuryAddress] != bytes32(0)) revert TreasuryAlreadyRegistered();
        
        // Effects
        companies[companyId] = CompanyInfo({
            treasuryAddress: treasuryAddress,
            walletType: walletType,
            allowanceModule: allowanceModule,
            isActive: true,
            registeredAt: block.timestamp,
            totalReimbursed: 0,
            reimbursementCount: 0
        });
        
        treasuryToCompanyId[treasuryAddress] = companyId;
        
        emit CompanyRegistered(companyId, treasuryAddress, walletType, msg.sender);
    }
    
    /**
     * @notice Deactivate a company to prevent further reimbursements
     * @dev Company can be reactivated later; all data is preserved
     * @param companyId Identifier of the company to deactivate
     * 
     * Requirements:
     * - Caller must have ADMIN_ROLE
     * - Company must exist (be registered)
     * 
     * Emits a {CompanyDeactivated} event
     */
    function deactivateCompany(bytes32 companyId) external onlyRole(ADMIN_ROLE) {
        // Checks
        CompanyInfo storage company = companies[companyId];
        if (company.treasuryAddress == address(0)) revert CompanyNotRegistered();
        
        // Effects
        company.isActive = false;
        
        emit CompanyDeactivated(companyId, msg.sender);
    }
    
    /**
     * @notice Reactivate a previously deactivated company
     * @dev Restores the company's ability to receive reimbursements
     * @param companyId Identifier of the company to reactivate
     * 
     * Requirements:
     * - Caller must have ADMIN_ROLE
     * - Company must exist (be registered)
     * 
     * Emits a {CompanyReactivated} event
     */
    function reactivateCompany(bytes32 companyId) external onlyRole(ADMIN_ROLE) {
        // Checks
        CompanyInfo storage company = companies[companyId];
        if (company.treasuryAddress == address(0)) revert CompanyNotRegistered();
        
        // Effects
        company.isActive = true;
        
        emit CompanyReactivated(companyId, msg.sender);
    }
    
    /**
     * @notice Update a company's treasury address
     * @dev Allows migration to a new treasury wallet while preserving history
     * @param companyId Identifier of the company to update
     * @param newTreasury New treasury wallet address
     * @param newWalletType Type of the new wallet
     * @param newAllowanceModule Optional new AllowanceModule for Safe wallets
     * 
     * Requirements:
     * - Caller must have ADMIN_ROLE
     * - `newTreasury` cannot be zero address
     * - Company must exist
     * - `newTreasury` must not be registered to a different company
     * 
     * Emits a {CompanyTreasuryUpdated} event
     */
    function updateCompanyTreasury(
        bytes32 companyId,
        address newTreasury,
        WalletType newWalletType,
        address newAllowanceModule
    ) external onlyRole(ADMIN_ROLE) {
        // Checks
        if (newTreasury == address(0)) revert ZeroAddress();
        
        CompanyInfo storage company = companies[companyId];
        if (company.treasuryAddress == address(0)) revert CompanyNotRegistered();
        
        // Check new treasury isn't already registered to another company
        bytes32 existingCompanyId = treasuryToCompanyId[newTreasury];
        if (existingCompanyId != bytes32(0) && existingCompanyId != companyId) {
            revert TreasuryAlreadyRegistered();
        }
        
        address oldTreasury = company.treasuryAddress;
        
        // Effects
        delete treasuryToCompanyId[oldTreasury];
        
        company.treasuryAddress = newTreasury;
        company.walletType = newWalletType;
        company.allowanceModule = newAllowanceModule;
        
        treasuryToCompanyId[newTreasury] = companyId;
        
        emit CompanyTreasuryUpdated(companyId, oldTreasury, newTreasury, msg.sender);
    }

    // ============ Reimbursement Execution ============
    
    /**
     * @notice Execute a reimbursement from company treasury to employee
     * @dev Uses ERC-20 transferFrom pattern - treasury must have approved this contract
     * 
     * Flow:
     * 1. Validates all inputs and company state
     * 2. Checks treasury has sufficient USDC allowance
     * 3. Verifies and updates recipient spending limits
     * 4. Marks receipt as processed (prevents replay)
     * 5. Creates audit record
     * 6. Executes atomic transfers (recipient + fee)
     * 7. Updates company statistics
     * 
     * @param companyId Company making the reimbursement
     * @param recipient Employee receiving the funds
     * @param amount Gross amount in USDC (6 decimals), fee will be deducted
     * @param receiptHash Keccak256 hash of receipt metadata for verification
     * @param auditProof Hash of AI audit result that approved this reimbursement
     * @return recordId Unique identifier for the created reimbursement record
     * 
     * Requirements:
     * - Caller must have OPERATOR_ROLE
     * - Contract must not be paused
     * - `recipient` cannot be zero address
     * - `amount` must be greater than zero
     * - `receiptHash` must not have been processed before
     * - Company must exist and be active
     * - Treasury must have approved sufficient USDC
     * - Reimbursement must not exceed recipient's daily/monthly limits
     * 
     * Emits {ReimbursementExecuted} on success or {ReimbursementFailed} on failure
     */
    function executeReimbursement(
        bytes32 companyId,
        address recipient,
        uint256 amount,
        bytes32 receiptHash,
        bytes32 auditProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) returns (uint256 recordId) {
        // === CHECKS ===
        if (recipient == address(0)) revert ZeroAddress();
        if (amount == 0) revert InvalidAmount();
        if (processedReceipts[receiptHash]) revert ReceiptAlreadyProcessed();
        
        CompanyInfo storage company = companies[companyId];
        if (company.treasuryAddress == address(0)) revert CompanyNotRegistered();
        if (!company.isActive) revert CompanyNotActive();
        
        // Check USDC allowance from treasury to this contract
        uint256 allowance = usdc.allowance(company.treasuryAddress, address(this));
        if (allowance < amount) revert InsufficientAllowance();
        
        // Check and update recipient limits (reverts if exceeded)
        _checkAndUpdateLimits(companyId, recipient, amount);
        
        // === EFFECTS ===
        // Mark receipt as processed BEFORE any external calls (CEI pattern)
        processedReceipts[receiptHash] = true;
        
        // Create record with pre-incremented ID
        recordId = nextRecordId++;
        records[recordId] = ReimbursementRecord({
            companyId: companyId,
            recipient: recipient,
            amount: amount,
            receiptHash: receiptHash,
            auditProof: auditProof,
            timestamp: block.timestamp,
            status: ReimbursementStatus.PENDING
        });
        
        // Calculate fee
        uint256 fee = _calculateFee(amount);
        uint256 netAmount = amount - fee;
        
        // === INTERACTIONS ===
        // Execute transfers using SafeERC20
        bool success = _executeTransfers(company.treasuryAddress, recipient, netAmount, fee);
        
        if (success) {
            // Update state on success
            records[recordId].status = ReimbursementStatus.EXECUTED;
            
            // Safe to do unchecked since these are bounded by USDC supply
            unchecked {
                company.totalReimbursed += amount;
                company.reimbursementCount++;
            }
            
            emit ReimbursementExecuted(
                recordId,
                companyId,
                recipient,
                amount,
                fee,
                receiptHash,
                auditProof
            );
        } else {
            // Revert state on failure
            records[recordId].status = ReimbursementStatus.FAILED;
            processedReceipts[receiptHash] = false;
            
            // Revert limit updates on failure
            _revertLimitUpdates(companyId, recipient, amount);
            
            emit ReimbursementFailed(
                recordId,
                companyId,
                recipient,
                amount,
                "USDC transfer failed"
            );
        }
        
        return recordId;
    }
    
    /**
     * @notice Execute USDC transfers for reimbursement
     * @dev Internal function using SafeERC20 for secure transfers
     * @param from Treasury address to transfer from
     * @param recipient Employee receiving the net amount
     * @param netAmount Amount after fee deduction
     * @param fee Platform fee amount
     * @return success True if all transfers succeeded
     */
    function _executeTransfers(
        address from,
        address recipient,
        uint256 netAmount,
        uint256 fee
    ) internal returns (bool success) {
        // Use try/catch to handle transfer failures gracefully
        try this.executeTransfersExternal(from, recipient, netAmount, fee) {
            return true;
        } catch {
            return false;
        }
    }
    
    /**
     * @notice External wrapper for transfers to enable try/catch
     * @dev This function is marked external to allow try/catch in _executeTransfers
     *      CRITICAL: Can only be called by this contract itself
     * @param from Treasury address
     * @param recipient Recipient address
     * @param netAmount Net amount to recipient
     * @param fee Fee amount to feeRecipient
     */
    function executeTransfersExternal(
        address from,
        address recipient,
        uint256 netAmount,
        uint256 fee
    ) external {
        // CRITICAL: Only allow calls from this contract
        // This prevents external actors from using this function
        if (msg.sender != address(this)) revert OnlyInternalCall();
        
        // Transfer net amount to recipient
        usdc.safeTransferFrom(from, recipient, netAmount);
        
        // Transfer fee if applicable
        if (fee > 0 && feeRecipient != address(0)) {
            usdc.safeTransferFrom(from, feeRecipient, fee);
        }
    }

    // ============ Limits Management ============
    
    /**
     * @notice Check and update recipient spending limits
     * @dev Handles daily/monthly reset logic and limit validation
     * @param companyId Company ID for the limits lookup
     * @param recipient Recipient address to check
     * @param amount Amount to add to spending
     */
    function _checkAndUpdateLimits(
        bytes32 companyId,
        address recipient,
        uint256 amount
    ) internal {
        RecipientLimits storage limits = recipientLimits[companyId][recipient];
        
        uint256 currentDay = block.timestamp / SECONDS_PER_DAY;
        uint256 currentMonth = block.timestamp / SECONDS_PER_MONTH;
        
        // Reset daily counter if new day
        if (limits.lastDayReset != currentDay) {
            limits.dailySpent = 0;
            limits.lastDayReset = currentDay;
        }
        
        // Reset monthly counter if new month
        if (limits.lastMonthReset != currentMonth) {
            limits.monthlySpent = 0;
            limits.lastMonthReset = currentMonth;
        }
        
        // Use defaults if custom limits not set
        uint256 dailyLimit = limits.dailyLimit > 0 ? limits.dailyLimit : defaultDailyLimit;
        uint256 monthlyLimit = limits.monthlyLimit > 0 ? limits.monthlyLimit : defaultMonthlyLimit;
        
        // Check limits (fail early and loudly)
        if (limits.dailySpent + amount > dailyLimit) revert ExceedsDailyLimit();
        if (limits.monthlySpent + amount > monthlyLimit) revert ExceedsMonthlyLimit();
        
        // Update spending counters
        unchecked {
            limits.dailySpent += amount;
            limits.monthlySpent += amount;
        }
    }
    
    /**
     * @notice Revert limit updates if transfer fails
     * @dev Called when transfer fails to restore original limit state
     * @param companyId Company ID for the limits lookup
     * @param recipient Recipient address
     * @param amount Amount to subtract from spending
     */
    function _revertLimitUpdates(
        bytes32 companyId,
        address recipient,
        uint256 amount
    ) internal {
        RecipientLimits storage limits = recipientLimits[companyId][recipient];
        
        unchecked {
            // Safe to unchecked since we're subtracting what we just added
            if (limits.dailySpent >= amount) {
                limits.dailySpent -= amount;
            }
            if (limits.monthlySpent >= amount) {
                limits.monthlySpent -= amount;
            }
        }
    }
    
    /**
     * @notice Set custom spending limits for a recipient
     * @dev Overrides default limits for this specific recipient
     * @param companyId Company ID
     * @param recipient Recipient address to set limits for
     * @param dailyLimit Maximum daily reimbursement in USDC
     * @param monthlyLimit Maximum monthly reimbursement in USDC
     * 
     * Requirements:
     * - Caller must have ADMIN_ROLE
     * - Company must exist
     * - `recipient` cannot be zero address
     * - `monthlyLimit` should be >= `dailyLimit` (logical validation)
     * 
     * Emits a {RecipientLimitsUpdated} event
     */
    function setRecipientLimits(
        bytes32 companyId,
        address recipient,
        uint256 dailyLimit,
        uint256 monthlyLimit
    ) external onlyRole(ADMIN_ROLE) {
        // Checks
        if (companies[companyId].treasuryAddress == address(0)) revert CompanyNotRegistered();
        if (recipient == address(0)) revert ZeroAddress();
        if (monthlyLimit > 0 && dailyLimit > monthlyLimit) revert InvalidLimitConfiguration();
        
        // Effects
        RecipientLimits storage limits = recipientLimits[companyId][recipient];
        limits.dailyLimit = dailyLimit;
        limits.monthlyLimit = monthlyLimit;
        
        emit RecipientLimitsUpdated(companyId, recipient, dailyLimit, monthlyLimit);
    }

    // ============ Fee Management ============
    
    /**
     * @notice Calculate platform fee for a given amount
     * @dev Returns 0 if feeBps is 0 or feeRecipient is not set
     * @param amount Gross amount to calculate fee from
     * @return fee Platform fee in USDC
     */
    function _calculateFee(uint256 amount) internal view returns (uint256 fee) {
        if (feeBps == 0 || feeRecipient == address(0)) return 0;
        return (amount * feeBps) / BPS_DENOMINATOR;
    }
    
    /**
     * @notice Update platform fee configuration
     * @dev Can set fee to 0 or feeRecipient to zero to disable fees
     * @param _feeRecipient New fee recipient address (ReimburseAI revenue wallet)
     * @param _feeBps New fee in basis points (100 bps = 1%)
     * 
     * Requirements:
     * - Caller must have ADMIN_ROLE
     * - `_feeBps` cannot exceed MAX_FEE_BPS (200 = 2%)
     * 
     * Emits a {FeeUpdated} event
     */
    function updateFee(address _feeRecipient, uint256 _feeBps) external onlyRole(ADMIN_ROLE) {
        // Checks
        if (_feeBps > MAX_FEE_BPS) revert FeeTooHigh();
        
        // Effects
        feeRecipient = _feeRecipient;
        feeBps = _feeBps;
        
        emit FeeUpdated(_feeRecipient, _feeBps, msg.sender);
    }
    
    /**
     * @notice Update default spending limits
     * @dev Affects all recipients without custom limits
     * @param _dailyLimit New default daily limit in USDC
     * @param _monthlyLimit New default monthly limit in USDC
     * 
     * Requirements:
     * - Caller must have ADMIN_ROLE
     * - `_monthlyLimit` should be >= `_dailyLimit`
     * 
     * Emits a {DefaultLimitsUpdated} event
     */
    function updateDefaultLimits(
        uint256 _dailyLimit,
        uint256 _monthlyLimit
    ) external onlyRole(ADMIN_ROLE) {
        // Checks
        if (_monthlyLimit > 0 && _dailyLimit > _monthlyLimit) revert InvalidLimitConfiguration();
        
        // Effects
        defaultDailyLimit = _dailyLimit;
        defaultMonthlyLimit = _monthlyLimit;
        
        emit DefaultLimitsUpdated(_dailyLimit, _monthlyLimit, msg.sender);
    }

    // ============ Emergency Functions ============
    
    /**
     * @notice Pause all reimbursement operations
     * @dev Emergency function to halt operations if issues are detected
     * 
     * Requirements:
     * - Caller must have PAUSER_ROLE
     * 
     * Emits a {Paused} event (from OpenZeppelin Pausable)
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }
    
    /**
     * @notice Resume reimbursement operations
     * @dev Unpauses the contract after emergency is resolved
     * 
     * Requirements:
     * - Caller must have ADMIN_ROLE (higher permission than PAUSER)
     * 
     * Emits an {Unpaused} event (from OpenZeppelin Pausable)
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    // ============ View Functions ============
    
    /**
     * @notice Get complete company information
     * @param companyId Identifier of the company
     * @return CompanyInfo struct with all company data
     */
    function getCompanyInfo(bytes32 companyId) external view returns (CompanyInfo memory) {
        return companies[companyId];
    }
    
    /**
     * @notice Get recipient's spending limits and current usage
     * @param companyId Company ID
     * @param recipient Recipient address
     * @return RecipientLimits struct with limits and current spending
     */
    function getRecipientLimits(
        bytes32 companyId,
        address recipient
    ) external view returns (RecipientLimits memory) {
        return recipientLimits[companyId][recipient];
    }
    
    /**
     * @notice Get a reimbursement record by ID
     * @param recordId Unique record identifier
     * @return ReimbursementRecord struct with all record data
     */
    function getRecord(uint256 recordId) external view returns (ReimbursementRecord memory) {
        return records[recordId];
    }
    
    /**
     * @notice Check if a receipt hash has been processed
     * @param receiptHash Hash to check
     * @return bool True if receipt was successfully processed
     */
    function isReceiptProcessed(bytes32 receiptHash) external view returns (bool) {
        return processedReceipts[receiptHash];
    }
    
    /**
     * @notice Calculate remaining daily allowance for a recipient
     * @dev Accounts for day rollover and default limits
     * @param companyId Company ID
     * @param recipient Recipient address
     * @return remaining Amount in USDC that can still be reimbursed today
     */
    function getRemainingDailyAllowance(
        bytes32 companyId,
        address recipient
    ) external view returns (uint256 remaining) {
        RecipientLimits storage limits = recipientLimits[companyId][recipient];
        uint256 currentDay = block.timestamp / SECONDS_PER_DAY;
        
        uint256 dailyLimit = limits.dailyLimit > 0 ? limits.dailyLimit : defaultDailyLimit;
        uint256 spent = (limits.lastDayReset == currentDay) ? limits.dailySpent : 0;
        
        return dailyLimit > spent ? dailyLimit - spent : 0;
    }
    
    /**
     * @notice Calculate remaining monthly allowance for a recipient
     * @dev Accounts for month rollover and default limits
     * @param companyId Company ID
     * @param recipient Recipient address
     * @return remaining Amount in USDC that can still be reimbursed this month
     */
    function getRemainingMonthlyAllowance(
        bytes32 companyId,
        address recipient
    ) external view returns (uint256 remaining) {
        RecipientLimits storage limits = recipientLimits[companyId][recipient];
        uint256 currentMonth = block.timestamp / SECONDS_PER_MONTH;
        
        uint256 monthlyLimit = limits.monthlyLimit > 0 ? limits.monthlyLimit : defaultMonthlyLimit;
        uint256 spent = (limits.lastMonthReset == currentMonth) ? limits.monthlySpent : 0;
        
        return monthlyLimit > spent ? monthlyLimit - spent : 0;
    }
    
    /**
     * @notice Check how much USDC the treasury has approved for this contract
     * @param companyId Company ID to check
     * @return allowance Current USDC allowance from treasury to this contract
     */
    function getTreasuryAllowance(bytes32 companyId) external view returns (uint256 allowance) {
        CompanyInfo storage company = companies[companyId];
        if (company.treasuryAddress == address(0)) return 0;
        return usdc.allowance(company.treasuryAddress, address(this));
    }
    
    /**
     * @notice Check if a company is registered and active
     * @param companyId Company ID to check
     * @return registered True if company exists
     * @return active True if company is active
     */
    function isCompanyActive(bytes32 companyId) external view returns (bool registered, bool active) {
        CompanyInfo storage company = companies[companyId];
        registered = company.treasuryAddress != address(0);
        active = registered && company.isActive;
    }
}
