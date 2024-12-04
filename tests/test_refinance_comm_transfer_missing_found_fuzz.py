from typing import Dict, Tuple
from ordered_set import OrderedSet
from collections import defaultdict

from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.core.src.hub.PWNHub import PWNHub
from pytypes.core.src.config.PWNConfig import PWNConfig
from pytypes.core.src.loan.token.PWNLOAN import PWNLOAN
from pytypes.core.src.nonce.PWNRevokedNonce import PWNRevokedNonce
from pytypes.core.lib.MultiToken.src.MultiTokenCategoryRegistry import (
    MultiTokenCategoryRegistry,
)

from pytypes.core.lib.MultiToken.src.MultiToken import MultiToken

from pytypes.core.lib.openzeppelincontracts.contracts.proxy.transparent.TransparentUpgradeableProxy import (
    TransparentUpgradeableProxy,
)


from pytypes.core.src.PWNErrors import AddressMissingHubTag, Expired

from pytypes.core.src.loan.terms.simple.loan.PWNSimpleLoan import PWNSimpleLoan
from pytypes.core.src.utilizedcredit.PWNUtilizedCredit import PWNUtilizedCredit

from pytypes.core.src.loan.terms.simple.proposal.PWNSimpleLoanElasticProposal import (
    PWNSimpleLoanElasticProposal,
)
from pytypes.core.src.loan.terms.simple.proposal.PWNSimpleLoanDutchAuctionProposal import (
    PWNSimpleLoanDutchAuctionProposal,
)
from pytypes.core.src.loan.terms.simple.proposal.PWNSimpleLoanSimpleProposal import (
    PWNSimpleLoanSimpleProposal,
)
from pytypes.core.src.loan.terms.simple.proposal.PWNSimpleLoanElasticChainlinkProposal import (
    PWNSimpleLoanElasticChainlinkProposal,
)
from pytypes.core.src.loan.terms.simple.proposal.PWNSimpleLoanListProposal import (
    PWNSimpleLoanListProposal,
)

from pytypes.periphery.src.pooladapter.ERC4626Adapter import ERC4626Adapter

from pytypes.core.src.loan.vault.Permit import Permit as PermitPWN

from pytypes.core.lib.openzeppelincontracts.contracts.mocks.ERC4626Mock import (
    ERC4626Mock,
)

from pytypes.tests.helpers.MockERC1155 import MockERC1155
from pytypes.tests.helpers.MockERC20Permit import MockERC20Permit
from pytypes.tests.helpers.RichERC20 import RichERC20
from pytypes.tests.helpers.RichERC721 import RichERC721
from pytypes.tests.helpers.RichERC1155 import RichERC1155
from pytypes.tests.helpers.ERC4626 import SimpleVault

from pytypes.core.lib.openzeppelincontracts.contracts.token.ERC20.ERC20 import ERC20
from pytypes.core.lib.openzeppelincontracts.contracts.token.ERC20.extensions.ERC20Permit import (
    ERC20Permit,
)
from pytypes.core.lib.openzeppelincontracts.contracts.token.ERC20.extensions.ERC4626 import (
    ERC4626,
)

from pytypes.wake.interfaces.IERC1155 import IERC1155
from pytypes.wake.interfaces.IERC721 import IERC721
from pytypes.wake.interfaces.IERC20 import IERC20

from dataclasses import dataclass

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# VERSION_TAG = "1.2" # VERSION
ACTIVE_LOAN_TAG = keccak256(b"PWN_ACTIVE_LOAN")  # ACTIVE_LOAN
LOAN_PROPOSAL_TAG = keccak256(b"PWN_LOAN_PROPOSAL")  # LOAN_PROPOSAL
NONCE_MANAGER_TAG = keccak256(b"PWN_NONCE_MANAGER")  # NONCE_MANAGER

MAX_APR = 160_000
MIN_DURATION = 10 * 60  # 10 minutes

TOKENS: Dict[int, Dict[str, Account]] = {
    0: {
        "USDC": IERC20("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        "USDT": IERC20("0xdac17f958d2ee523a2206206994597c13d831ec7"),
        "BNB": IERC20("0xB8c77482e45F1F44dE1745F52C74426C631bDD52"),
        "DAI": IERC20("0x6b175474e89094c44da98b954eedeac495271d0f"),
        "WETH": IERC20("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
        "STA": IERC20("0xa7DE087329BFcda5639247F96140f9DAbe3DeED1"),
        "LEND": IERC20("0x80fB784B7eD66730e8b1DBd9820aFD29931aab03"),
        "YAMV2": IERC20("0xaba8cac6866b83ae4eec97dd07ed254282f6ad8a"),
        "MKR": IERC20("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2"),
        "EURS": IERC20("0xdb25f211ab05b1c97d595516f45794528a807ad8"),
        "UNI": IERC20("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"),
    },
    1: {
        "CRYPTO_KITTIES": IERC721("0x06012c8cf97bead5deae237070f95834efb2b2b5"),
        "LAND": IERC721("0xf87e31492faf9a91b02ee0deaad50d51d56d5d4d"),
        "AXIE": IERC721("0xF5b0A3eFB8e8E4c201e2A935F110eAaF3FFEcb8d"),
        "GODS_UNCHAINED": IERC721("0x0e3a2a1f2146d86a604adc220b4967a898d7fe07"),
        "CRYPTO_PUNKS": IERC721("0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB"),
        "RARIBLE": IERC721("0xF6793dA657495ffeFF9Ee6350824910Abc21356C"),
    },
}

from enum import Enum, auto


class ProposalType(Enum):
    SIMPLE = auto()
    ELASTIC = auto()
    ELASTIC_CHAINLINK = auto()
    LIST = auto()
    DUTCH_AUCTION = auto()


@dataclass
class ProposalInfo:
    lender: Account
    borrower: Account
    third_party: Account | None
    collrateral_token: Account
    credit_token: Account
    proposal_config: any
    default_timestamp: int
    actual_repaying_amount: int
    refinancing_loan_id: int | None
    user_vault: SimpleVault | None
    proposal_type: ProposalType
    collateral_id: int | None


def random_duration_or_date():
    # min duration is 10 minutes
    if random_bool():
        # duration
        return random_int(MIN_DURATION, 1000)
    else:
        return chain.blocks["pending"].timestamp + random_int(MIN_DURATION, 1000)


class PWNFuzzTest(FuzzTest):
    hub: PWNHub
    vault: PWNSimpleLoan
    config: PWNConfig
    fee_collector: Account
    utilized_credit: PWNUtilizedCredit
    utilized_credit_tag: bytes32
    revoked_nonce: PWNRevokedNonce
    multi_token_registry: MultiTokenCategoryRegistry

    loan_token: PWNLOAN

    elastic_proposal: PWNSimpleLoanElasticProposal
    dutch_auction_proposal: PWNSimpleLoanDutchAuctionProposal
    simple_proposal: PWNSimpleLoanSimpleProposal
    elastic_chainlink_proposal: PWNSimpleLoanElasticChainlinkProposal
    list_proposal: PWNSimpleLoanListProposal

    proposals_from_simple: Dict[bytes32, ProposalInfo]
    pending_proposal_hash: List[bytes32]  # proposal hashs of pending propose

    pending_refinancing_proposal_hash: List[
        bytes32
    ]  # proposal hashs of pending refinancing propose
    nonce: Dict[Account, int]  # nonce in PWNRevokedNonce
    nonce_spaces: Dict[Account, int]

    running_loan_id: List[int]  # loan_ids of running loan
    claimable_loan_id: List[int]  # loan_ids of claimable loan

    burned_loan_id: OrderedSet[int]
    proposals_from_loan_id: Dict[int, ProposalInfo]
    # loan_owner: Account

    erc20_balances: Dict[IERC20, Dict[Account, int]]
    erc721_owners: Dict[IERC721, Dict[int, Account]]
    erc1155_balances: Dict[IERC1155, Dict[Tuple[int, Account], int]]
    erc1155_support_ids: List[int]  # define for testing perpose.

    def pre_sequence(self) -> None:
        self.owner = random_account(
            predicate=lambda acc: acc != chain.accounts[0]
        )  # it can randomize
        self.hub = PWNHub.deploy(from_=self.owner)
        self.fee_collector = random_account()
        self.fee = random_int(0, 1000)  # MAX_FEE is 1000 (10%)
        self.proxy_control_owner = chain.accounts[0]
        self.config = PWNConfig(
            TransparentUpgradeableProxy.deploy(
                PWNConfig.deploy(),
                self.proxy_control_owner,
                # Warning, make sure to call initialize function in upgrading transaction,
                # otherwise anyone can be owner.
                abi.encode_call(
                    PWNConfig.initialize,
                    [self.owner, self.fee, self.fee_collector.address],
                ),
            )
        )
        self.proposals_from_simple = {}
        self.pending_proposal_hash = []
        self.nonce = {}
        self.nonce_spaces = {}
        self.running_loan_id = []
        self.proposals_from_loan_id = {}
        self.burned_loan_id = OrderedSet()
        self.claimable_loan_id = []
        self.pending_refinancing_proposal_hash = []

        self.erc4626_adapter = ERC4626Adapter.deploy(self.hub)

        self.revoked_nonce = PWNRevokedNonce.deploy(self.hub, NONCE_MANAGER_TAG)
        self.multi_token_registry = MultiTokenCategoryRegistry.deploy()

        self.utilized_credit_tag = random_bytes(32)

        self.utilized_credit = PWNUtilizedCredit.deploy(
            self.hub, self.utilized_credit_tag
        )
        self.hub.setTag(
            self.utilized_credit, self.utilized_credit_tag, True, from_=self.owner
        )

        self.loan_token = PWNLOAN.deploy(self.hub)
        self.vault = PWNSimpleLoan.deploy(
            self.hub,
            self.loan_token,
            self.config,
            self.revoked_nonce,
            self.multi_token_registry,
        )

        self.elastic_proposal = PWNSimpleLoanElasticProposal.deploy(
            self.hub, self.revoked_nonce, self.config, self.utilized_credit
        )
        self.dutch_auction_proposal = PWNSimpleLoanDutchAuctionProposal.deploy(
            self.hub, self.revoked_nonce, self.config, self.utilized_credit
        )
        self.simple_proposal = PWNSimpleLoanSimpleProposal.deploy(
            self.hub, self.revoked_nonce, self.config, self.utilized_credit
        )
        self.list_proposal = PWNSimpleLoanListProposal.deploy(
            self.hub, self.revoked_nonce, self.config, self.utilized_credit
        )

        self.elastic_chainlink_proposal = PWNSimpleLoanElasticChainlinkProposal.deploy(
            self.hub,
            self.revoked_nonce,
            self.config,
            self.utilized_credit,
            Address("0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf"),
            Address.ZERO,
            TOKENS[0]["WETH"],
        )

        self.hub.setTags(
            [
                self.elastic_proposal,
                self.dutch_auction_proposal,
                self.simple_proposal,
                self.elastic_chainlink_proposal,
                self.list_proposal,
            ],
            [LOAN_PROPOSAL_TAG] * 5,
            True,
            from_=self.owner,
        )
        self.hub.setTag(
            self.simple_proposal, NONCE_MANAGER_TAG, True, from_=self.owner
        )  # nonce updator
        self.hub.setTag(
            self.list_proposal, NONCE_MANAGER_TAG, True, from_=self.owner
        )  # nonce updator

        self.hub.setTag(self.vault, NONCE_MANAGER_TAG, True, from_=self.owner)
        self.hub.setTag(self.vault, ACTIVE_LOAN_TAG, True, from_=self.owner)

        self._register_tokens()

        # remove lator
        self.erc20_balances = defaultdict(lambda: defaultdict(int))
        self.erc721_owners = defaultdict(lambda: defaultdict(Account))
        self.erc1155_balances = defaultdict(lambda: defaultdict(int))
        self.local_tokens: Dict[int, Account] = {
            MultiToken.Category.ERC20: RichERC20.deploy("rich20", "rich20", 0),
            MultiToken.Category.ERC721: RichERC721.deploy(),
            MultiToken.Category.ERC1155: RichERC1155.deploy("rich1155"),
        }

        self.erc1155_support_ids = [1, 4, 11, 32]

        self.erc20_balances[self.local_tokens[MultiToken.Category.ERC20]] = defaultdict(
            int
        )
        self.erc721_owners[self.local_tokens[MultiToken.Category.ERC721]] = defaultdict(
            Account
        )
        self.erc721_owners[self.loan_token] = defaultdict(
            Account
        )  # loan token is also ERC721
        self.erc1155_balances[self.local_tokens[MultiToken.Category.ERC1155]] = (
            defaultdict(int)
        )

        for category, token in self.local_tokens.items():
            self.multi_token_registry.registerCategoryValue(token.address, category)

        self.vault_owner = random_account(
            predicate=lambda acc: acc != self.proxy_control_owner
            and acc != self.fee_collector
            and acc != self.owner
        )
        self.simple_vault = SimpleVault.deploy(
            self.local_tokens[MultiToken.Category.ERC20],
            "simple vault",
            "simple vault",
            from_=self.vault_owner,
        )

        self.config.registerPoolAdapter(
            self.simple_vault.address, self.erc4626_adapter.address, from_=self.owner
        )


    def _register_tokens(self):
        for category, tokens in TOKENS.items():
            for token, token_address in tokens.items():
                self.multi_token_registry.registerCategoryValue(token_address, category)

    @flow()
    def flow_create_loan_with_simple_proposal(self):
        # self.fee_collector call then the fee transfer check fail. since fee_collector balance does not changes.

        lender = random_account(
            predicate=lambda acc: acc != self.proxy_control_owner
            and acc != self.fee_collector
        )

        use_vault = random_bool()

        if use_vault:
            lender = self.vault_owner

        borrower = random_account(
            predicate=lambda acc: acc != self.proxy_control_owner
            and acc != self.fee_collector
            and acc != lender
        )

        if lender not in self.nonce:
            self.nonce[lender] = 0

        collateral_category = random.choice(
            [
                MultiToken.Category.ERC20,
                MultiToken.Category.ERC721,
                MultiToken.Category.ERC1155,
            ]
            # [ MultiToken.Category.ERC721, MultiToken.Category.ERC1155]
        )
        collateral_token = self.local_tokens[collateral_category]

        credit_token = self.local_tokens[MultiToken.Category.ERC20]

        collateral_id = 0
        if collateral_category == MultiToken.Category.ERC1155:
            collateral_id = random.choice(self.erc1155_support_ids)
        elif collateral_category == MultiToken.Category.ERC721:
            collateral_id = random_int(0, 2**256 - 1)
        elif collateral_category == MultiToken.Category.ERC20:
            collateral_id = 0
        else:
            raise Error

        proposal_config = PWNSimpleLoanSimpleProposal.Proposal(
            collateralCategory=collateral_category,
            collateralAddress=collateral_token.address,  # Assuming t1155 is your ERC1155 token contract
            collateralId=collateral_id,
            collateralAmount=(
                random_int(0, 100 * 10**18)
                if collateral_category != MultiToken.Category.ERC721
                else 0
            ),  # 10 tokens with 18 decimals
            checkCollateralStateFingerprint=False,
            collateralStateFingerprint=bytes(32),
            creditAddress=credit_token.address,  # CREDIT is only ERC20e
            creditAmount=random_int(0, 10 * 10**18),
            availableCreditLimit=0,
            utilizedCreditId=random_bytes(32),
            fixedInterestAmount=random_int(0, 100_000),
            accruingInterestAPR=random_int(0, MAX_APR, max_prob=0.5),
            durationOrDate=random_duration_or_date(),
            expiration=random_int(0, uint40.max),
            allowedAcceptor=Address.ZERO,
            proposer=lender.address,
            proposerSpecHash=keccak256(
                abi.encode(
                    PWNSimpleLoan.LenderSpec(
                        lender.address if not use_vault else self.simple_vault.address
                    )
                )
            ),
            isOffer=True,
            refinancingLoanId=0,
            nonceSpace=0,
            nonce=self.nonce[lender],
            loanContract=self.vault.address,
        )
        tx = self.simple_proposal.makeProposal(proposal_config, from_=lender)

        proposal_hash = tx.return_value

        self.nonce[lender] += 1
        self.proposals_from_simple[proposal_hash] = ProposalInfo(
            lender=lender,
            borrower=borrower,
            third_party=None,
            collrateral_token=proposal_config.collateralAddress,
            credit_token=credit_token,
            proposal_config=proposal_config,
            default_timestamp=0,
            actual_repaying_amount=0,
            refinancing_loan_id=None,
            user_vault=self.simple_vault if use_vault else None,
            proposal_type=ProposalType.SIMPLE,
            collateral_id=collateral_id,
        )
        self.pending_proposal_hash.append(proposal_hash)

        logger.info(
            f"Create Loan propose in {self.simple_proposal}, lender={lender} borrower={borrower} use_vault={use_vault}"
        )

    # @flow()
    def flow_create_loan_with_list_proposal(self):
        # self.fee_collector call then the fee transfer check fail. since fee_collector balance does not changes.

        lender = random_account(
            predicate=lambda acc: acc != self.proxy_control_owner
            and acc != self.fee_collector
        )

        use_vault = random_bool()

        if use_vault:
            lender = self.vault_owner

        borrower = random_account(
            predicate=lambda acc: acc != self.proxy_control_owner
            and acc != self.fee_collector
            and acc != lender
        )

        if lender not in self.nonce:
            self.nonce[lender] = 0

        collateral_category = random.choice(
            [
                MultiToken.Category.ERC20,
                MultiToken.Category.ERC721,
                MultiToken.Category.ERC1155,
            ]
            # [ MultiToken.Category.ERC721, MultiToken.Category.ERC1155]
        )
        collateral_token = self.local_tokens[collateral_category]

        credit_token = self.local_tokens[MultiToken.Category.ERC20]

        proposal_config = PWNSimpleLoanListProposal.Proposal(
            collateralCategory=collateral_category,
            collateralAddress=collateral_token.address,
            collateralIdsWhitelistMerkleRoot=bytes(32),  # Empty merkle root
            collateralAmount=(
                random_int(0, 100 * 10**18)
                if collateral_category != MultiToken.Category.ERC721
                else 0
            ),
            checkCollateralStateFingerprint=False,
            collateralStateFingerprint=bytes(32),
            creditAddress=credit_token.address,
            creditAmount=random_int(0, 10 * 10**18),
            availableCreditLimit=0,
            utilizedCreditId=random_bytes(32),
            fixedInterestAmount=random_int(0, 100_000),
            accruingInterestAPR=random_int(0, MAX_APR, max_prob=0.5),
            durationOrDate=random_duration_or_date(),
            expiration=random_int(0, uint40.max),
            allowedAcceptor=Address.ZERO,
            proposer=lender.address,
            proposerSpecHash=keccak256(
                abi.encode(
                    PWNSimpleLoan.LenderSpec(
                        lender.address if not use_vault else self.simple_vault.address
                    )
                )
            ),
            isOffer=True,
            refinancingLoanId=0,
            nonceSpace=0,
            nonce=self.nonce[lender],
            loanContract=self.vault.address,
        )
        tx = self.list_proposal.makeProposal(proposal_config, from_=lender)

        proposal_hash = tx.return_value

        self.nonce[lender] += 1
        self.proposals_from_simple[proposal_hash] = ProposalInfo(
            lender=lender,
            borrower=borrower,
            third_party=None,
            collrateral_token=proposal_config.collateralAddress,
            credit_token=credit_token,
            proposal_config=proposal_config,
            default_timestamp=0,
            actual_repaying_amount=0,
            refinancing_loan_id=None,
            user_vault=self.simple_vault if use_vault else None,
            proposal_type=ProposalType.LIST,
            collateral_id=None,
        )
        self.pending_proposal_hash.append(proposal_hash)

        logger.info(
            f"Create Loan propose in {self.simple_proposal}, lender={lender} borrower={borrower} use_vault={use_vault}"
        )

    @flow(precondition=lambda self: len(self.pending_proposal_hash) != 0, weight=1000)
    def flow_create_loan_from_proposal(self):
        proposal_hash = random.choice(self.pending_proposal_hash)
        proposal_info = self.proposals_from_simple[proposal_hash]

        use_vault = True if proposal_info.user_vault is not None else False

        lender = proposal_info.lender
        borrower = proposal_info.borrower

        signature = b""

        if proposal_info.proposal_type == ProposalType.SIMPLE:
            proposal_data = self.simple_proposal.encodeProposalData(
                proposal_info.proposal_config
            )

            proposal_config: PWNSimpleLoanSimpleProposal.Proposal = (
                proposal_info.proposal_config
            )

            collateral_id = proposal_info.collateral_id

        elif proposal_info.proposal_type == ProposalType.LIST:
            proposal_config: PWNSimpleLoanListProposal.Proposal = (
                proposal_info.proposal_config
            )

            collateral_id = (
                random_int(0, 2**256 - 1)
                if proposal_config.collateralCategory != MultiToken.Category.ERC20
                else 0
            )

            proposal_data = self.list_proposal.encodeProposalData(
                proposal=proposal_info.proposal_config,
                proposalValues=PWNSimpleLoanListProposal.ProposalValues(
                    collateral_id,
                    merkleInclusionProof=[],
                ),
            )

            hash = self.list_proposal.getProposalHash(proposal_config)
            assert hash == proposal_hash

        if proposal_config.collateralCategory == MultiToken.Category.ERC20:
            mint_erc20(
                Account(proposal_config.collateralAddress, chain=chain),
                borrower,
                proposal_config.collateralAmount,
            )
            with may_revert():
                IERC20(proposal_config.collateralAddress).approve(
                    self.vault, 0, from_=borrower
                )
            IERC20(proposal_config.collateralAddress).approve(
                self.vault, proposal_config.collateralAmount, from_=borrower
            )

            self.erc20_balances[
                IERC20(Account(proposal_config.collateralAddress, chain=chain))
            ][borrower] += proposal_config.collateralAmount

        elif proposal_config.collateralCategory == MultiToken.Category.ERC721:
            mint_erc721(
                Account(proposal_config.collateralAddress, chain=chain),
                borrower,
                collateral_id,
                owner_mapping_slot=2,
            )
            IERC721(proposal_config.collateralAddress).approve(
                self.vault, collateral_id, from_=borrower
            )

            self.erc721_owners[
                IERC721(Account(proposal_config.collateralAddress, chain=chain))
            ][collateral_id] = borrower
        # borrower need corateral token and approved
        elif proposal_config.collateralCategory == MultiToken.Category.ERC1155:
            mint_erc1155(
                Account(proposal_config.collateralAddress, chain=chain),
                borrower,
                collateral_id,
                proposal_config.collateralAmount,
            )
            IERC1155(proposal_config.collateralAddress).setApprovalForAll(
                self.vault, True, from_=borrower
            )

            self.erc1155_balances[IERC1155(proposal_config.collateralAddress)][
                (collateral_id, borrower)
            ] += proposal_config.collateralAmount

        mint_erc20(
            Account(proposal_config.creditAddress, chain=chain),
            lender,
            proposal_config.creditAmount,
        )
        if use_vault:
            IERC20(proposal_config.creditAddress).approve(
                proposal_info.user_vault, proposal_config.creditAmount, from_=lender
            )
            proposal_info.user_vault.deposit(
                proposal_config.creditAmount, lender, from_=lender
            )
            proposal_info.user_vault.approve(
                self.erc4626_adapter, proposal_config.creditAmount, from_=lender
            )
            IERC20(proposal_config.creditAddress).approve(
                self.vault, proposal_config.creditAmount, from_=lender
            )

            self.erc20_balances[IERC20(proposal_config.creditAddress)][
                proposal_info.user_vault
            ] += proposal_config.creditAmount

        else:

            IERC20(proposal_config.creditAddress).approve(
                self.vault, proposal_config.creditAmount, from_=lender
            )
            self.erc20_balances[IERC20(proposal_config.creditAddress)][
                lender
            ] += proposal_config.creditAmount

        proposal_contract = self.simple_proposal.address
        if proposal_info.proposal_type == ProposalType.LIST:
            proposal_contract = self.list_proposal.address

        proposal_spec = PWNSimpleLoan.ProposalSpec(
            proposalContract=proposal_contract,
            proposalData=proposal_data,  # This is the proposal object we created earlier
            proposalInclusionProof=[],  # Empty bytes32 array
            signature=signature,  # Empty signature, you might need to generate a real signature
        )
        #  PWNSimpleLoan.LenderSpec(lender.address if not use_vault else self.vault_owner.address))
        lender_spec = PWNSimpleLoan.LenderSpec(
            sourceOfFunds=(
                lender.address if not use_vault else proposal_info.user_vault.address
            )
        )

        if borrower not in self.nonce:
            self.nonce[borrower] = 0

        caller_spec = PWNSimpleLoan.CallerSpec(
            refinancingLoanId=0,
            revokeNonce=False,
            nonce=self.nonce[borrower],
            permitData=bytes(0),  # Empty bytes
        )

        # Duration of a loan in seconds. If the value is greater than 10^9, it is treated as a timestamp of a loan end.

        with may_revert() as e:
            tx = self.vault.createLOAN(
                proposal_spec,
                lender_spec,
                caller_spec,
                bytes(0),  # extra parameter as empty bytes
                from_=borrower,  # Call from borrower account
            )

        if proposal_config.durationOrDate > 10**9:
            duration = proposal_config.durationOrDate - chain.blocks["latest"].timestamp
            if duration <= 0:
                assert e.value == PWNSimpleLoanSimpleProposal.DefaultDateInPast(
                    proposal_config.durationOrDate, chain.blocks["latest"].timestamp
                )
                self.pending_proposal_hash.remove(proposal_hash)
                logger.info(
                    f"Loan creation fail because of duration timestamp is in the past"
                )
                return
        else:
            duration = proposal_config.durationOrDate

        if proposal_config.expiration < chain.blocks["latest"].timestamp:
            assert e.value == Expired(
                chain.blocks["latest"].timestamp, proposal_config.expiration
            )
            self.pending_proposal_hash.remove(proposal_hash)
            logger.info(f"Loan creation fail because of proposal expiration")
            return

        if duration < 10 * 60:
            assert e.value == PWNSimpleLoan.InvalidDuration(duration, 10 * 60)

            self.pending_proposal_hash.remove(proposal_hash)
            logger.info(
                f"Loan creation fail because of duration is less than 10 minutes"
            )
            return

        assert e.value is None
        loan_id = tx.return_value

        event = next(e for e in tx.events if isinstance(e, PWNSimpleLoan.LOANCreated))
        assert event.proposalContract == proposal_contract
        assert event.proposalHash == proposal_hash
        assert event.refinancingLoanId == 0
        assert event.extra == b""
        assert event.terms.lender == lender.address
        assert event.terms.borrower == borrower.address
        assert event.lenderSpec.sourceOfFunds == (
            lender.address if not use_vault else proposal_info.user_vault.address
        )
        assert event.terms.collateral.category == proposal_config.collateralCategory
        assert event.terms.collateral.assetAddress == proposal_config.collateralAddress
        assert event.terms.collateral.id == collateral_id
        assert event.terms.collateral.amount == proposal_config.collateralAmount
        assert event.terms.credit.assetAddress == proposal_config.creditAddress
        assert (
            event.terms.credit.id == MultiToken.Category.ERC20
        )  # credit is only ERC20
        assert event.terms.credit.amount == proposal_config.creditAmount

        collateral_token = Account(proposal_config.collateralAddress, chain=chain)
        # corrateral send to vault
        if proposal_config.collateralCategory == MultiToken.Category.ERC20:
            self.erc20_balances[IERC20(collateral_token)][
                borrower
            ] -= proposal_config.collateralAmount
            self.erc20_balances[IERC20(collateral_token)][
                self.vault
            ] += proposal_config.collateralAmount
        elif proposal_config.collateralCategory == MultiToken.Category.ERC721:
            self.erc721_owners[IERC721(collateral_token)][collateral_id] = self.vault
        elif proposal_config.collateralCategory == MultiToken.Category.ERC1155:
            self.erc1155_balances[IERC1155(collateral_token)][
                (collateral_id, borrower)
            ] -= proposal_config.collateralAmount
            self.erc1155_balances[IERC1155(collateral_token)][
                (collateral_id, self.vault)
            ] += proposal_config.collateralAmount

        credit_token = IERC20(Account(proposal_config.creditAddress, chain=chain))

        proposal_info.collateral_id = collateral_id

        if use_vault:
            self.erc20_balances[credit_token][
                proposal_info.user_vault
            ] -= proposal_config.creditAmount
        else:
            self.erc20_balances[credit_token][lender] -= proposal_config.creditAmount

        fee_amount = (proposal_config.creditAmount * self.fee) // 10000
        after_fee_amount = proposal_config.creditAmount - fee_amount

        self.erc20_balances[credit_token][self.fee_collector] += fee_amount

        self.erc20_balances[credit_token][borrower] += after_fee_amount

        event = next(e for e in tx.events if isinstance(e, PWNLOAN.Transfer))
        assert event.from_ == Address.ZERO
        assert event.to == lender.address
        assert event.tokenId == loan_id

        event = next(e for e in tx.events if isinstance(e, PWNLOAN.LOANMinted))
        assert event.loanId == loan_id
        assert event.loanContract == self.vault.address
        assert event.owner == lender.address

        self.erc721_owners[IERC721(self.loan_token)][loan_id] = lender

        if proposal_config.durationOrDate > 10**9:
            proposal_info.default_timestamp = proposal_config.durationOrDate
        else:
            proposal_info.default_timestamp = (
                chain.blocks["latest"].timestamp + proposal_config.durationOrDate
            )

        self.nonce[borrower] += 1

        self.running_loan_id.append(loan_id)
        self.proposals_from_loan_id[loan_id] = proposal_info
        self.pending_proposal_hash.remove(proposal_hash)

        logger.info(
            f"Created loan {loan_id} lender={lender}, borrower={borrower} use_vault={use_vault}"
        )

    @flow(precondition=lambda self: len(self.running_loan_id) != 0)
    def flow_create_refinancing_loan_proposal(self):
        refinancing_loan_id = random.choice(self.running_loan_id)
        refinancing_proposal_info = self.proposals_from_loan_id[refinancing_loan_id]
        refinancing_proposal_config: PWNSimpleLoanSimpleProposal.Proposal = (
            refinancing_proposal_info.proposal_config
        )
        # self.fee_collector call then the fee transfer check fail. since fee_collector balance does not changes.
        borrower = refinancing_proposal_info.borrower
        lender = random_account(
            predicate=lambda acc: acc != borrower
            and acc != self.proxy_control_owner
            and acc != self.fee_collector
        )

        if lender not in self.nonce:
            self.nonce[lender] = 0

        third_guy = random_account(
            predicate=lambda acc: acc != borrower
            and acc != self.proxy_control_owner
            and acc != self.fee_collector
            and acc != lender
            and acc != borrower
        )

        credit_token = self.local_tokens[MultiToken.Category.ERC20]

        proposal_config = PWNSimpleLoanSimpleProposal.Proposal(
            collateralCategory=refinancing_proposal_config.collateralCategory,  # necessary match
            collateralAddress=refinancing_proposal_config.collateralAddress,  # necessary match
            collateralId=refinancing_proposal_info.collateral_id,  # necessary match
            collateralAmount=refinancing_proposal_config.collateralAmount,  # necessary match
            checkCollateralStateFingerprint=False,
            collateralStateFingerprint=bytes(32),
            creditAddress=refinancing_proposal_config.creditAddress,  # necessary match
            creditAmount=random_int(0, 10 * 10**18),  # can increase , can decrease
            availableCreditLimit=0,
            utilizedCreditId=random_bytes(32),
            fixedInterestAmount=random_int(0, 100_000),
            accruingInterestAPR=random_int(0, MAX_APR, max_prob=0.5),
            durationOrDate=random_duration_or_date(),  # 7 days in seconds
            expiration=random_int(0, uint40.max),  # current time + 1 day
            allowedAcceptor=Address.ZERO,
            proposer=lender.address,
            proposerSpecHash=keccak256(
                abi.encode(PWNSimpleLoan.LenderSpec(lender.address))
            ),
            isOffer=True,  # make false to propose from borrowe
            refinancingLoanId=0,
            nonceSpace=0,
            nonce=self.nonce[lender],
            loanContract=self.vault.address,
        )
        tx = self.simple_proposal.makeProposal(proposal_config, from_=lender)

        proposal_hash = tx.return_value

        self.nonce[lender] += 1
        self.proposals_from_simple[proposal_hash] = ProposalInfo(
            lender=lender,
            borrower=borrower,
            third_party=third_guy,
            collrateral_token=proposal_config.collateralAddress,
            credit_token=credit_token,
            proposal_config=proposal_config,
            default_timestamp=0,
            actual_repaying_amount=0,
            refinancing_loan_id=refinancing_loan_id,
            user_vault=None,
            proposal_type=ProposalType.SIMPLE,
            collateral_id=refinancing_proposal_info.collateral_id,
        )

        self.pending_refinancing_proposal_hash.append(proposal_hash)

        logger.info(
            f"Create Loan propose in {self.simple_proposal}, lender={lender} borrower={borrower}"
        )

    @flow(
        precondition=lambda self: len(self.pending_refinancing_proposal_hash) != 0,
        weight=100,
    )
    def flow_create_refinancing_loan_from_proposal(self):

        proposal_hash = random.choice(self.pending_refinancing_proposal_hash)
        proposal_info = self.proposals_from_simple[proposal_hash]

        lender = proposal_info.lender
        borrower = proposal_info.borrower

        signature = b""

        proposal_data = self.simple_proposal.encodeProposalData(
            proposal_info.proposal_config
        )

        proposal_config: PWNSimpleLoanSimpleProposal.Proposal = (
            proposal_info.proposal_config
        )

        refinancing_proposal_info = self.proposals_from_loan_id[
            proposal_info.refinancing_loan_id
        ]

        if proposal_info.refinancing_loan_id not in self.running_loan_id:
            self.pending_refinancing_proposal_hash.remove(proposal_hash)
            return

        refinancing_proposal_config: PWNSimpleLoanSimpleProposal.Proposal = (
            refinancing_proposal_info.proposal_config
        )

        refinancing_loan_owner = self.erc721_owners[IERC721(self.loan_token)][
            proposal_info.refinancing_loan_id
        ]

        fee_amount = (proposal_config.creditAmount * self.fee) // 10000
        after_fee_amount = proposal_config.creditAmount - fee_amount

        (
            status,
            start_timestamp,
            default_timestamp,
            borrower_loan,
            original_lender,
            loan_owner,
            accruing_interest_apr,
            fixed_interest_amount,
            credit_loan,
            collateral,
            original_source_of_funds,
            repayment_amount,
        ) = self.vault.getLOAN(proposal_info.refinancing_loan_id)
        calculation_timestamp = chain.blocks["latest"].timestamp + 20
        if refinancing_proposal_config.accruingInterestAPR > 0:
            accruing_minutes = (
                calculation_timestamp - start_timestamp
            ) // 60  # 10 seconds future for approve
            accrued_interest = (
                refinancing_proposal_config.creditAmount
                * refinancing_proposal_config.accruingInterestAPR
                * accruing_minutes
            ) // (10_000 * 525600)
            total_interest = (
                refinancing_proposal_config.fixedInterestAmount + accrued_interest
            )
        else:
            total_interest = refinancing_proposal_config.fixedInterestAmount

        repayment_amount = (
            refinancing_proposal_config.creditAmount + total_interest
        )  # repayment amount
        diff = after_fee_amount - repayment_amount

        comm = min(after_fee_amount, repayment_amount)

        if (
            lender
            == self.erc721_owners[IERC721(self.loan_token)][
                proposal_info.refinancing_loan_id
            ]
            and refinancing_proposal_info.user_vault == proposal_info.user_vault
        ):
            # only diff is required.

            # surplus
            if diff > 0:
                # lender need to pay fee and surplus

                if refinancing_proposal_info.lender != refinancing_loan_owner:
                    lender_require = diff + fee_amount + repayment_amount
                else:
                    lender_require = diff + fee_amount
                    # this case comm required to pay.
                    # repayment_amount

                mint_erc20(
                    Account(proposal_config.creditAddress, chain=chain),
                    lender,
                    lender_require,
                )

                IERC20(proposal_config.creditAddress).approve(
                    self.vault, lender_require, from_=lender
                )
                self.erc20_balances[IERC20(proposal_config.creditAddress)][
                    lender
                ] += lender_require
            # shortage
            else:
                if refinancing_proposal_info.lender != refinancing_loan_owner:
                    # this case comm required to pay.
                    lender_require = fee_amount + repayment_amount
                else:
                    lender_require = fee_amount

                # lender need to pay fee
                mint_erc20(
                    Account(proposal_config.creditAddress, chain=chain),
                    lender,
                    lender_require,
                )
                IERC20(proposal_config.creditAddress).approve(
                    self.vault, lender_require, from_=lender
                )
                self.erc20_balances[IERC20(proposal_config.creditAddress)][
                    lender
                ] += lender_require
                # borrower need to pay the shortage of loan.

                borrower_require = -diff
                # print(f"borrower require (shortage): {borrower_require}")
                mint_erc20(
                    Account(proposal_config.creditAddress, chain=chain),
                    borrower,
                    borrower_require,
                )
                IERC20(proposal_config.creditAddress).approve(
                    self.vault, borrower_require, from_=borrower
                )
                self.erc20_balances[IERC20(proposal_config.creditAddress)][
                    borrower
                ] += borrower_require
        else:

            # all credit is required for lender which is loan_token owner
            # print(f"lender {lender} is not the owner of the loan token")
            # print(
            #     f"new lender require credit for repay previous loan (similar as sending borrower) {proposal_config.creditAmount}"
            # )

            mint_erc20(
                Account(proposal_config.creditAddress, chain=chain),
                lender,
                proposal_config.creditAmount,
            )
            IERC20(proposal_config.creditAddress).approve(
                self.vault, proposal_config.creditAmount, from_=lender
            )

            if proposal_info.user_vault is not None:
                proposal_info.user_vault.deposit(
                    proposal_config.creditAmount, lender, from_=lender
                )
                proposal_info.user_vault.approve(
                    self.erc4626_adapter, proposal_config.creditAmount, from_=lender
                )
                self.erc20_balances[IERC20(proposal_config.creditAddress)][
                    proposal_info.user_vault
                ] += proposal_config.creditAmount
            else:
                self.erc20_balances[IERC20(proposal_config.creditAddress)][
                    lender
                ] += proposal_config.creditAmount

            if diff < 0:
                mint_erc20(
                    Account(proposal_config.creditAddress, chain=chain),
                    borrower,
                    -diff,
                )
                IERC20(proposal_config.creditAddress).approve(
                    self.vault, -diff, from_=borrower
                )
                self.erc20_balances[IERC20(proposal_config.creditAddress)][
                    borrower
                ] += -diff

        proposal_spec = PWNSimpleLoan.ProposalSpec(
            proposalContract=self.simple_proposal.address,
            proposalData=proposal_data,  # This is the proposal object we created earlier
            proposalInclusionProof=[],  # Empty bytes32 array
            signature=signature,  # Empty signature, you might need to generate a real signature
        )

        lender_spec = PWNSimpleLoan.LenderSpec(sourceOfFunds=lender.address)

        if borrower not in self.nonce:
            self.nonce[borrower] = 0

        caller_spec = PWNSimpleLoan.CallerSpec(
            refinancingLoanId=proposal_info.refinancing_loan_id,
            revokeNonce=False,
            nonce=self.nonce[borrower],
            permitData=bytes(0),  # Empty bytes
        )

        assert chain.blocks["latest"].timestamp < calculation_timestamp
        # Duration of a loan in seconds. If the value is greater than 10^9, it is treated as a timestamp of a loan end
        chain.mine(
            lambda t: t + calculation_timestamp - chain.blocks["latest"].timestamp - 1
        )

        with may_revert() as e:
            tx = self.vault.createLOAN(
                proposal_spec,
                lender_spec,
                caller_spec,
                bytes(0),  # extra parameter as empty bytes
                from_=borrower,  # Call from borrower account
            )
            # print(tx.call_trace)
            # print(tx.events)

        # print(IERC20(proposal_config.creditAddress).balanceOf(self.vault))

        if (
            refinancing_proposal_info.default_timestamp
            < chain.blocks["latest"].timestamp
        ):
            assert e.value == PWNSimpleLoan.LoanDefaulted(
                refinancing_proposal_info.default_timestamp
            )
            self.pending_refinancing_proposal_hash.remove(proposal_hash)
            return

        if proposal_config.durationOrDate > 10**9:
            duration = proposal_config.durationOrDate - chain.blocks["latest"].timestamp
            if duration < 0:
                assert e.value == PWNSimpleLoanSimpleProposal.DefaultDateInPast(
                    proposal_config.durationOrDate, chain.blocks["latest"].timestamp
                )
                self.pending_refinancing_proposal_hash.remove(proposal_hash)
                logger.info(
                    f"Loan creation fail because of duration timestamp is in the past"
                )
                return
        else:
            duration = proposal_config.durationOrDate

        if duration < 10 * 60:
            assert e.value == PWNSimpleLoan.InvalidDuration(duration, 10 * 60)

            self.pending_refinancing_proposal_hash.remove(proposal_hash)
            logger.info(
                f"Loan creation fail because of duration is less than 10 minutes"
            )
            return

        if proposal_config.expiration < chain.blocks["latest"].timestamp:
            assert e.value == Expired(
                chain.blocks["latest"].timestamp, proposal_config.expiration
            )
            self.pending_refinancing_proposal_hash.remove(proposal_hash)
            logger.info(f"Loan creation fail because of proposal expiration")
            return

        assert e.value is None
        loan_id = tx.return_value

        event = next(e for e in tx.events if isinstance(e, PWNSimpleLoan.LOANCreated))
        assert event.proposalContract == self.simple_proposal.address
        assert event.proposalHash == proposal_hash
        assert event.refinancingLoanId == proposal_info.refinancing_loan_id
        assert event.extra == b""
        assert event.terms.lender == lender.address
        assert event.terms.borrower == borrower.address
        assert event.lenderSpec.sourceOfFunds == lender.address
        assert event.terms.collateral.category == proposal_config.collateralCategory
        assert event.terms.collateral.assetAddress == proposal_config.collateralAddress
        assert event.terms.collateral.id == proposal_info.collateral_id
        assert event.terms.collateral.amount == proposal_config.collateralAmount
        assert event.terms.credit.assetAddress == proposal_config.creditAddress
        assert (
            event.terms.credit.id == MultiToken.Category.ERC20
        )  # credit is only ERC20
        assert event.terms.credit.amount == proposal_config.creditAmount

        # Nothing change about collateral

        credit_token = IERC20(Account(proposal_config.creditAddress, chain=chain))

        fee_amount = (proposal_config.creditAmount * self.fee) // 10000
        after_fee_amount = proposal_config.creditAmount - fee_amount

        # print(f"the fee of this loan is {fee_amount}")
        # print(f"the after fee amount(the loan price ) is {after_fee_amount}")

        self.erc20_balances[credit_token][self.fee_collector] += fee_amount

        if refinancing_proposal_config.accruingInterestAPR > 0:
            accruing_minutes = (
                chain.blocks["latest"].timestamp - start_timestamp
            ) // 60  # Division by 1 minutes
            accrued_interest = (
                refinancing_proposal_config.creditAmount
                * refinancing_proposal_config.accruingInterestAPR
                * accruing_minutes
            ) // (100_00 * 525600)
            total_interest = (
                refinancing_proposal_config.fixedInterestAmount + accrued_interest
            )
        else:
            total_interest = refinancing_proposal_config.fixedInterestAmount

        repayment_amount = refinancing_proposal_config.creditAmount + total_interest

        # different loan owner

        event = next(e for e in tx.events if isinstance(e, PWNLOAN.LOANMinted))
        assert event.loanId == loan_id
        assert event.loanContract == self.vault.address
        assert event.owner == lender.address

        event = next(e for e in tx.events if isinstance(e, PWNSimpleLoan.LOANPaidBack))
        assert event.loanId == proposal_info.refinancing_loan_id

        self.erc721_owners[IERC721(self.loan_token)][loan_id] = lender

        if proposal_config.durationOrDate > 10**9:
            proposal_info.default_timestamp = proposal_config.durationOrDate
        else:
            proposal_info.default_timestamp = (
                chain.blocks["latest"].timestamp + proposal_config.durationOrDate
            )

        self.running_loan_id.remove(proposal_info.refinancing_loan_id)
        self.claimable_loan_id.append(proposal_info.refinancing_loan_id)

        self.nonce[borrower] += 1

        self.running_loan_id.append(loan_id)
        self.proposals_from_loan_id[loan_id] = proposal_info
        self.pending_refinancing_proposal_hash.remove(proposal_hash)
        if lender == refinancing_loan_owner and (
            refinancing_proposal_info.lender != refinancing_loan_owner
            or refinancing_proposal_info.user_vault == proposal_info.user_vault
        ):
            # no comm

            # this case only diff will pay
            self.erc20_balances[IERC20(proposal_config.creditAddress)][
                lender
            ] -= fee_amount
            # which will be withdrawn
            if diff > 0:
                # print("surplus, ", diff)
                refinancing_proposal_info.actual_repaying_amount = 0
                self.erc20_balances[IERC20(proposal_config.creditAddress)][
                    lender
                ] -= diff  # lender payed surplus

                self.erc20_balances[IERC20(proposal_config.creditAddress)][
                    borrower
                ] += diff  # lender payed surplus
            else:
                # print("shortage")
                diff = -diff
                refinancing_proposal_info.actual_repaying_amount = (
                    diff  # about refinanced loan
                )
                self.erc20_balances[IERC20(proposal_config.creditAddress)][
                    borrower
                ] -= diff

                self.erc20_balances[credit_token][
                    self.vault
                ] += diff  # which will be withdrawn

        else:
            # print("sending everything to the vault")
            # self.erc20_balances[credit_token][self.vault] += 0 nothing will be wieth
            if proposal_info.user_vault is None:
                self.erc20_balances[IERC20(proposal_config.creditAddress)][
                    lender
                ] -= proposal_config.creditAmount
            else:
                self.erc20_balances[IERC20(proposal_config.creditAddress)][
                    proposal_info.user_vault
                ] -= proposal_config.creditAmount

            # pay common as well

            self.erc20_balances[IERC20(proposal_config.creditAddress)][
                self.vault
            ] += repayment_amount

            self.erc20_balances[IERC20(proposal_config.creditAddress)][borrower] += diff

            refinancing_proposal_info.actual_repaying_amount = repayment_amount

        # tryClaimRepaidLOAN
        # print(f"refinancing_proposal_info.lender: {refinancing_proposal_info.lender}")
        # print(
        #     f"self.erc721_owners[IERC721(self.loan_token)][proposal_info.refinancing_loan_id]: {self.erc721_owners[IERC721(self.loan_token)][proposal_info.refinancing_loan_id]}"
        # )
        if (
            refinancing_proposal_info.lender
            == self.erc721_owners[IERC721(self.loan_token)][
                proposal_info.refinancing_loan_id
            ]
        ):
            logger.info(
                f"claim on refinancing loan {proposal_info.refinancing_loan_id}"
            )
            event = next(e for e in tx.events if isinstance(e, PWNLOAN.LOANBurned))
            assert event.loanId == proposal_info.refinancing_loan_id
            self.erc721_owners[IERC721(self.loan_token)][
                proposal_info.refinancing_loan_id
            ] = None
            self.burned_loan_id.append(proposal_info.refinancing_loan_id)

            event = next(
                e for e in tx.events if isinstance(e, PWNSimpleLoan.LOANClaimed)
            )
            assert event.loanId == proposal_info.refinancing_loan_id
            assert event.defaulted == False
            self.erc20_balances[credit_token][
                self.vault
            ] -= refinancing_proposal_info.actual_repaying_amount
            if refinancing_proposal_info.user_vault is not None:
                event = next(
                    e for e in tx.events if isinstance(e, PWNSimpleLoan.PoolSupply)
                )
                assert event.asset.assetAddress == proposal_config.creditAddress
                assert event.owner == refinancing_proposal_info.lender.address
                self.erc20_balances[credit_token][
                    self.simple_vault
                ] += refinancing_proposal_info.actual_repaying_amount
            else:
                self.erc20_balances[credit_token][
                    refinancing_proposal_info.lender
                ] += refinancing_proposal_info.actual_repaying_amount

            self.claimable_loan_id.remove(proposal_info.refinancing_loan_id)
        else:

            # print(
            #     "try claim fails, comm:", comm
            # )
            any(e for e in tx.events if isinstance(e, PWNLOAN.LOANBurned))
            # ------------------HOTFIX applied

            if lender == refinancing_loan_owner and (
                refinancing_proposal_info.lender != refinancing_loan_owner
                or refinancing_proposal_info.user_vault == proposal_info.user_vault
            ):
                logger.critical(f"comm: {comm} does not sent, lender: {lender}, refinancing loan: {proposal_config.refinancingLoanId}")
                # refinancing_proposal_info.actual_repaying_amount += comm
                # if proposal_info.user_vault is None:
                #     self.erc20_balances[IERC20(proposal_config.creditAddress)][
                #         lender
                #     ] -= comm
                # else:
                #     self.erc20_balances[IERC20(proposal_config.creditAddress)][
                #         proposal_info.user_vault
                #     ] -= comm

                # self.erc20_balances[IERC20(proposal_config.creditAddress)][
                #     self.vault
                # ] += comm
            # ------------------ HOTFIX END ------------------

        logger.info(
            f"Created refinancing loan {loan_id} lender={lender}, borrower={borrower} credit={proposal_config.creditAddress} collateral={proposal_config.collateralAddress}"
        )

    @flow(precondition=lambda self: len(self.running_loan_id) != 0)
    def flow_repay_loan(self):

        loan_id = random.choice(self.running_loan_id)

        proposal_info = self.proposals_from_loan_id[loan_id]

        proposal_config: PWNSimpleLoanSimpleProposal.Proposal = (
            proposal_info.proposal_config
        )

        credit: RichERC20 = proposal_info.credit_token
        # lender = proposal_info.lender
        borrower = proposal_info.borrower

        (
            status,
            start_timestamp,
            default_timestamp,
            borrower_loan,
            original_lender,
            loan_owner,
            accruing_interest_apr,
            fixed_interest_amount,
            credit_loan,
            collateral,
            original_source_of_funds,
            repayment_amount,
        ) = self.vault.getLOAN(loan_id)

        # assert start
        assert proposal_config.creditAmount == credit_loan.amount

        # because we did something
        # assert proposal_config.fixedInterestAmount == fixed_interest_amount

        if proposal_config.accruingInterestAPR > 0:
            accruing_minutes = (
                chain.blocks["latest"].timestamp + 10 - start_timestamp
            ) // 60  # 10 seconds future for approve
            accrued_interest = (
                proposal_config.creditAmount
                * proposal_config.accruingInterestAPR
                * accruing_minutes
            ) // (10_000 * 525600)
            total_interest = proposal_config.fixedInterestAmount + accrued_interest
        else:
            total_interest = proposal_config.fixedInterestAmount

        approve_amount = proposal_config.creditAmount + total_interest

        # lender get loan token from loan token(mint)
        # borrower get credit token from lender
        # loan vault (pwn_simple_loan) get corrateral from borrower
        with may_revert():
            credit.approve(self.vault, 0, from_=borrower)  # reset approval

        data = b""

        if random_bool():

            @dataclass
            class Permit:
                owner: Address
                spender: Address
                value: uint256
                nonce: uint256
                deadline: uint256

            message = Permit(
                borrower,
                self.vault,
                uint256(approve_amount),
                credit.nonces(borrower.address),
                chain.blocks["latest"].timestamp + 100,
            )
            data = Eip712Domain()
            data["name"] = credit.name()
            data["chainId"] = credit.chain.chain_id
            data["version"] = "1"
            data["verifyingContract"] = credit.address

            permit_sign = borrower.sign_structured(message=message, domain=data)

            assert len(permit_sign) == 65

            data = abi.encode(
                PermitPWN(
                    asset=credit.address,
                    owner=message.owner,
                    amount=message.value,
                    deadline=message.deadline,
                    r=permit_sign[:32],
                    s=permit_sign[32:64],
                    v=uint8(int.from_bytes(permit_sign[64:], "big")),
                )
            )

        else:
            credit.approve(self.vault, approve_amount, from_=borrower)
        balance = credit.balanceOf(borrower)
        if approve_amount > balance:
            mint_erc20(
                Account(credit.address, chain=chain),
                borrower,
                (approve_amount - balance),
            )
            self.erc20_balances[IERC20(credit)][borrower] += approve_amount - balance

        with may_revert() as e:
            tx = self.vault.repayLOAN(loan_id, data, from_=borrower.address)

        if status != 2:
            if status == 0:
                assert e.value == PWNSimpleLoan.LoanNotRunning()
            elif status == 3:
                assert e.value == PWNSimpleLoan.LoanDefaulted(default_timestamp)
                logger.info(
                    f"repayLOAN {loan_id} is not possible since default timestamp reached"
                )
            return

        if default_timestamp < chain.blocks["latest"].timestamp:
            assert e.value == PWNSimpleLoan.LoanDefaulted(default_timestamp)
            logger.info(
                f"repayLOAN {loan_id} is not possible since default timestamp reached"
            )
            return

        assert e.value is None

        if proposal_config.accruingInterestAPR > 0:
            accruing_minutes = (
                chain.blocks["latest"].timestamp - start_timestamp
            ) // 60  # Division by 1 minutes
            accrued_interest = (
                proposal_config.creditAmount
                * proposal_config.accruingInterestAPR
                * accruing_minutes
            ) // (100_00 * 525600)
            total_interest = proposal_config.fixedInterestAmount + accrued_interest
        else:
            total_interest = proposal_config.fixedInterestAmount
        # total_interest is estimated interest for 10 seconds
        actual_repaying_amount = proposal_config.creditAmount + total_interest

        proposal_info.actual_repaying_amount = actual_repaying_amount

        event = next(e for e in tx.events if isinstance(e, PWNSimpleLoan.LOANPaidBack))
        assert event.loanId == loan_id

        # vault pull from borrower
        event = next(e for e in tx.events if isinstance(e, PWNSimpleLoan.VaultPull))
        assert event.asset.category == MultiToken.Category.ERC20
        assert event.asset.assetAddress == proposal_config.creditAddress
        assert event.asset.amount == actual_repaying_amount
        assert event.origin_ == borrower.address

        # credit return
        self.erc20_balances[credit][borrower] -= actual_repaying_amount
        self.erc20_balances[credit][self.vault] += actual_repaying_amount

        # vault push to lender the collateral
        event = next(e for e in tx.events if isinstance(e, PWNSimpleLoan.VaultPush))
        assert event.asset.category == proposal_config.collateralCategory
        assert event.asset.assetAddress == proposal_config.collateralAddress
        assert event.asset.amount == proposal_config.collateralAmount
        assert event.beneficiary == proposal_info.borrower.address

        if proposal_config.collateralCategory == MultiToken.Category.ERC20:
            self.erc20_balances[IERC20(proposal_config.collateralAddress)][
                self.vault
            ] -= proposal_config.collateralAmount
            self.erc20_balances[IERC20(proposal_config.collateralAddress)][
                borrower
            ] += proposal_config.collateralAmount

        elif proposal_config.collateralCategory == MultiToken.Category.ERC721:
            self.erc721_owners[IERC721(proposal_config.collateralAddress)][
                proposal_info.collateral_id
            ] = borrower
        elif proposal_config.collateralCategory == MultiToken.Category.ERC1155:
            self.erc1155_balances[IERC1155(proposal_config.collateralAddress)][
                (proposal_info.collateral_id, self.vault)
            ] -= proposal_config.collateralAmount
            self.erc1155_balances[IERC1155(proposal_config.collateralAddress)][
                (proposal_info.collateral_id, borrower)
            ] += proposal_config.collateralAmount

        loan_owner = self.erc721_owners[IERC721(self.loan_token)][loan_id]
        if proposal_info.lender == loan_owner:
            # tryClaimRepaidLOAN will be fail or return without doing nothing
            event = next(e for e in tx.events if isinstance(e, PWNLOAN.LOANBurned))
            assert event.loanId == loan_id

            self.erc721_owners[IERC721(self.loan_token)][loan_id] = None

            self.erc20_balances[credit][self.vault] -= actual_repaying_amount
            if proposal_info.user_vault is None:
                self.erc20_balances[credit][
                    proposal_info.lender
                ] += actual_repaying_amount
            else:
                self.erc20_balances[credit][
                    proposal_info.user_vault
                ] += actual_repaying_amount

            event = next(
                e for e in tx.events if isinstance(e, PWNSimpleLoan.LOANClaimed)
            )
            assert event.loanId == loan_id
            assert event.defaulted == False

            self.burned_loan_id.add(loan_id)
            self.running_loan_id.remove(loan_id)
            logger.info(
                f"repayLOAN {loan_id} is done, used {proposal_config.collateralCategory} loan_owner: {loan_owner}, lender: {proposal_info.lender}, borrower: {borrower}, self.vault: {self.vault}"
            )
            return
        self.running_loan_id.remove(loan_id)
        # this is done in try chatch case, I can not find case that this fails.
        self.claimable_loan_id.append(loan_id)

        logger.info(
            f"repayLOAN {loan_id} is done, used {proposal_config.collateralCategory} loan_owner: {loan_owner}, lender: {proposal_info.lender}, borrower: {borrower}, self.vault: {self.vault}"
        )

    @flow(
        precondition=lambda self: len(self.running_loan_id) != 0
        or len(self.claimable_loan_id) != 0
    )
    def flow_claim_loan(self):
        defaulted = False
        target_loan_id = None
        if len(self.claimable_loan_id) != 0:
            target_loan_id = random.choice(self.claimable_loan_id)

        if target_loan_id is None:
            defaulted = True
            if len(self.running_loan_id) != 0:
                target_loan_id = None
                for loan_id in self.running_loan_id:
                    (_, _, default_timestamp, _, _, _, _, _, _, _, _, _) = (
                        self.vault.getLOAN(loan_id)
                    )
                    if default_timestamp < chain.blocks["latest"].timestamp:
                        target_loan_id = loan_id
                        break  # Exit loop once we find a defaulted loan

        if target_loan_id is None:
            return

        (_, _, default_timestamp, _, _, _, _, _, _, _, _, _) = self.vault.getLOAN(
            target_loan_id
        )
        loan_id = target_loan_id
        loan_owner = self.erc721_owners[IERC721(self.loan_token)][loan_id]

        proposal_info = self.proposals_from_loan_id[loan_id]

        tx = self.vault.claimLOAN(loan_id, from_=loan_owner)
        # loanBurned
        event = next(e for e in tx.events if isinstance(e, PWNLOAN.LOANBurned))
        assert event.loanId == loan_id

        self.erc721_owners[IERC721(self.loan_token)][loan_id] = None

        # loanClaimed
        event = next(e for e in tx.events if isinstance(e, PWNSimpleLoan.LOANClaimed))
        assert event.loanId == loan_id
        assert event.defaulted == defaulted

        self.burned_loan_id.add(loan_id)
        proposal_info = self.proposals_from_loan_id[loan_id]

        proposal_config: PWNSimpleLoanSimpleProposal.Proposal = (
            proposal_info.proposal_config
        )

        if defaulted:  #  return collateral to lender
            event = next(e for e in tx.events if isinstance(e, PWNSimpleLoan.VaultPush))
            assert event.asset.category == proposal_config.collateralCategory
            assert event.asset.assetAddress == proposal_config.collateralAddress
            assert event.asset.amount == proposal_config.collateralAmount
            assert event.beneficiary == loan_owner.address

            if proposal_config.collateralCategory == MultiToken.Category.ERC20:
                self.erc20_balances[IERC20(proposal_config.collateralAddress)][
                    self.vault
                ] -= proposal_config.collateralAmount
                self.erc20_balances[IERC20(proposal_config.collateralAddress)][
                    loan_owner
                ] += proposal_config.collateralAmount
            elif proposal_config.collateralCategory == MultiToken.Category.ERC721:
                self.erc721_owners[IERC721(proposal_config.collateralAddress)][
                    proposal_info.collateral_id
                ] = loan_owner
            elif proposal_config.collateralCategory == MultiToken.Category.ERC1155:
                self.erc1155_balances[IERC1155(proposal_config.collateralAddress)][
                    (proposal_info.collateral_id, self.vault)
                ] -= proposal_config.collateralAmount
                self.erc1155_balances[IERC1155(proposal_config.collateralAddress)][
                    (proposal_info.collateral_id, loan_owner)
                ] += proposal_config.collateralAmount
                logger.info(f"claimLOAN done for defaulted loan")
            self.running_loan_id.remove(loan_id)
        else:  # return the credit to lender
            event = next(e for e in tx.events if isinstance(e, PWNSimpleLoan.VaultPush))
            assert event.asset.category == MultiToken.Category.ERC20
            assert (
                event.asset.assetAddress == proposal_config.creditAddress
            )
            assert event.asset.amount == proposal_info.actual_repaying_amount
            assert event.beneficiary == loan_owner.address
            self.erc20_balances[Account(proposal_config.creditAddress, chain=chain)][
                self.vault
            ] -= proposal_info.actual_repaying_amount
            self.erc20_balances[Account(proposal_config.creditAddress, chain=chain)][
                loan_owner
            ] += proposal_info.actual_repaying_amount
            logger.info(
                f"claimLOAN from different lender which already borrower returned the credit"
            )
            self.claimable_loan_id.remove(loan_id)

    @flow(precondition=lambda self: len(self.running_loan_id) != 0)
    def flow_make_extention(self):
        loan_id = random.choice(self.running_loan_id)
        proposal_info = self.proposals_from_loan_id[loan_id]

        # Random proposer (either borrower or lender)
        loan_owner = self.erc721_owners[IERC721(self.loan_token)][loan_id]
        proposer = random.choice([proposal_info.borrower, loan_owner])
        if proposer not in self.nonce:
            self.nonce[proposer] = 0

        extension = PWNSimpleLoan.ExtensionProposal(
            loanId=loan_id,
            compensationAddress=proposal_info.credit_token.address,  # Use same token as loan
            compensationAmount=0,  # Random compensation 0-10 tokens
            duration=random_int(
                24 * 60 * 60, 7 * 24 * 60 * 60
            ),  # Random duration 1-7 days
            expiration=chain.blocks["pending"].timestamp + 1,  # 24 hours from now
            proposer=proposer.address,
            nonceSpace=0,
            nonce=self.nonce[proposer],
        )

        self.nonce[proposer] += 1

        if proposer == proposal_info.borrower:
            caller = loan_owner
        else:
            caller = proposal_info.borrower  # this case

        extension_hash = self.vault.getExtensionHash(extension)
        signature = proposer.sign_hash(extension_hash)

        with may_revert(PWNSimpleLoan.LoanDefaulted) as e:
            tx = self.vault.extendLOAN(extension, signature, b"", from_=caller)

        if extension.expiration < chain.blocks["latest"].timestamp:
            assert e.value == Expired(
                chain.blocks["latest"].timestamp, extension.expiration
            )
            logger.info(
                f"Loan extension {loan_id} is not possible since extension expiration reached"
            )
            return

        assert e.value is None

        event = next(e for e in tx.events if isinstance(e, PWNSimpleLoan.LOANExtended))
        assert event.loanId == loan_id
        assert event.originalDefaultTimestamp == proposal_info.default_timestamp
        assert (
            event.extendedDefaultTimestamp
            == proposal_info.default_timestamp + extension.duration
        )

        proposal_info.default_timestamp = (
            proposal_info.default_timestamp + extension.duration
        )
        logger.info(f"Extended loan {loan_id} duration by {extension.duration} seconds")

    @flow(precondition=lambda self: len(self.running_loan_id) != 0, weight=200)
    def flow_transfer_loan_owner(self):
        loan_id = random.choice(self.running_loan_id)
        new_owner = random_account()
        owner = self.loan_token.ownerOf(loan_id)
        tx = self.loan_token.transferFrom(
            owner, new_owner, loan_id, from_=Account(owner, chain=chain)
        )
        self.erc721_owners[IERC721(self.loan_token)][loan_id] = new_owner

        logger.info(f"transfer loan owner {loan_id} from {owner} to {new_owner}")

    @flow(weight=10)
    def go_future(self):
        chain.mine(lambda t: t + random_int(10 * 60,  60 * 60 * 2, min_prob=0.5))

    @invariant()
    def invariant_check_loan_details(self):
        for loan_id in range(1, self.loan_token.lastLoanId()):
            (
                status,
                start_timestamp,
                default_timestamp,
                borrower,
                original_lender,
                loan_owner,
                accruing_interest_apr,
                fixed_interest_amount,
                credit,
                collateral,
                original_source_of_funds,
                repayment_amount,
            ) = self.vault.getLOAN(loan_id)
            if loan_id in self.burned_loan_id:
                # everything should be 0
                assert status == 0
                assert start_timestamp == 0
                assert default_timestamp == 0
                assert borrower == Address.ZERO
                assert original_lender == Address.ZERO
                assert loan_owner == Address.ZERO
                assert accruing_interest_apr == 0
                assert fixed_interest_amount == 0
                assert credit.amount == 0 * 100_00
                assert credit.id == 0
                assert credit.assetAddress == Address.ZERO
                assert credit.category == MultiToken.Category.ERC20
                assert collateral.amount == 0
                assert collateral.id == 0
                assert collateral.category == MultiToken.Category.ERC20
                assert collateral.assetAddress == Address.ZERO
                assert original_source_of_funds == Address.ZERO
                assert repayment_amount == 0
                continue

            assert status in [1, 2, 3, 4]
            assert borrower != original_lender

            if loan_id in self.proposals_from_loan_id:
                proposal_info = self.proposals_from_loan_id[loan_id]
                assert proposal_info.default_timestamp == default_timestamp

    @invariant()
    def invariant_erc20_balances(self):
        for contract in self.erc20_balances:
            for acc in self.erc20_balances[contract]:
                assert contract.balanceOf(acc) == self.erc20_balances[contract][acc]

    @invariant()
    def invariant_erc721_owners(self):
        for contract in self.erc721_owners:
            for token_id in self.erc721_owners[contract]:
                with may_revert() as e:
                    contract.ownerOf(token_id)
                if self.erc721_owners[contract][token_id] is None:
                    assert e.value == Error(message="ERC721: invalid token ID")
                    continue
                assert (
                    contract.ownerOf(token_id)
                    == self.erc721_owners[contract][token_id].address
                )

    @invariant()
    def invariant_erc1155_balances(self):
        for contract in self.erc1155_balances:
            # for token_id in self.erc1155_support_ids:
            for token_id, acc in self.erc1155_balances[contract]:
                assert (
                    contract.balanceOf(acc, token_id)
                    == self.erc1155_balances[contract][(token_id, acc)]
                )


@chain.connect()
@on_revert(lambda e: print(e.value.tx.call_trace))
def test_fuzz():
    PWNFuzzTest().run(5, 10_000)
