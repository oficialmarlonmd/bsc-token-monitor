"""Tests for ContractAnalyzer."""

from src.contract_analyzer import ContractAnalyzer


class TestFindHiddenFunctions:
    def setup_method(self):
        self.analyzer = ContractAnalyzer(api_key="dummy")

    def test_detects_mint_in_abi(self):
        abi = [
            {"type": "function", "name": "mint", "inputs": [], "outputs": []},
            {"type": "function", "name": "transfer", "inputs": [], "outputs": []},
        ]
        found = self.analyzer.find_hidden_functions(abi=abi)
        assert "mint" in found

    def test_detects_settax_in_source(self):
        source = "function setTax(uint256 newTax) public onlyOwner { ... }"
        found = self.analyzer.find_hidden_functions(source_code=source)
        assert "setTax" in found

    def test_detects_blacklist_in_source(self):
        source = "function blacklistAddress(address addr) external { ... }"
        found = self.analyzer.find_hidden_functions(source_code=source)
        assert "blacklistAddress" in found

    def test_no_suspicious_functions_returns_empty(self):
        abi = [
            {"type": "function", "name": "transfer", "inputs": [], "outputs": []},
            {"type": "function", "name": "balanceOf", "inputs": [], "outputs": []},
        ]
        found = self.analyzer.find_hidden_functions(abi=abi)
        assert found == []

    def test_case_insensitive_source_match(self):
        source = "function MINT(uint256 amount) public { }"
        found = self.analyzer.find_hidden_functions(source_code=source)
        assert "mint" in found

    def test_no_false_positive_on_transfer(self):
        source = "function transfer(address to, uint256 amount) public returns (bool) { }"
        found = self.analyzer.find_hidden_functions(source_code=source)
        assert "transfer" not in found

    def test_deduplicates_results(self):
        abi = [
            {"type": "function", "name": "mint", "inputs": [], "outputs": []},
            {"type": "function", "name": "mint", "inputs": [], "outputs": []},
        ]
        found = self.analyzer.find_hidden_functions(abi=abi)
        assert found.count("mint") == 1


class TestExtractTaxInfo:
    def setup_method(self):
        self.analyzer = ContractAnalyzer(api_key="dummy")

    def test_extract_sell_tax(self):
        source = "uint256 public sellFee = 5;"
        taxes = self.analyzer.extract_tax_info(source)
        assert taxes["sell_tax"] == 5.0

    def test_extract_buy_tax(self):
        source = "uint256 public buyFee = 3;"
        taxes = self.analyzer.extract_tax_info(source)
        assert taxes["buy_tax"] == 3.0

    def test_no_tax_returns_zeros(self):
        taxes = self.analyzer.extract_tax_info("// no fee here")
        assert taxes["sell_tax"] == 0.0
        assert taxes["buy_tax"] == 0.0

    def test_empty_source_returns_zeros(self):
        taxes = self.analyzer.extract_tax_info("")
        assert taxes == {"sell_tax": 0.0, "buy_tax": 0.0}
