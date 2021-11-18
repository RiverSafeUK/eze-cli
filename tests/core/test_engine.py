# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import TestCase

from eze.core.engine import EzeCore
from tests.__test_helpers__.mock_helper import teardown_mock


class TestEzeCore(TestCase):
    def setUp(self) -> None:
        """Pre-Test Setup func"""
        teardown_mock()

    def tearDown(self) -> None:
        """Post-Test Tear Down func"""
        teardown_mock()

    def test_get_instance(self):
        # Given
        eze_instance = EzeCore.get_instance()
        # When
        second_eze_instance = EzeCore.get_instance()
        # Then
        assert eze_instance == second_eze_instance

    def test_reset_instance(self):
        # Given
        eze_instance = EzeCore.get_instance()
        # When
        EzeCore.reset_instance()
        second_eze_instance = EzeCore.get_instance()
        # Then
        assert eze_instance != second_eze_instance
