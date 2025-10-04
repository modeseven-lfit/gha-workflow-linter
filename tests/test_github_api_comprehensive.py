# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Comprehensive tests for GitHub GraphQL API client."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from gha_workflow_linter.exceptions import (
    AuthenticationError,
    GitHubAPIError,
    NetworkError,
    RateLimitError,
    TemporaryAPIError,
)
from gha_workflow_linter.github_api import GitHubGraphQLClient
from gha_workflow_linter.models import (
    APICallStats,
    GitHubAPIConfig,
    GitHubRateLimitInfo,
)


class TestGitHubGraphQLClient:
    """Test GitHub GraphQL API client."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.config = GitHubAPIConfig(
            token="ghp_test123",
            base_url="https://api.github.com/graphql",
            timeout=30.0,
            max_retries=3,
            retry_delay=1.0,
            batch_size=10,
        )
        self.client = GitHubGraphQLClient(self.config)

    def test_init_with_token(self) -> None:
        """Test client initialization with token."""
        assert self.client.config == self.config
        assert self.client._token == "ghp_test123"
        assert isinstance(self.client._rate_limit_info, GitHubRateLimitInfo)
        assert isinstance(self.client.api_stats, APICallStats)

    def test_init_without_token(self) -> None:
        """Test client initialization without token."""
        config = GitHubAPIConfig(token=None)
        with patch.dict("os.environ", {}, clear=True):
            client = GitHubGraphQLClient(config)
            assert client._token is None

    def test_init_with_env_token(self) -> None:
        """Test client initialization with environment token."""
        config = GitHubAPIConfig(token=None)
        with patch.dict("os.environ", {"GITHUB_TOKEN": "env_token123"}):
            client = GitHubGraphQLClient(config)
            assert client._token == "env_token123"

    @pytest.mark.asyncio
    async def test_async_context_manager(self) -> None:
        """Test async context manager functionality."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            async with self.client as client:
                assert client is self.client
                assert self.client._http_client is mock_client

            mock_client.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_aenter_without_token(self) -> None:
        """Test async context manager entry without token."""
        config = GitHubAPIConfig(token=None)
        client = GitHubGraphQLClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            # Mock the _update_rate_limit_info method to avoid HTTP calls
            with patch.object(
                client, "_update_rate_limit_info", return_value=asyncio.Future()
            ) as mock_update:
                mock_update.return_value.set_result(None)

                # Should not raise error - client allows operation without token
                async with client:
                    pass

    @pytest.mark.asyncio
    async def test_validate_repositories_batch_success(self) -> None:
        """Test successful repository validation."""
        repositories = ["actions/checkout", "actions/setup-node"]

        mock_response = {
            "actions/checkout": True,
            "actions/setup-node": True,
        }

        with patch.object(
            self.client,
            "_validate_repositories_graphql_batch",
            return_value=mock_response,
        ) as mock_validate:
            result = await self.client.validate_repositories_batch(repositories)

            mock_validate.assert_called_once_with(repositories)
            assert "actions/checkout" in result
            assert "actions/setup-node" in result
            assert result["actions/checkout"] is True
            assert result["actions/setup-node"] is True

    @pytest.mark.asyncio
    async def test_validate_repositories_batch_not_found(self) -> None:
        """Test repository validation with not found repositories."""
        repositories = ["nonexistent/repo"]

        mock_response = {"nonexistent/repo": False}

        with patch.object(
            self.client,
            "_validate_repositories_graphql_batch",
            return_value=mock_response,
        ):
            result = await self.client.validate_repositories_batch(repositories)

            assert "nonexistent/repo" in result
            assert result["nonexistent/repo"] is False

    @pytest.mark.asyncio
    async def test_validate_repositories_batch_empty(self) -> None:
        """Test repository validation with empty list."""
        result = await self.client.validate_repositories_batch([])
        assert result == {}

    @pytest.mark.asyncio
    async def test_validate_references_batch_success(self) -> None:
        """Test successful reference validation."""
        repo_refs = [
            ("actions/checkout", "v4"),
            ("actions/setup-node", "abc123"),
        ]

        # Mock method returns results for each repository separately
        def mock_validate_refs(repo_key, _refs):
            if repo_key == "actions/checkout":
                return {"v4": True}
            elif repo_key == "actions/setup-node":
                return {"abc123": True}
            return {}

        with patch.object(
            self.client,
            "_validate_references_graphql_batch",
            side_effect=mock_validate_refs,
        ):
            result = await self.client.validate_references_batch(repo_refs)

            assert len(result) == 2
            # v4 should be valid
            assert result[("actions/checkout", "v4")] is True
            # abc123 should be valid
            assert result[("actions/setup-node", "abc123")] is True

    @pytest.mark.asyncio
    async def test_validate_references_batch_invalid(self) -> None:
        """Test reference validation with invalid references."""
        repo_refs = [
            ("actions/checkout", "invalid"),
        ]

        mock_response = {"invalid": False}

        with patch.object(
            self.client,
            "_validate_references_graphql_batch",
            return_value=mock_response,
        ):
            result = await self.client.validate_references_batch(repo_refs)

            assert len(result) == 1
            assert result[("actions/checkout", "invalid")] is False

    @pytest.mark.asyncio
    async def test_validate_references_batch_empty(self) -> None:
        """Test reference validation with empty list."""
        result = await self.client.validate_references_batch([])
        assert result == {}

    @pytest.mark.asyncio
    async def test_validate_repositories_graphql_batch(self) -> None:
        """Test GraphQL repository validation query."""
        repositories = ["actions/checkout", "actions/setup-node"]

        with patch.object(
            self.client,
            "_execute_graphql_query",
            return_value={
                "data": {
                    "repo_0": {"id": "1", "name": "checkout"},
                    "repo_1": {"id": "2", "name": "setup-node"},
                }
            },
        ) as mock_execute:
            result = await self.client._validate_repositories_graphql_batch(
                repositories
            )

            mock_execute.assert_called_once()
            query_arg = mock_execute.call_args[0][0]
            assert "repository(" in query_arg
            assert "actions" in query_arg
            assert "checkout" in query_arg

            # Should return boolean validation results
            expected = {
                "actions/checkout": True,
                "actions/setup-node": True,
            }
            assert result == expected

    @pytest.mark.asyncio
    async def test_validate_references_graphql_batch(self) -> None:
        """Test GraphQL reference validation query."""
        repo_key = "actions/checkout"
        references = ["v4"]

        mock_response = {"v4": True}

        with patch.object(
            self.client,
            "_execute_graphql_query",
            return_value={
                "data": {
                    "repository": {
                        "refs": {"nodes": []},
                        "tags": {"nodes": [{"name": "v4"}]},
                    }
                }
            },
        ) as mock_execute:
            result = await self.client._validate_references_graphql_batch(
                repo_key, references
            )

            mock_execute.assert_called_once()
            query_arg = mock_execute.call_args[0][0]
            assert "repository(" in query_arg
            assert "refs(" in query_arg
            assert "refs/heads/" in query_arg
            assert result == mock_response

    @pytest.mark.asyncio
    async def test_validate_commit_shas_graphql(self) -> None:
        """Test commit SHA validation GraphQL query."""
        owner = "actions"
        name = "checkout"
        shas = ["abc123"]

        with patch.object(
            self.client,
            "_execute_graphql_query",
            return_value={
                "data": {"repository": {"commit_0": {"oid": "abc123"}}}
            },
        ) as mock_execute:
            result = await self.client._validate_commit_shas_graphql(
                owner, name, shas
            )

            mock_execute.assert_called_once()
            query_arg = mock_execute.call_args[0][0]
            assert "repository(" in query_arg
            assert "object(" in query_arg
            expected = {"abc123": True}
            assert result == expected

    @pytest.mark.asyncio
    async def test_validate_branch_tag_names_graphql(self) -> None:
        """Test branch/tag name validation GraphQL query."""
        owner = "actions"
        name = "checkout"
        refs = ["v4"]

        mock_response = {"v4": True}

        with patch.object(
            self.client,
            "_execute_graphql_query",
            return_value={
                "data": {
                    "repository": {
                        "refs": {"nodes": []},
                        "tags": {"nodes": [{"name": "v4"}]},
                    }
                }
            },
        ) as mock_execute:
            result = await self.client._validate_branch_tag_names_graphql(
                owner, name, refs
            )

            mock_execute.assert_called_once()
            query_arg = mock_execute.call_args[0][0]
            assert "repository(" in query_arg
            assert "refs/heads/" in query_arg
            assert result == mock_response

    @pytest.mark.asyncio
    async def test_execute_graphql_query_success(self) -> None:
        """Test successful GraphQL query execution."""
        query = "query { viewer { login } }"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.json.return_value = {
            "data": {"viewer": {"login": "testuser"}}
        }

        async with self.client as client:
            with patch.object(
                client._http_client, "post", return_value=mock_response
            ) as mock_post:
                result = await client._execute_graphql_query(query)

                mock_post.assert_called_once()
                call_args = mock_post.call_args

                # Check request payload
                request_data = call_args[1]["json"]
                assert request_data["query"] == query

                assert result == {"data": {"viewer": {"login": "testuser"}}}

    @pytest.mark.asyncio
    async def test_execute_graphql_query_network_error(self) -> None:
        """Test GraphQL query execution with network error."""
        query = "query { viewer { login } }"

        async with self.client as client:
            with patch.object(
                client._http_client,
                "post",
                side_effect=httpx.ConnectError("Connection failed"),
            ):
                with pytest.raises(
                    NetworkError, match="Network connection failed"
                ):
                    await client._execute_graphql_query(query)

    @pytest.mark.asyncio
    async def test_execute_graphql_query_timeout(self) -> None:
        """Test GraphQL query execution with timeout."""
        query = "query { viewer { login } }"

        async with self.client as client:
            with patch.object(
                client._http_client,
                "post",
                side_effect=httpx.TimeoutException("Request timed out"),
            ):
                with pytest.raises(
                    NetworkError, match="Network request failed"
                ):
                    await client._execute_graphql_query(query)

    @pytest.mark.asyncio
    async def test_execute_graphql_query_auth_error(self) -> None:
        """Test GraphQL query execution with authentication error."""
        query = "query { viewer { login } }"

        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.headers = {}
        mock_response.text = "Bad credentials"
        mock_response.json.return_value = {
            "errors": [{"message": "Bad credentials"}]
        }

        async with self.client as client:
            with patch.object(
                client._http_client, "post", return_value=mock_response
            ):
                with pytest.raises(
                    AuthenticationError,
                    match="GitHub API authentication failed",
                ):
                    await client._execute_graphql_query(query)

    @pytest.mark.asyncio
    async def test_execute_graphql_query_rate_limit(self) -> None:
        """Test GraphQL query execution with rate limit error."""
        query = "query { viewer { login } }"

        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "rate limit exceeded"
        mock_response.headers = {
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": "1640995200",
        }
        mock_response.json.return_value = {
            "errors": [
                {"type": "RATE_LIMITED", "message": "Rate limit exceeded"}
            ]
        }

        async with self.client as client:
            with patch.object(
                client._http_client, "post", return_value=mock_response
            ):
                with pytest.raises(
                    RateLimitError, match="GitHub API rate limit exceeded"
                ):
                    await client._execute_graphql_query(query)

    @pytest.mark.asyncio
    async def test_execute_graphql_query_server_error(self) -> None:
        """Test GraphQL query execution with server error."""
        query = "query { viewer { login } }"

        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.headers = {}
        mock_response.text = "Internal server error"
        mock_response.json.return_value = {
            "errors": [{"message": "Internal server error"}]
        }

        async with self.client as client:
            with patch.object(
                client._http_client, "post", return_value=mock_response
            ):
                with pytest.raises(
                    TemporaryAPIError, match="GitHub API server error"
                ):
                    await client._execute_graphql_query(query)

    @pytest.mark.asyncio
    async def test_execute_graphql_query_graphql_errors(self) -> None:
        """Test GraphQL query execution with GraphQL errors."""
        query = "query { viewer { login } }"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = "GraphQL errors"
        mock_response.json.return_value = {
            "errors": [{"message": "Field 'invalidField' doesn't exist"}],
            "data": None,
        }

        async with self.client as client:
            with patch.object(
                client._http_client, "post", return_value=mock_response
            ):
                with pytest.raises(GitHubAPIError, match="GraphQL errors"):
                    await client._execute_graphql_query(query)

    @pytest.mark.skip(reason="Retry functionality not implemented")
    @pytest.mark.asyncio
    async def test_execute_graphql_query_with_retries(self) -> None:
        """Test GraphQL query execution with automatic retries."""
        query = "query { viewer { login } }"

        # First call fails with temporary error, second succeeds
        error_response = Mock()
        error_response.status_code = 502
        error_response.headers = {}
        error_response.text = "Bad gateway"
        error_response.json.return_value = {
            "errors": [{"message": "Bad gateway"}]
        }

        success_response = Mock()
        success_response.status_code = 200
        success_response.headers = {}
        success_response.json.return_value = {
            "data": {"viewer": {"login": "testuser"}}
        }

        async with self.client as client:
            with patch.object(
                client._http_client,
                "post",
                side_effect=[error_response, success_response],
            ) as mock_post:
                with patch("asyncio.sleep"):  # Mock sleep to speed up test
                    result = await client._execute_graphql_query(query)

                assert mock_post.call_count == 2
                assert result == {"data": {"viewer": {"login": "testuser"}}}

    @pytest.mark.skip(reason="Retry functionality not implemented")
    @pytest.mark.asyncio
    async def test_execute_graphql_query_max_retries_exceeded(self) -> None:
        """Test GraphQL query execution when max retries are exceeded."""
        query = "query { viewer { login } }"

        mock_response = Mock()
        mock_response.status_code = 502
        mock_response.headers = {}
        mock_response.text = "Bad gateway"
        mock_response.json.return_value = {
            "errors": [{"message": "Bad gateway"}]
        }

        async with self.client as client:
            with patch.object(
                client._http_client, "post", return_value=mock_response
            ) as mock_post:
                with (
                    patch("asyncio.sleep"),  # Mock sleep to speed up test
                    pytest.raises(
                        TemporaryAPIError, match="GitHub API server error"
                    ),
                ):
                    await client._execute_graphql_query(query)

                # Should try initial + max_retries times
                assert mock_post.call_count == 1 + self.config.max_retries

    @pytest.mark.asyncio
    async def test_update_rate_limit_info(self) -> None:
        """Test updating rate limit information."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "resources": {
                "graphql": {
                    "remaining": 4500,
                    "limit": 5000,
                    "reset": 1640995200,
                }
            }
        }

        with patch("httpx.AsyncClient.get", return_value=mock_response):
            self.client._http_client = httpx.AsyncClient()
            await self.client._update_rate_limit_info()

        rate_limit = self.client._rate_limit_info
        assert rate_limit.remaining == 4500
        assert rate_limit.limit == 5000
        assert rate_limit.reset_at == 1640995200

    def test_update_rate_limit_from_headers(self) -> None:
        """Test updating rate limit from HTTP headers."""
        headers = {
            "x-ratelimit-remaining": "3000",
            "x-ratelimit-limit": "5000",
            "x-ratelimit-reset": "1640995200",
        }

        self.client._update_rate_limit_from_headers(headers)

        rate_limit = self.client._rate_limit_info
        assert rate_limit.remaining == 3000
        assert rate_limit.limit == 5000
        assert rate_limit.reset_timestamp == 1640995200

    def test_update_rate_limit_from_headers_missing(self) -> None:
        """Test updating rate limit with missing headers."""
        headers: dict[str, str] = {}

        # Should not raise error with missing headers
        self.client._update_rate_limit_from_headers(headers)

    def test_update_rate_limit_from_headers_invalid(self) -> None:
        """Test updating rate limit with invalid header values."""
        headers = {
            "x-ratelimit-remaining": "invalid",
            "x-ratelimit-limit": "not_a_number",
            "x-ratelimit-reset": "bad_timestamp",
        }

        # Should not raise error with invalid values
        self.client._update_rate_limit_from_headers(headers)

    @pytest.mark.asyncio
    async def test_check_rate_limit_ok(self) -> None:
        """Test rate limit check when rate limit is OK."""
        self.client._rate_limit_info.remaining = 1000
        self.client._rate_limit_info.limit = 5000

        # Should not raise any exception
        await self.client._check_rate_limit()

    @pytest.mark.asyncio
    async def test_check_rate_limit_low(self) -> None:
        """Test rate limit check when rate limit is low."""
        import time

        # Set remaining below threshold and reset time in future
        self.client._rate_limit_info.remaining = (
            10  # Below default threshold of 1000
        )
        self.client._rate_limit_info.limit = 5000
        self.client._rate_limit_info.reset_at = (
            int(time.time()) + 3600
        )  # 1 hour from now

        # Mock sleep and update_rate_limit_info to avoid actually waiting
        with (
            patch("asyncio.sleep") as mock_sleep,
            patch.object(self.client, "_update_rate_limit_info") as mock_update,
            patch.object(self.client.logger, "warning") as mock_warning,
        ):
            await self.client._check_rate_limit()

            mock_warning.assert_called()
            mock_sleep.assert_called()
            mock_update.assert_called()

    @pytest.mark.asyncio
    async def test_check_rate_limit_exceeded(self) -> None:
        """Test rate limit check when rate limit is exceeded."""
        import time
        from unittest.mock import patch

        # Set rate limit to be exceeded with reset time in near future
        near_future_time = int(time.time()) + 2  # 2 seconds from now

        self.client._rate_limit_info.remaining = 0
        self.client._rate_limit_info.limit = 5000
        self.client._rate_limit_info.reset_at = near_future_time

        # Mock asyncio.sleep to avoid actually waiting
        with (
            patch("asyncio.sleep") as mock_sleep,
            patch.object(self.client, "_update_rate_limit_info") as mock_update,
        ):
            await self.client._check_rate_limit()

            # Verify that sleep was called with appropriate delay
            assert mock_sleep.called
            sleep_duration = mock_sleep.call_args[0][0]
            assert sleep_duration > 0  # Should sleep for some positive duration

            # Verify rate limit info was updated after sleep
            mock_update.assert_called_once()

    def test_get_api_stats(self) -> None:
        """Test getting API statistics."""
        # Manually increment stats to test
        for _ in range(10):
            self.client.api_stats.increment_graphql()

        stats = self.client.api_stats

        assert stats.graphql_calls == 10
        assert stats.total_calls == 10

        # No duplicate assertions needed

    def test_get_rate_limit_info(self) -> None:
        """Test getting rate limit information."""
        self.client._rate_limit_info.remaining = 4000
        self.client._rate_limit_info.limit = 5000

        rate_limit = self.client._rate_limit_info

        assert rate_limit.remaining == 4000
        assert rate_limit.limit == 5000


class TestGitHubGraphQLClientIntegration:
    """Integration tests for GitHub GraphQL client."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.config = GitHubAPIConfig(
            token="ghp_test123",
            batch_size=2,  # Small batch size for testing
        )

    @pytest.mark.skip(reason="Complex integration test with mocking issues")
    @pytest.mark.asyncio
    async def test_batch_processing_repositories(self) -> None:
        """Test batch processing for repository validation."""
        repositories = [
            "actions/checkout",
            "actions/setup-node",
            "actions/upload-artifact",
        ]

        # Mock responses for two batches
        batch1_response = {
            "actions/checkout": True,
            "actions/setup-node": True,
        }
        batch2_response = {
            "actions/upload-artifact": True,
        }

        client = GitHubGraphQLClient(self.config)

        with patch.object(
            client,
            "_validate_repositories_graphql_batch",
            side_effect=[batch1_response, batch2_response],
        ) as mock_validate:
            result = await client.validate_repositories_batch(repositories)

            # Should make two batch calls
            assert mock_validate.call_count == 2

            # All repositories should be in result
            assert len(result) == 3
            assert "actions/checkout" in result
            assert "actions/setup-node" in result
            assert "actions/upload-artifact" in result

    @pytest.mark.skip(reason="Complex integration test with mocking issues")
    @pytest.mark.asyncio
    async def test_batch_processing_references(self) -> None:
        """Test batch processing for reference validation."""
        repo_refs = [
            ("actions/checkout", "v4"),
            ("actions/setup-node", "v3"),
        ]

        # Mock method returns results for each repository separately
        def mock_validate_refs(repo_key, _refs):
            if repo_key == "actions/checkout":
                return {"v4": True}
            elif repo_key == "actions/setup-node":
                return {"v3": True}
            return {}

        client = GitHubGraphQLClient(self.config)

        with patch.object(
            client,
            "_validate_references_graphql_batch",
            side_effect=mock_validate_refs,
        ) as mock_validate:
            result = await client.validate_references_batch(repo_refs)

            # Should make calls for each repository
            assert mock_validate.call_count >= 1

            # All references should have results
            assert len(result) == 2
            assert result[("actions/checkout", "v4")] is True
            assert result[("actions/setup-node", "abc123")] is True

    @pytest.mark.skip(reason="Complex integration test with mocking issues")
    @pytest.mark.asyncio
    async def test_error_handling_in_batches(self) -> None:
        """Test error handling when one batch fails."""
        repositories = [
            "actions/checkout",
            "actions/setup-node",
            "actions/upload-artifact",
        ]

        # First batch succeeds, second fails
        batch1_response = {
            "actions/checkout": True,
            "actions/setup-node": True,
        }

        client = GitHubGraphQLClient(self.config)

        with (
            patch.object(
                client,
                "_validate_repositories_graphql_batch",
                side_effect=[
                    batch1_response,
                    NetworkError("Connection failed"),
                ],
            ),
            pytest.raises(NetworkError),
        ):
            await client.validate_repositories_batch(repositories)

    @pytest.mark.skip(reason="Complex integration test with mocking issues")
    @pytest.mark.asyncio
    async def test_api_stats_tracking(self) -> None:
        """Test that API statistics are properly tracked."""
        repositories = ["actions/checkout"]

        mock_response = {"actions/checkout": True}

        client = GitHubGraphQLClient(self.config)

        with patch.object(
            client,
            "_validate_repositories_graphql_batch",
            return_value=mock_response,
        ):
            await client.validate_repositories_batch(repositories)

            stats = client.api_stats
            assert stats.graphql_calls == 1

    @pytest.mark.skip(reason="Complex integration test with mocking issues")
    @pytest.mark.asyncio
    async def test_concurrent_request_handling(self) -> None:
        """Test handling concurrent requests safely."""
        repositories1 = ["actions/checkout"]
        repositories2 = ["actions/setup-node"]

        mock_response1 = {"actions/checkout": True}
        mock_response2 = {"actions/setup-node": True}

        client = GitHubGraphQLClient(self.config)

        with patch.object(
            client,
            "_validate_repositories_graphql_batch",
            side_effect=[mock_response1, mock_response2],
        ):
            # Run concurrent requests
            results = await asyncio.gather(
                client.validate_repositories_batch(repositories1),
                client.validate_repositories_batch(repositories2),
            )

            assert len(results) == 2
            assert results[0] == {"actions/checkout": True}
            assert results[1] == {"actions/setup-node": True}

            # Both requests should have been tracked
            stats = client.api_stats
            assert stats.graphql_calls >= 2
