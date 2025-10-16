#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
Cache functionality demonstration script for gha-workflow-linter.

This script demonstrates how the local caching feature works by:
1. Creating a temporary cache configuration
2. Simulating validation results storage and retrieval
3. Showing cache statistics and performance benefits
"""

from pathlib import Path
import tempfile
import time
from typing import Optional

from gha_workflow_linter.cache import CacheConfig, ValidationCache
from gha_workflow_linter.models import ValidationMethod, ValidationResult


def demo_basic_cache_operations() -> None:
    """Demonstrate basic cache put/get operations."""
    print("=== Basic Cache Operations Demo ===")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create cache configuration
        config = CacheConfig(
            enabled=True,
            cache_dir=Path(temp_dir),
            cache_file="demo_cache.json",
            default_ttl_seconds=300,  # 5 minutes
            max_cache_size=1000,
        )

        cache = ValidationCache(config)

        # Simulate some validation results
        test_repos = [
            ("actions/checkout", "v4", ValidationResult.VALID),
            ("actions/setup-python", "v5", ValidationResult.VALID),
            ("actions/setup-node", "v4", ValidationResult.VALID),
            ("invalid/repo", "v1", ValidationResult.INVALID_REPOSITORY),
            (
                "actions/checkout",
                "invalid-ref",
                ValidationResult.INVALID_REFERENCE,
            ),
        ]

        print("Storing validation results in cache...")
        for repo, ref, result in test_repos:
            cache.put(repo, ref, result, "graphql")
            print(f"  Cached: {repo}@{ref} -> {result.value}")

        print("\nRetrieving cached results...")
        for repo, ref, _expected_result in test_repos:
            cached_entry = cache.get(repo, ref)
            if cached_entry:
                print(
                    f"  Retrieved: {repo}@{ref} -> {cached_entry.result.value} "
                    f"(age: {cached_entry.age_seconds:.1f}s)"
                )
            else:
                print(f"  Cache miss: {repo}@{ref}")

        # Show cache statistics
        print("\nCache Stats:")
        print(f"  Hits: {cache.stats.hits}")
        print(f"  Misses: {cache.stats.misses}")
        print(f"  Writes: {cache.stats.writes}")
        print(f"  Hit Rate: {cache.stats.hit_rate:.1f}%")


def demo_batch_operations() -> None:
    """Demonstrate batch cache operations."""
    print("\n=== Batch Operations Demo ===")

    with tempfile.TemporaryDirectory() as temp_dir:
        config = CacheConfig(
            enabled=True,
            cache_dir=Path(temp_dir),
            cache_file="batch_demo_cache.json",
        )

        cache = ValidationCache(config)

        # Batch put operations
        batch_data: list[
            tuple[
                str, str, ValidationResult, str, ValidationMethod, Optional[str]
            ]
        ] = [
            (
                "actions/checkout",
                "v4",
                ValidationResult.VALID,
                "graphql",
                ValidationMethod.GITHUB_API,
                None,
            ),
            (
                "actions/setup-python",
                "v5",
                ValidationResult.VALID,
                "graphql",
                ValidationMethod.GITHUB_API,
                None,
            ),
            (
                "actions/setup-node",
                "v4",
                ValidationResult.VALID,
                "graphql",
                ValidationMethod.GITHUB_API,
                None,
            ),
            (
                "actions/checkout",
                "v4",
                ValidationResult.VALID,
                "graphql",
                ValidationMethod.GITHUB_API,
                None,
            ),
            (
                "actions/download-artifact",
                "v4",
                ValidationResult.VALID,
                "graphql",
                ValidationMethod.GITHUB_API,
                None,
            ),
        ]

        print("Storing batch validation results...")
        cache.put_batch(batch_data)
        print(f"Stored {len(batch_data)} entries in batch")

        # Batch get operations
        repo_refs = [
            ("actions/checkout", "v4"),
            ("actions/setup-python", "v5"),
            ("actions/setup-node", "v4"),
            ("actions/missing", "v1"),  # This will be a cache miss
            ("actions/upload-artifact", "v4"),
        ]

        print("\nRetrieving batch validation results...")
        cached_results, cache_misses = cache.get_batch(repo_refs)

        print(f"Cache hits: {len(cached_results)}")
        for (repo, ref), entry in cached_results.items():
            print(f"  {repo}@{ref} -> {entry.result.value}")

        print(f"Cache misses: {len(cache_misses)}")
        for repo, ref in cache_misses:
            print(f"  {repo}@{ref}")


def demo_cache_expiration() -> None:
    """Demonstrate cache expiration functionality."""
    print("\n=== Cache Expiration Demo ===")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create cache with short TTL for demo
        config = CacheConfig(
            enabled=True,
            cache_dir=Path(temp_dir),
            cache_file="expiration_demo_cache.json",
            default_ttl_seconds=2,  # 2 seconds for demo
        )

        cache = ValidationCache(config)

        # Store an entry
        print("Storing cache entry with 2-second TTL...")
        cache.put("actions/checkout", "v4", ValidationResult.VALID, "graphql")

        # Retrieve immediately
        entry = cache.get("actions/checkout", "v4")
        if entry:
            print(
                f"Immediate retrieval: Success (age: {entry.age_seconds:.1f}s)"
            )

        # Wait for expiration
        print("Waiting 3 seconds for expiration...")
        time.sleep(3)

        # Try to retrieve expired entry
        entry = cache.get("actions/checkout", "v4")
        if entry:
            print("Retrieval after expiration: Success (should not happen)")
        else:
            print("Retrieval after expiration: Cache miss (expected)")

        print(f"Expired entries encountered: {cache.stats.expired}")


def demo_cache_size_limits() -> None:
    """Demonstrate cache size limit enforcement."""
    print("\n=== Cache Size Limits Demo ===")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create cache with small size limit
        config = CacheConfig(
            enabled=True,
            cache_dir=Path(temp_dir),
            cache_file="size_limit_demo_cache.json",
            max_cache_size=3,  # Only 3 entries allowed
        )

        cache = ValidationCache(config)

        print("Adding 5 entries to cache with max_cache_size=3...")

        # Add more entries than the limit
        entries = [
            ("repo1/action", "v1"),
            ("repo2/action", "v1"),
            ("repo3/action", "v1"),
            ("repo4/action", "v1"),
            ("repo5/action", "v1"),
        ]

        for i, (repo, ref) in enumerate(entries):
            cache.put(repo, ref, ValidationResult.VALID, "graphql")
            print(f"  Added entry {i + 1}: {repo}@{ref}")
            # Small delay to ensure different timestamps
            time.sleep(0.01)

        print("\nChecking which entries remain after size limit enforcement:")
        for repo, ref in entries:
            entry = cache.get(repo, ref)
            if entry:
                print(f"  Present: {repo}@{ref}")
            else:
                print(f"  Evicted: {repo}@{ref}")

        cache_info = cache.get_cache_info()
        print(f"\nFinal cache size: {cache_info['entries']} (should be 3)")


def demo_cache_persistence() -> None:
    """Demonstrate cache persistence across instances."""
    print("\n=== Cache Persistence Demo ===")

    with tempfile.TemporaryDirectory() as temp_dir:
        config = CacheConfig(
            enabled=True,
            cache_dir=Path(temp_dir),
            cache_file="persistence_demo_cache.json",
        )

        # First cache instance
        print("Creating first cache instance and storing data...")
        cache1 = ValidationCache(config)
        cache1.put("actions/checkout", "v4", ValidationResult.VALID, "graphql")
        cache1.put(
            "actions/setup-python", "v5", ValidationResult.VALID, "graphql"
        )
        cache1.save()
        print("Data saved to disk")

        # Second cache instance (should load from disk)
        print("\nCreating second cache instance (should load from disk)...")
        cache2 = ValidationCache(config)

        # Try to retrieve data
        entry1 = cache2.get("actions/checkout", "v4")
        entry2 = cache2.get("actions/setup-python", "v5")

        if entry1 and entry2:
            print("✅ Cache persistence working correctly!")
            print(f"  Retrieved: actions/checkout@v4 -> {entry1.result.value}")
            print(
                f"  Retrieved: actions/setup-python@v5 -> {entry2.result.value}"
            )
        else:
            print("❌ Cache persistence failed")


def demo_cache_info() -> None:
    """Demonstrate cache information reporting."""
    print("\n=== Cache Information Demo ===")

    with tempfile.TemporaryDirectory() as temp_dir:
        config = CacheConfig(
            enabled=True,
            cache_dir=Path(temp_dir),
            cache_file="info_demo_cache.json",
            default_ttl_seconds=3600,
            max_cache_size=1000,
        )

        cache = ValidationCache(config)

        # Add some test data
        cache.put(
            "actions/checkout",
            "v4",
            ValidationResult.VALID,
            "graphql",
            ValidationMethod.GITHUB_API,
        )
        cache.put(
            "actions/setup-node",
            "v4",
            ValidationResult.VALID,
            "graphql",
            ValidationMethod.GITHUB_API,
        )
        cache.put(
            "invalid/repo",
            "v1",
            ValidationResult.INVALID_REPOSITORY,
            "graphql",
            ValidationMethod.GITHUB_API,
            "Repository not found",
        )

        # Generate some stats
        cache.get("actions/checkout", "v4")  # hit
        cache.get("actions/missing", "v1")  # miss

        info = cache.get_cache_info()

        print("Cache Information:")
        print(f"  Enabled: {info['enabled']}")
        print(f"  Cache file: {info['cache_file']}")
        print(f"  Total entries: {info['entries']}")
        print(f"  Max cache size: {info['max_cache_size']}")
        print(f"  TTL (seconds): {info['ttl_seconds']}")

        print("\nCache Statistics:")
        stats = info["stats"]
        print(f"  Hits: {stats['hits']}")
        print(f"  Misses: {stats['misses']}")
        print(f"  Writes: {stats['writes']}")
        print(f"  Hit rate: {cache.stats.hit_rate:.1f}%")


def main() -> None:
    """Run all cache demonstrations."""
    print("🏷️ gha-workflow-linter Cache Functionality Demo")
    print("=" * 50)

    try:
        demo_basic_cache_operations()
        demo_batch_operations()
        demo_cache_expiration()
        demo_cache_size_limits()
        demo_cache_persistence()
        demo_cache_info()

        print("\n✅ All cache demos completed successfully!")
        print("\nKey Benefits of Caching:")
        print("  • Reduces API calls to GitHub")
        print("  • Improves performance for repeated validations")
        print("  • Respects rate limits better")
        print("  • Provides offline validation for previously seen references")
        print("  • Configurable TTL and size limits")

    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        raise


if __name__ == "__main__":
    main()
