import type { JsonValue } from '@flue/runtime';

// Boundary cast for tool return values: TypeScript cannot prove a named
// interface (with optional fields) satisfies JsonValue's index signature.
// Centralized so the assertion stays greppable instead of scattered per tool.
export function asJson<T>(value: T): JsonValue {
  return value as unknown as JsonValue;
}
