import type { JsonValue } from '@flue/runtime';

// Boundary cast: TypeScript cannot prove a named interface with optional fields
// satisfies JsonValue's index signature. Centralized to keep it greppable.
export function asJson<T>(value: T): JsonValue {
  return value as unknown as JsonValue;
}
