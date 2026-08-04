// Ambient `.md` skill-import declarations ship with @flue/runtime but aren't
// auto-included, so reference them explicitly.
/// <reference path="../node_modules/@flue/runtime/types/skill-md.d.ts" />
/// <reference path="../node_modules/@flue/runtime/types/markdown-md.d.ts" />

// Worker `ai` binding from wrangler.jsonc, so env.AI typechecks without a build step.
declare namespace Cloudflare {
  interface Env {
    AI: Ai;
  }
}
