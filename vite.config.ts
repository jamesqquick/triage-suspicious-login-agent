import { cloudflare } from '@cloudflare/vite-plugin';
import { flue, flueWorkerConfig } from '@flue/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [
    flue({ providers: ['openai', 'cloudflare'] }),
    cloudflare({ config: flueWorkerConfig() }),
  ],
});
