import adapter from '@sveltejs/adapter-auto';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import { sveltePreprocess } from 'svelte-preprocess';

const config = {
    preprocess: [vitePreprocess()],
    kit: { adapter: adapter() },
};

export default config;
