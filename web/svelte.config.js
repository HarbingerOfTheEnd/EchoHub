import adapter from '@sveltejs/adapter-auto';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import { sveltePreprocess } from 'svelte-preprocess';

const config = {
    preprocess: [
        vitePreprocess(),
        sveltePreprocess({
            scss: {
                prependData: `@import '$style/variables.scss';`,
            },
        }),
    ],
    kit: { adapter: adapter() },
};

export default config;
