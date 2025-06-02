import { describe, test, expect } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/svelte';
import Page from './+page.svelte';

describe('/+page.svelte', () => {
    test('renders the page with the correct title', () => {
        render(Page);
        const { title } = document;
        expect(title).toBe('EchoHub');
    });
});
