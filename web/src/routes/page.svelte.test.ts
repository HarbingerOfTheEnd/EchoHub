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

    test('renders the main heading', () => {
        render(Page);
        const heading = screen.getByRole('heading', {
            name: 'Welcome to EchoHub',
        });
        expect(heading).toBeInTheDocument();
    });
});
